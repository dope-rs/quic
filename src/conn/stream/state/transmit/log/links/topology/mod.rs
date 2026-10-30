use crate::conn::{
    machine::storage::{self, demand},
    stream::state::transmit::log::{
        self, journal,
        links::storage::{Borrowed, Projected},
        planes,
    },
};
pub(in crate::conn::stream::state::transmit::log) use group::{Active, Group};
pub(in crate::conn::stream::state::transmit::log) use member::Member;
use o3::depot;
use o3::depot::index::Initialized;
use o3::depot::queue::{indexed::keyed, links};
pub(in crate::conn::stream::state::transmit::log) use records::Record;
pub(in crate::conn::stream::state::transmit::log) use tables::Tables;

mod group;
mod member;
mod records;
mod tables;

pub(in crate::conn::stream::state::transmit::log) struct Transfer<
    'a,
    const MOVED: bool = false,
    P = (),
> {
    record: Record<'a, P, (), Active>,
    action: Action,
}

enum Action {
    Lose,
    Resend,
}

impl<'a> Transfer<'a, false, log::Retry> {
    pub(in crate::conn::stream::state::transmit::log) fn resend(
        record: Record<'a, log::Retry, (), Active>,
    ) -> Self {
        Self {
            record,
            action: Action::Resend,
        }
    }
}

impl<P> Transfer<'_, false, P> {
    pub(in crate::conn::stream::state::transmit::log) fn commit(mut self) {
        if matches!(self.action, Action::Lose) {
            self.record.advance();
        }
        // SAFETY: the occupied node and group preserve the checked source membership.
        unsafe { keyed::Slot::from_source(depot::raw::Proof::new(self)) }
            .transfer()
            .release()
    }
}

impl<P> Transfer<'_, true, P> {
    /// Commits one transferred record's charge under the retained node/group loans.
    /// Native admission bounds all active records by u16 and RetryLedger's wire
    /// product; each consumed membership adds or removes one charge per ledger.
    fn finish(mut self) {
        let wire_len = self.record.node.get().record.wire_len.get();
        match self.action {
            Action::Lose => {
                if self.record.group.get().nodes.inflight.is_empty() {
                    Group::probe(
                        &mut self.record.group,
                        self.record.queues,
                        self.record.node.as_table().entries(),
                    );
                }
                if let Ok(vacant) = keyed::Slot::try_vacant(Member {
                    entry: &mut self.record.group,
                    queue: &self.record.queues.retry,
                }) {
                    vacant.push::<false>();
                }
                self.record.node.get_mut().carriers = 0;
                let group = self.record.group.get_mut();
                for ledger in [&mut *self.record.work, &mut group.retry_work] {
                    ledger.frames += 1;
                    ledger.wire_bytes += u32::from(wire_len);
                    ledger.wire_ceiling = ledger.wire_ceiling.max(wire_len);
                }
            }
            Action::Resend => {
                if self.record.group.get().nodes.retry.is_empty() {
                    Group::unlink::<planes::Retry>(
                        &mut self.record.group,
                        &self.record.queues.retry,
                    );
                }
                if let Ok(vacant) = keyed::Slot::try_vacant(Member {
                    entry: &mut self.record.group,
                    queue: &self.record.queues.probe.chain,
                }) {
                    vacant.push::<false>();
                }
                self.record.node.get_mut().carriers = 1;
                let group = self.record.group.get_mut();
                for ledger in [&mut *self.record.work, &mut group.retry_work] {
                    ledger.frames -= 1;
                    ledger.wire_bytes -= u32::from(wire_len);
                    if ledger.frames == 0 {
                        ledger.wire_ceiling = 0;
                    }
                }
            }
        }
    }
}

// SAFETY: native occupied guards retain the exact node, group, and their storage.
// The action and consuming route select the two delivery queues of that group.
unsafe impl<const MOVED: bool, P> depot::raw::KeyOwner<planes::Delivery>
    for Transfer<'_, MOVED, P>
{
    type Key = storage::Key<log::NodeTag>;
    type Fifo = keyed::Fifo<Self::Key, planes::Delivery>;

    fn parts(&self) -> (Self::Key, &keyed::Link<Self::Key, planes::Delivery>) {
        depot::raw::KeyBorrow::parts(Borrowed(&self.record.node))
    }

    fn fifo(&self) -> &keyed::Fifo<Self::Key, planes::Delivery> {
        let group = self.record.group.get();
        match (&self.action, MOVED) {
            (Action::Lose, false) | (Action::Resend, true) => &group.nodes.inflight,
            (Action::Lose, true) | (Action::Resend, false) => &group.nodes.retry,
        }
    }

    fn entry<'a>(
        live: depot::raw::Proof<(&'a Self, links::Index), Initialized<planes::Delivery>>,
    ) -> keyed::Entry<'a, Self::Key, planes::Delivery> {
        let live =
            unsafe { live.map(|(owner, index)| (owner.record.node.as_table().entries(), index)) };
        keyed::Entry::from_source(Projected(live))
    }
}

unsafe impl<'a, P> depot::raw::KeyRoute<planes::Delivery> for Transfer<'a, false, P> {
    type Target = Transfer<'a, true, P>;

    unsafe fn route(self) -> Self::Target {
        let Self { record, action } = self;
        Transfer { record, action }
    }
}

unsafe impl<P> depot::raw::KeyFinish<true, planes::Delivery> for Transfer<'_, true, P> {
    type Output = ();

    unsafe fn finish(self) {
        self.finish()
    }
}

const _: () = {
    assert!(std::mem::size_of::<Transfer<'static>>() == 64);
    assert!(
        std::mem::size_of::<Transfer<'static>>() == std::mem::size_of::<Transfer<'static, true>>()
    );
    assert!(
        std::mem::size_of::<Option<Transfer<'static>>>()
            == std::mem::size_of::<Transfer<'static>>()
    );
    assert!(
        std::mem::size_of::<Transfer<'static, false, log::Retry>>()
            == std::mem::size_of::<Transfer<'static>>()
    );
};

struct Reclaim<'a> {
    group: demand::Occupied<'a, log::Group, log::GroupTag, { u32::MAX }, planes::Reclaim>,
    nodes: &'a mut demand::Table<log::Node, log::NodeTag, { u32::MAX }>,
    queues: &'a mut journal::Queues,
    ledger: &'a mut journal::Ledger,
    work: &'a mut log::RetryLedger,
}

// SAFETY: this exclusive journal owns the original reclaim FIFO and both tables.
unsafe impl depot::raw::KeySource<planes::Reclaim> for &mut journal::Journal {
    type Key = storage::Key<log::GroupTag>;
    fn fifo(&self) -> &keyed::Fifo<Self::Key, planes::Reclaim> {
        &self.queues.reclaim
    }
}

impl<'a> Reclaim<'a> {
    fn from(
        live: depot::raw::Proof<
            (&'a mut journal::Journal, links::Index),
            Initialized<planes::Reclaim>,
        >,
    ) -> depot::raw::Proof<Self, keyed::NonEmpty> {
        let live = unsafe {
            live.map(|(journal, index)| {
                (
                    (
                        &mut journal.storage.groups,
                        (
                            &mut journal.storage.nodes,
                            &mut journal.queues,
                            &mut journal.ledger,
                            &mut journal.retry_work,
                        ),
                    ),
                    index,
                )
            })
        };
        let (group, (nodes, queues, ledger, work)) = demand::Occupied::project(live);
        // SAFETY: only cancellation publishes a nonempty group to reclaim.
        // This original journal loan retains both tables until front projection.
        unsafe {
            depot::raw::Proof::new(Reclaim {
                group,
                nodes,
                queues,
                ledger,
                work,
            })
        }
    }
}

// SAFETY: a retained reclaim group owns every node in its stream-order FIFO.
unsafe impl depot::raw::KeySource<planes::All> for Reclaim<'_> {
    type Key = storage::Key<log::NodeTag>;
    fn fifo(&self) -> &keyed::Fifo<Self::Key, planes::All> {
        &self.group.get().nodes.all
    }
}
