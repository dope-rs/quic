use crate::conn::Selected;
use crate::conn::{
    machine::storage::{self, demand},
    output::delivery,
    stream::state::transmit::log::{
        self, journal,
        links::{
            storage::{Account, Borrowed, Projected, Walk},
            topology::{Action, Active, Group, Member, Reclaim, Tables, Transfer},
        },
        planes,
    },
};
use o3::depot;
use o3::depot::queue::{indexed::keyed, links};
use std::num::NonZero;

pub(in crate::conn::stream::state::transmit::log) struct Record<'a, P = (), G = (), S = ()> {
    pub(in crate::conn::stream::state::transmit::log) node:
        demand::Occupied<'a, log::Node, log::NodeTag, { u32::MAX }, P>,
    pub(in crate::conn::stream::state::transmit::log) group:
        demand::Occupied<'a, log::Group, log::GroupTag, { u32::MAX }, G>,
    pub(super) queues: &'a mut journal::Queues,
    ledger: &'a mut journal::Ledger,
    pub(super) work: &'a mut log::RetryLedger,
    state: S,
}

impl<'a> Record<'a, planes::All, planes::Reclaim> {
    pub(in crate::conn::stream::state::transmit::log) fn reclaim(
        journal: &'a mut journal::Journal,
    ) -> Option<Self> {
        let group = keyed::Fifo::first(journal)?;
        let node = keyed::Fifo::front(Reclaim::from(group));
        let live = unsafe {
            node.map(|(group, index): (Reclaim<'a>, _)| {
                (
                    (
                        group.nodes,
                        (group.group, group.queues, group.ledger, group.work),
                    ),
                    index,
                )
            })
        };
        let (node, (group, queues, ledger, work)) = demand::Occupied::project(live);
        Some(Self {
            node,
            group,
            queues,
            ledger,
            work,
            state: (),
        })
    }
}

impl<'a> Record<'a> {
    pub(in crate::conn::stream::state::transmit::log) fn bind(
        journal: &'a mut journal::Journal,
        handle: delivery::Handle<delivery::Stream>,
    ) -> Option<Self> {
        let (group, node) = journal.storage.bind(handle)?;
        Some(Self {
            node,
            group,
            queues: &mut journal.queues,
            ledger: &mut journal.ledger,
            work: &mut journal.retry_work,
            state: (),
        })
    }

    pub(in crate::conn::stream::state::transmit::log) fn lose(mut self) {
        if self.node.get().is_acked(storage::Key::new(self.node.key())) {
            return;
        }
        if !self.group.get().active {
            self.discard(Account::Retired);
            return;
        }
        let node = self.node.get();
        if node.carriers == 0 || !node.delivery.is_linked(storage::Key::new(self.node.key())) {
            return;
        }
        if node.carriers > 1 {
            self.node.get_mut().carriers -= 1;
            return;
        }
        let Self {
            node,
            group,
            queues,
            ledger,
            work,
            state: (),
        } = self;
        Transfer {
            record: Record {
                node,
                group,
                queues,
                ledger,
                work,
                state: Active(()),
            },
            action: Action::Lose,
        }
        .commit();
    }

    pub(in crate::conn::stream::state::transmit::log) fn acknowledge(
        mut self,
    ) -> Option<Record<'a, (), (), Active>> {
        let key = storage::Key::new(self.node.key());
        if self.node.get().is_acked(key) {
            return None;
        }
        if !self.group.get().active {
            self.discard(Account::Retired);
            return None;
        }
        // SAFETY: this existing Record retains its exact All member and parent.
        // Their shared borrow excludes detach until the head projection completes.
        let head = keyed::Fifo::front(unsafe {
            depot::raw::Proof::new(Walk {
                entries: self.node.as_table().entries(),
                queue: &self.group.get().nodes.all,
            })
        });
        let (first, node) = Walk::get(unsafe { head.as_ref() });
        if first == key {
            let Self {
                node,
                group,
                queues,
                ledger,
                work,
                state: (),
            } = self;
            return Some(Record {
                node,
                group,
                queues,
                ledger,
                work,
                state: Active(()),
            });
        }
        if !node.is_acked(first) {
            self.untrack();
        }
        None
    }
}

impl<'a, P> Record<'a, P, (), Active> {
    pub(in crate::conn::stream::state::transmit::log) fn cancel(self) {
        let Self {
            node,
            group,
            queues,
            ledger,
            work,
            state,
        } = self;
        Group {
            entry: group,
            nodes: node.as_table().entries(),
            queues,
            ledger,
            work,
            active: state,
        }
        .cancel();
    }
}

impl Record<'_, log::Probe, (), Active> {
    pub(in crate::conn::stream::state::transmit::log) fn probe(mut self, carriers: NonZero<u16>) {
        self.advance();
        self.node.get_mut().carriers = carriers.get();
    }
}

impl<'a, P: log::raw::Selected> Record<'a, P, (), Active> {
    pub(in crate::conn::stream::state::transmit::log) fn project<C>(
        live: Selected<(&'a mut journal::Journal, C), storage::Key<log::NodeTag>, P>,
    ) -> (Self, C) {
        let live = unsafe {
            live.map(|((journal, context), key)| {
                (
                    (
                        &mut journal.storage,
                        (
                            &mut journal.queues,
                            &mut journal.ledger,
                            &mut journal.retry_work,
                            context,
                        ),
                    ),
                    depot::raw::Word::from_offset(key.index() as usize),
                )
            })
        };
        let (group, node, (queues, ledger, work, context)) = Tables::project(live);
        (
            Self {
                node,
                group,
                queues,
                ledger,
                work,
                state: Active(()),
            },
            context,
        )
    }
}

impl<'a, P, G, S> Record<'a, P, G, S> {
    pub(super) fn advance(&mut self) {
        let position = log::Position {
            group: storage::Key::new(self.group.key()),
            node: storage::Key::new(self.node.key()),
        };
        if self.queues.probe.cursor == Some(position) {
            let member = unsafe {
                keyed::Slot::from_source(depot::raw::Proof::new(Member {
                    entry: &mut self.node,
                    queue: &self.group.get().nodes.inflight,
                }))
            };
            match member.successor() {
                Some(live) => {
                    let live = unsafe {
                        live.map(|(owner, index)| (owner.entry.as_table().entries(), index))
                    };
                    self.queues.probe.cursor = Some(log::Position {
                        group: position.group,
                        node: storage::Key::new(demand::Entries::project(live).0),
                    });
                }
                None => {
                    let journal::ProbeQueue { chain, cursor } = &mut self.queues.probe;
                    let member = unsafe {
                        keyed::Slot::from_source(depot::raw::Proof::new(Member {
                            entry: &mut self.group,
                            queue: chain,
                        }))
                    };
                    Group::advance(&member, self.node.as_table().entries(), cursor);
                }
            }
        }
    }

    /// Removes a checked delivery membership and its retained accounting.
    /// Each active retry member owns one charge in its group and journal ledgers.
    pub(in crate::conn::stream::state::transmit::log) fn untrack(&mut self) {
        let carriers = self.node.get().carriers;
        if carriers != 0 {
            self.advance();
        }
        let queue = if carriers == 0 {
            &self.group.get().nodes.retry
        } else {
            &self.group.get().nodes.inflight
        };
        if let Ok(member) = keyed::Slot::try_new(Member {
            entry: &mut self.node,
            queue,
        }) {
            member.remove();
            if carriers == 0 && self.group.get().active {
                let wire_len = self.node.get().record.wire_len.get();
                let group = self.group.get_mut();
                for ledger in [&mut *self.work, &mut group.retry_work] {
                    ledger.frames -= 1;
                    ledger.wire_bytes -= u32::from(wire_len);
                    if ledger.frames == 0 {
                        ledger.wire_ceiling = 0;
                    }
                }
            }
        }
        if self.group.get().nodes.retry.is_empty() {
            Group::unlink::<planes::Retry>(&mut self.group, &self.queues.retry);
        }
        if self.group.get().nodes.inflight.is_empty() {
            Group::probe(&mut self.group, self.queues, self.node.as_table().entries());
        }
        self.node.get_mut().carriers = 0;
    }

    fn charge(&mut self, account: Account) {
        self.untrack();
        self.group.get_mut().len -= 1;
        if matches!(account, Account::Active) {
            self.ledger.active -= 1;
        }
    }

    pub(in crate::conn::stream::state::transmit::log) fn discard(mut self, account: Account) {
        self.charge(account);
        unsafe { keyed::Slot::from_source(depot::raw::Proof::new(self)) }
            .remove()
            .release()
    }

    pub(in crate::conn::stream::state::transmit::log) fn next(
        mut self,
        account: Account,
    ) -> Option<Record<'a, planes::All, G, S>> {
        self.charge(account);
        match unsafe { keyed::Slot::from_source(depot::raw::Proof::new(self)) }.advance() {
            Ok(live) => {
                let live = unsafe {
                    live.map(|(mut record, index)| {
                        keyed::Slot::from_source(depot::raw::Proof::new(Member {
                            entry: &mut record.node,
                            queue: &record.group.get().nodes.all,
                        }))
                        .remove();
                        let (nodes, _) = record.node.take();
                        (
                            (
                                nodes,
                                (
                                    record.group,
                                    record.queues,
                                    record.ledger,
                                    record.work,
                                    record.state,
                                ),
                            ),
                            index,
                        )
                    })
                };
                let (node, (group, queues, ledger, work, state)) = demand::Occupied::project(live);
                Some(Record {
                    node,
                    group,
                    queues,
                    ledger,
                    work,
                    state,
                })
            }
            Err(last) => {
                last.remove().release();
                None
            }
        }
    }
}

// SAFETY: every exposed record retains its original stream-order membership.
unsafe impl<P, G, S> depot::raw::KeyOwner<planes::All> for Record<'_, P, G, S> {
    type Key = storage::Key<log::NodeTag>;
    type Fifo = keyed::Fifo<Self::Key, planes::All>;
    fn parts(&self) -> (Self::Key, &keyed::Link<Self::Key, planes::All>) {
        depot::raw::KeyBorrow::parts(Borrowed(&self.node))
    }
    fn fifo(&self) -> &keyed::Fifo<Self::Key, planes::All> {
        &self.group.get().nodes.all
    }
    fn entry<'b>(
        live: Selected<&'b Self, links::Index, planes::All>,
    ) -> keyed::Entry<'b, Self::Key, planes::All> {
        let live = unsafe { live.map(|(record, index)| (record.node.as_table().entries(), index)) };
        keyed::Entry::from_source(Projected(live))
    }
}

// SAFETY: the consuming detach removed this record's final membership.
unsafe impl<P, G, S> depot::raw::KeyFinish<false, planes::All> for Record<'_, P, G, S> {
    type Output = ();
    unsafe fn finish(mut self) {
        self.node.remove();
        if self.group.get().len == 0 {
            Group::unlink::<planes::Reclaim>(&mut self.group, &self.queues.reclaim);
            self.group.remove();
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<Record<'static>>() == 56);
    assert!(std::mem::size_of::<Record<'static, (), (), Active>>() == 56);
};
