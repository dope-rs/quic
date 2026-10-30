use crate::conn::machine::storage::demand;
use o3::depot;
use o3::depot::index::Initialized;
use o3::depot::queue::{indexed::keyed, links};

use crate::conn::machine::storage;
use crate::conn::stream::state::transmit::log::links::storage::{Borrowed, Projected};
use crate::conn::stream::state::transmit::log::planes;

pub(in crate::conn::stream::state::transmit::log) struct Member<'b, 'a, P: planes::Plane, Q = ()> {
    pub(in crate::conn::stream::state::transmit::log) entry:
        &'b mut demand::Occupied<'a, P::Value, P::Tag, { u32::MAX }, Q>,
    pub(in crate::conn::stream::state::transmit::log) queue:
        &'b keyed::Fifo<storage::Key<P::Tag>, P>,
}

// SAFETY: each membership retains the native occupied slot and the FIFO selected
// by its original journal group. Queue mutations cannot release either slot.
unsafe impl<P: planes::Plane, Q> depot::raw::KeyOwner<P> for Member<'_, '_, P, Q> {
    type Key = storage::Key<P::Tag>;
    type Fifo = keyed::Fifo<Self::Key, P>;

    fn parts(&self) -> (Self::Key, &keyed::Link<Self::Key, P>) {
        depot::raw::KeyBorrow::parts(Borrowed(self.entry))
    }

    fn fifo(&self) -> &keyed::Fifo<Self::Key, P> {
        self.queue
    }

    fn entry<'b>(
        live: depot::raw::Proof<(&'b Self, links::Index), Initialized<P>>,
    ) -> keyed::Entry<'b, Self::Key, P> {
        let live = unsafe { live.map(|(owner, index)| (owner.entry.as_table().entries(), index)) };
        keyed::Entry::from_source(Projected(live))
    }
}

const _: () = assert!(std::mem::size_of::<Member<'static, 'static, planes::All>>() == 16);
