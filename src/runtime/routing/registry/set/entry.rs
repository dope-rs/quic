use crate::runtime::routing::registry;
use std::time;

use o3::buffer;
use o3::depot::{
    capacity,
    heap::indexed,
    queue::indexed::planes::{bound, resident},
};

use crate::runtime::routing::registry::Key;
use crate::runtime::routing::registry::set::Live;
use crate::runtime::{brand, mux};
use crate::stream;

pub(in crate::runtime) struct Entries<
    'storage,
    'id,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
> {
    pub(super) source: Live<'storage, 'id, C, DOMAIN, B, D, T>,
}

impl<'storage, 'id, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    Entries<'storage, 'id, C, DOMAIN, B, D, T>
{
    pub(in crate::runtime) fn admit(&self, key: bound::ActiveKey<'id>) -> Option<Key<'id>> {
        self.source.admit(key).map(Key)
    }

    pub(in crate::runtime) fn access<'loan, const TRACK: bool>(
        &'loan mut self,
        key: Key<'id>,
        brand: brand::Token<'loan>,
    ) -> registry::Access<'loan, C, DOMAIN, B, D, T, TRACK> {
        self.source.get_mut(key.0).access(brand)
    }

    pub(in crate::runtime) fn select(
        &mut self,
        key: Key<'id>,
    ) -> (
        indexed::Entry<'_, time::Instant, capacity::Limit<{ mux::MAX_CONNECTIONS }>>,
        Entry<'_, C, DOMAIN, B, D, T>,
    ) {
        let (timer, entry) = self.source.select(key.0);
        (timer, Entry { inner: entry })
    }
}

pub(in crate::runtime) struct Entry<
    'storage,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
> {
    pub(super) inner: resident::Entry<
        'storage,
        registry::Slot<C, DOMAIN, B, D, T>,
        registry::Epoch,
        { mux::QUEUE_PLANES },
        false,
        { mux::FREE_QUEUE },
    >,
}

impl<C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    Entry<'_, C, DOMAIN, B, D, T>
{
    pub(in crate::runtime) fn get(&self) -> &registry::Slot<C, DOMAIN, B, D, T> {
        self.inner.get()
    }

    pub(in crate::runtime) fn access<'loan, const TRACK: bool>(
        &'loan mut self,
        brand: brand::Token<'loan>,
    ) -> registry::Access<'loan, C, DOMAIN, B, D, T, TRACK> {
        self.inner.get_mut().access(brand)
    }

    pub(in crate::runtime) fn is_linked<const PLANE: usize>(&self) -> bool {
        self.inner.is_linked::<PLANE>()
    }

    pub(in crate::runtime) fn link_back<const PLANE: usize>(&mut self) {
        self.inner.link_back::<PLANE>();
    }

    pub(in crate::runtime) fn unlink<const PLANE: usize>(&mut self) {
        self.inner.unlink::<PLANE>();
    }
}
