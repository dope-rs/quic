use crate::runtime::routing::registry;
use o3::buffer;
use o3::depot::{self, array, index::Initialized, queue::indexed::planes::bound};
use o3::mem::{self, slot};

use crate::runtime::mux::router;
use crate::runtime::routing::registry::set::routes::{
    Directory,
    node::{Node, pack},
};
use crate::{
    conn::{id, wire::path::local::Assigned},
    runtime::mux,
    stream,
};
use registry::{
    Key,
    set::{Entries, scope::Scope},
};
use router::routing::state::cids;

pub(in crate::runtime) struct Reservation<
    'storage,
    'id,
    C,
    I,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
> {
    pub(super) owner: Directory<'storage, 'id, C, DOMAIN, B, D, T>,
    pub(super) key: bound::ActiveKey<'id>,
    pub(super) handle: id::Handle<I, DOMAIN>,
    pub(super) routes: cids::Routes<'id>,
}

impl<'storage, 'id, C, I: Copy, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    Reservation<'storage, 'id, C, I, DOMAIN, B, D, T>
{
    pub(in crate::runtime) fn handle(&self) -> id::Handle<I, DOMAIN> {
        self.handle
    }

    pub(in crate::runtime) fn reject(mut self) {
        self.owner
            .entries
            .entry(self.key)
            .plane::<{ mux::FREE_QUEUE }>()
            .link_back();
    }

    pub(in crate::runtime) fn install<R>(
        self,
        slot: registry::Slot<C, DOMAIN, B, D, T>,
        apply: impl FnOnce(&mut Scope<'storage, 'id, C, DOMAIN, B, D, T>, Key<'id>) -> R,
    ) -> R {
        let Directory {
            entries,
            resets,
            cids,
            tokens,
            active,
        } = self.owner;
        let (entries, key) = entries.install::<{ mux::FREE_QUEUE }>(self.key, slot);
        *active += 1;
        let key = Key(key);
        use o3::depot::raw::TagEntry as _;
        let mut scope = Scope {
            entries: Entries { source: entries },
            resets,
            cids,
            tokens,
            active,
        };
        let routes = self.routes;
        let (value, hash) = routes.local();
        let index = pack(key, array::Index::at::<0>());
        {
            let slot = scope.entries.source.get_mut(key.0);
            let mut assigned: mem::raw::Occupied<'_, Assigned> =
                unsafe { depot::raw::Proof::<_, Initialized<Assigned>>::new((slot, index)) }.into();
            let local = assigned.get().local();
            *assigned.get_mut() = Assigned::new(value, local, index);
        }
        let node = Node {
            owner: &mut scope,
            row: key,
            index,
            hash,
        };
        let Node { owner, .. } = unsafe { node.vacant() }.push::<true>().into_inner();
        let owner = if let Some((value, hash)) = routes.alias() {
            let index = pack(
                key,
                array::Index::at::<{ crate::conn::MAX_ACTIVE_CONNECTION_IDS }>(),
            );
            {
                let slot = owner.entries.source.get_mut(key.0);
                let cell: &mut slot::Storage<Assigned> = unsafe {
                    depot::raw::Proof::<_, Initialized<slot::Storage<Assigned>>>::new((slot, index))
                }
                .into();
                *cell = slot::Storage::filled(Assigned::new(value, None, index), ());
            }
            let node = Node {
                owner,
                row: key,
                index,
                hash,
            };
            let Node { owner, .. } = unsafe { node.vacant() }.push::<true>().into_inner();
            owner
        } else {
            owner
        };
        apply(owner, key)
    }
}
