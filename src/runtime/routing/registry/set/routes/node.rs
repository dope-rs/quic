use o3::base::num::bounded;
use o3::buffer;
use o3::depot::{
    self, array,
    index::Initialized,
    queue::{links, tagged},
};
use o3::mem::{self, slot};

use crate::conn::wire::path::{self, local::Assigned};
use crate::runtime::mux;
use crate::runtime::routing::registry::set::routes::endpoint;
use crate::runtime::routing::registry::{Key, set::scope::Scope};
use crate::{conn, stream};

pub(super) struct Node<
    'loan,
    'storage,
    'id,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
> {
    pub(super) owner: &'loan mut Scope<'storage, 'id, C, DOMAIN, B, D, T>,
    pub(super) row: Key<'id>,
    pub(super) index: links::Index,
    pub(super) hash: u64,
}

/// The exclusive root retains this initialized detached or linked Assigned.
unsafe impl<'storage, 'id, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    depot::raw::TagEntry for Node<'_, 'storage, 'id, C, DOMAIN, B, D, T>
{
    type Store = Scope<'storage, 'id, C, DOMAIN, B, D, T>;
    fn store(&self) -> &Self::Store {
        self.owner
    }
    fn index(&self) -> links::Index {
        self.index
    }
    fn hook(&self) -> &tagged::Hook {
        let slot = self.owner.entries.source.get(self.row.0);
        let value: &Assigned =
            unsafe { depot::raw::Proof::<_, Initialized<Assigned>>::new((slot, self.index)) }
                .into();
        value.hook()
    }
}

/// The cached hash selects only this retained root's immutable head allocation.
unsafe impl<C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T> depot::raw::TagTarget
    for Node<'_, '_, '_, C, DOMAIN, B, D, T>
{
    fn lane(&self) -> tagged::Endpoint<&Self::Store> {
        unsafe { endpoint(&*self.owner, self.hash) }
    }
}

pub(super) fn pack(
    key: Key<'_>,
    ordinal: array::Index<{ conn::MAX_ACTIVE_CONNECTION_IDS + 1 }>,
) -> links::Index {
    const {
        assert!(mux::MAX_CONNECTIONS <= u16::MAX as usize + 1);
        assert!(conn::MAX_ACTIVE_CONNECTION_IDS < 16);
    };
    let value = ((key.0.active().index() << 4) | ordinal.index()) as u32;
    let value = unsafe {
        bounded::raw::Proof::<0, { (mux::MAX_CONNECTIONS * 16 - 1) as u32 }>::assume(value)
    };
    value.retain().into()
}

pub(super) fn remove<
    'storage,
    'id,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
>(
    scope: &mut Scope<'storage, 'id, C, DOMAIN, B, D, T>,
    key: Key<'id>,
    local: path::LocalCidKey,
) {
    let index = pack(key, local.slot_index().widen());
    {
        let slot = scope.entries.source.get(key.0);
        let cell: &slot::Storage<Assigned> = unsafe {
            depot::raw::Proof::<_, Initialized<slot::Storage<Assigned>>>::new((slot, index))
        }
        .into();
        let Some(value) = cell.get() else {
            return;
        };
        if value.local() != Some(local) {
            return;
        }
    }
    use o3::depot::raw::TagEntry as _;
    // The admitted cell is linked under this same exclusive scope.
    let entry = unsafe { depot::raw::Proof::<_, Initialized<links::Chain>>::new((scope, index)) };
    let (scope, index) = unsafe { entry.linked() }.unlink().into_inner().into_inner();
    let slot = scope.entries.source.get_mut(key.0);
    let value: mem::raw::Occupied<'_, Assigned> =
        unsafe { depot::raw::Proof::<_, Initialized<Assigned>>::new((slot, index)) }.into();
    value.clear();
}

pub(in crate::runtime::routing::registry::set) fn detach<
    'loan,
    'storage,
    'id,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
>(
    mut scope: &'loan mut Scope<'storage, 'id, C, DOMAIN, B, D, T>,
    key: Key<'id>,
) {
    use o3::depot::raw::TagEntry as _;
    for ordinal in array::Index::<{ conn::MAX_ACTIVE_CONNECTION_IDS + 1 }>::iter() {
        let index = pack(key, ordinal);
        let present = {
            let slot = scope.entries.source.get(key.0);
            let cell: &slot::Storage<Assigned> = unsafe {
                depot::raw::Proof::<_, Initialized<slot::Storage<Assigned>>>::new((slot, index))
            }
            .into();
            cell.get().is_some()
        };
        if present {
            let entry =
                unsafe { depot::raw::Proof::<_, Initialized<links::Chain>>::new((scope, index)) };
            (scope, _) = unsafe { entry.linked() }.unlink().into_inner().into_inner();
        }
    }
}
