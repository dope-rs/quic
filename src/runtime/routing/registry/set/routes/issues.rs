use crate::runtime::routing::registry;
use o3::buffer;
use o3::depot::{
    self,
    index::{self, Initialized},
};
use o3::mem;

use crate::runtime::mux::router::routing::state::cids;
use crate::runtime::routing::registry::set::routes::{
    node::{Node, pack, remove},
    scan,
};
use crate::{
    conn::wire::path::local::{Assigned, routes},
    runtime::brand,
    stream,
};
use registry::{Key, set::scope::Scope};

pub(in crate::runtime) struct Drain<
    'loan,
    'storage,
    'id,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
> {
    pub(in crate::runtime::routing::registry::set) scope:
        &'loan mut Scope<'storage, 'id, C, DOMAIN, B, D, T>,
    pub(in crate::runtime::routing::registry::set) key: Key<'id>,
    pub(in crate::runtime::routing::registry::set) drain: routes::Drain,
    pub(in crate::runtime::routing::registry::set) brand: brand::Token<'loan>,
}
pub(in crate::runtime) struct Issue<
    'loan,
    'storage,
    'id,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
> {
    owner: Drain<'loan, 'storage, 'id, C, DOMAIN, B, D, T>,
    prepared: routes::Prepared<'loan>,
}

impl<'loan, 'storage, 'id, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    Drain<'loan, 'storage, 'id, C, DOMAIN, B, D, T>
{
    pub(in crate::runtime) fn next(
        mut self,
    ) -> Option<Issue<'loan, 'storage, 'id, C, DOMAIN, B, D, T>> {
        loop {
            let update = self.drain.next(
                &mut self.scope.entries.source.get_mut(self.key.0).conn,
                self.brand,
            )?;
            match update {
                routes::Update::Remove(local) => remove(self.scope, self.key, local.key()),
                routes::Update::Issue(prepared) => {
                    return Some(Issue {
                        owner: self,
                        prepared,
                    });
                }
            }
        }
    }
}

impl<'loan, 'storage, 'id, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    Issue<'loan, 'storage, 'id, C, DOMAIN, B, D, T>
{
    pub(in crate::runtime) fn hash(&self, value: &[u8]) -> u64 {
        self.owner.scope.cids.hash(value)
    }
    pub(in crate::runtime) fn len(&self) -> usize {
        *self.owner.scope.active as usize
    }
    pub(in crate::runtime) fn contains(&self, value: &[u8], hash: u64) -> bool {
        unsafe { scan(self.owner.scope, value, hash) }.is_some()
    }

    /// The consumed Issue retains actual metadata, issuance and vacancy during all shared lookups.
    pub(in crate::runtime) fn defer(self) {
        let Self { owner, prepared } = self;
        let Drain { scope, key, .. } = owner;
        let conn = &mut scope.entries.source.get_mut(key.0).conn;
        unsafe { depot::raw::Proof::<_, Initialized<routes::raw::Deferred>>::new((conn, prepared)) }
            .into()
    }

    /// The real child vacancy is initialized before its loan ends; publication returns
    /// the same whole owner before the retained metadata completes its reset token.
    pub(in crate::runtime) fn assign(
        self,
        route: cids::Route,
    ) -> Drain<'loan, 'storage, 'id, C, DOMAIN, B, D, T> {
        use o3::depot::raw::TagEntry as _;
        let Self { owner, prepared } = self;
        let Drain {
            scope,
            key,
            drain,
            brand,
        } = owner;
        let local = prepared.key();
        let index = pack(key, local.slot_index().widen());
        let value = {
            let slot = scope.entries.source.get_mut(key.0);
            let vacant: mem::raw::Vacant<'_, Assigned> = unsafe {
                depot::raw::Proof::<_, Initialized<index::Vacant<Assigned>>>::new((slot, index))
            }
            .into();
            vacant
                .insert(Assigned::new(route.value(), Some(local), index))
                .get()
                .value()
        };
        let node = Node {
            owner: scope,
            row: key,
            index,
            hash: route.hash(),
        };
        let Node { owner: scope, .. } = unsafe { node.vacant() }.push::<true>().into_inner();
        let conn = &mut scope.entries.source.get_mut(key.0).conn;
        let done: routes::Completion<'_> = unsafe {
            depot::raw::Proof::<_, Initialized<routes::raw::Published>>::new((conn, prepared))
        }
        .into();
        done.finish(value);
        Drain {
            scope,
            key,
            drain,
            brand,
        }
    }
}
