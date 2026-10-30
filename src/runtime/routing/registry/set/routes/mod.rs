use crate::runtime::routing::registry;
use o3::base::num::bounded;
use o3::buffer;
use o3::depot::{
    self, capacity,
    index::Initialized,
    queue::{indexed::planes::bound, links, tagged},
};

use crate::conn::{id, wire::path};
use crate::runtime::mux;
use crate::runtime::mux::router;
use crate::runtime::routing::registry::set::{Bound, Entries, Live, Set, Tokens, scope::Scope};
use crate::stream;
use path::local::Assigned;
use registry::Key;
use router::reset;
use router::routing::state::cids;

pub(in crate::runtime::routing::registry) mod claims;
pub(in crate::runtime::routing::registry) mod issues;
pub(super) mod node;
use claims::Reservation;

pub(in crate::runtime) struct Directory<
    'storage,
    'id,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
> {
    entries: Bound<'storage, 'id, C, DOMAIN, B, D, T>,
    resets: Tokens<'storage, 'id>,
    cids: &'storage mut registry::Table,
    tokens: &'storage reset::Reset,
    active: &'storage mut u32,
}

pub(in crate::runtime) struct Hit<
    'storage,
    'id,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
> {
    owner: Directory<'storage, 'id, C, DOMAIN, B, D, T>,
    index: links::Index,
    local: Option<path::LocalCidKey>,
}

impl<'storage, 'id, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    Directory<'storage, 'id, C, DOMAIN, B, D, T>
{
    pub(in crate::runtime) fn with<R>(
        set: &'storage mut Set<C, DOMAIN, B, D, T>,
        apply: impl for<'next> FnOnce(Directory<'storage, 'next, C, DOMAIN, B, D, T>) -> R,
    ) -> R {
        let Set {
            entries,
            cids,
            reset,
            active,
        } = set;
        bound::Scope::with(entries, |root| {
            let (entries, resets) = root.split();
            apply(Directory {
                entries,
                resets,
                cids,
                tokens: reset,
                active,
            })
        })
    }

    pub(in crate::runtime) fn hash(&self, bytes: &[u8]) -> u64 {
        self.cids.hash(bytes)
    }

    pub(in crate::runtime) fn len(&self) -> usize {
        *self.active as usize
    }

    pub(in crate::runtime) fn contains(&self, bytes: &[u8], hash: u64) -> bool {
        unsafe { scan(self, bytes, hash) }.is_some()
    }

    pub(in crate::runtime) fn lookup(
        self,
        bytes: &[u8],
        hash: u64,
    ) -> Result<Hit<'storage, 'id, C, DOMAIN, B, D, T>, Self> {
        match unsafe { scan(&self, bytes, hash) } {
            Some((index, local)) => Ok(Hit {
                owner: self,
                index,
                local,
            }),
            None => Err(self),
        }
    }

    pub(in crate::runtime) fn claim<I: Copy>(
        mut self,
        domain: id::Domain<I, DOMAIN>,
        routes: cids::Routes<'id>,
    ) -> Option<Reservation<'storage, 'id, C, I, DOMAIN, B, D, T>> {
        let (key, epoch) = loop {
            let (key, front) = self.entries.front_entry::<{ mux::FREE_QUEUE }>()?;
            let mut entry = front.pop();
            if let Some(epoch) = entry.metadata_mut().claim() {
                break (key, epoch);
            }
        };
        let handle = domain.handle(key.position(), epoch);
        Some(Reservation {
            owner: self,
            key,
            handle,
            routes,
        })
    }

    pub(in crate::runtime) fn capacity(
        &self,
    ) -> (usize, capacity::Limit<{ mux::MAX_CONNECTIONS }>) {
        (*self.active as usize, self.entries.limit())
    }
}

impl<'storage, 'id, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    Hit<'storage, 'id, C, DOMAIN, B, D, T>
{
    pub(in crate::runtime) fn into_scope(
        self,
    ) -> (
        Scope<'storage, 'id, C, DOMAIN, B, D, T>,
        Key<'id>,
        Option<path::LocalCidKey>,
    ) {
        let Directory {
            entries,
            resets,
            cids,
            tokens,
            active,
        } = self.owner;
        let index = parent(self.index);
        let source = unsafe {
            depot::raw::Proof::<_, Initialized<Live<'storage, 'id, C, DOMAIN, B, D, T>>>::new((
                entries, index,
            ))
        };
        let (entries, key) = source.into();
        (
            Scope {
                entries: Entries { source: entries },
                resets,
                cids,
                tokens,
                active,
            },
            Key(key),
            self.local,
        )
    }
}

/// Every linked CID remains inside its installed row until it is unlinked.
/// The private whole-root owner excludes resize, removal, and competing publication.
unsafe impl<C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T> depot::raw::TagStore
    for Directory<'_, '_, C, DOMAIN, B, D, T>
{
    type Head = links::List;
    type Heads = [links::List];

    fn heads(&self) -> &Self::Heads {
        self.cids.heads()
    }

    fn capacity(&self) -> usize {
        mux::MAX_CONNECTIONS * 16
    }

    unsafe fn hook(&self, index: links::Index) -> &tagged::Hook {
        unsafe { depot::raw::Project::<_, links::Chain>::project(self, index) }.hook()
    }
}

/// A linked child retains its original installed parent and initialized Assigned cell.
unsafe impl<'loan, 'storage, 'id, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    depot::raw::Project<links::Index, links::Chain>
    for &'loan Directory<'storage, 'id, C, DOMAIN, B, D, T>
{
    type Output = &'loan Assigned;

    unsafe fn project(self, index: links::Index) -> Self::Output {
        let row = parent(index);
        let source = unsafe {
            depot::raw::Proof::<_, Initialized<Live<'storage, 'id, C, DOMAIN, B, D, T>>>::new((
                &self.entries,
                row,
            ))
        };
        let slot: &'loan registry::Slot<C, DOMAIN, B, D, T> = source.into();
        unsafe { depot::raw::Proof::<_, Initialized<Assigned>>::new((slot, index)) }.into()
    }
}

pub(super) fn parent(index: links::Index) -> links::Index {
    const {
        assert!(mux::MAX_CONNECTIONS <= u16::MAX as usize + 1);
        assert!(crate::conn::MAX_ACTIVE_CONNECTION_IDS < 16);
    };
    let row = (index.get() >> 4) as u32;
    let row = unsafe { bounded::raw::Proof::<0, { mux::MAX_CONNECTIONS as u32 - 1 }>::assume(row) };
    row.retain().into()
}

/// This private caller retains the same nonempty power-of-two heads and freezes
/// topology and payloads for every cursor or item loan, including after cursor drop.
unsafe fn scan<'loan, S>(
    owner: &'loan S,
    bytes: &[u8],
    hash: u64,
) -> Option<(links::Index, Option<path::LocalCidKey>)>
where
    S: depot::raw::TagStore<Head = links::List, Heads = [links::List]>,
    &'loan S: depot::raw::Project<links::Index, links::Chain, Output = &'loan Assigned>,
{
    let lane = hash as usize & (owner.heads().len() - 1);
    let cursor: tagged::Endpoint<&'loan S, Option<links::Index>> = unsafe {
        depot::raw::Proof::<_, Initialized<tagged::Endpoint<&'loan S, Option<links::Index>>>>::new(
            (owner, lane),
        )
    }
    .into();
    for node in cursor {
        let (owner, index) = node.into_inner();
        let value = unsafe { depot::raw::Project::<_, links::Chain>::project(owner, index) };
        if value.value().as_slice() == bytes {
            return Some((index, value.local()));
        }
    }
    None
}

/// The private caller retains the same original nonempty power-of-two head allocation.
unsafe fn endpoint<S>(owner: &S, hash: u64) -> tagged::Endpoint<&S>
where
    S: depot::raw::TagStore<Head = links::List, Heads = [links::List]>,
{
    let lane = hash as usize & (owner.heads().len() - 1);
    unsafe { depot::raw::Proof::<_, Initialized<tagged::Endpoint<&S>>>::new((owner, lane)) }.into()
}
