use crate::runtime::routing::registry;
use std::time;

use crate::conn::wire::path::local::Assigned;
use crate::runtime::routing::registry::set::{Live, routes};
use o3::depot::{heap::indexed, queue::indexed::planes::bound};
use o3::depot::{
    index::Initialized,
    queue::{links, tagged},
};
use o3::{buffer, depot};

use crate::runtime::mux::router;
use crate::runtime::routing::registry::set::{
    Entries, Entry, Group, Record, Set, Tokens,
    routes::{issues::Drain, node},
};
use crate::runtime::{brand, mux};
use crate::{conn, stream};
use conn::id;
use registry::Key;
use router::reset;

pub(in crate::runtime) struct Taken<
    'storage,
    C,
    I,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
> {
    handle: id::Handle<I, DOMAIN>,
    slot: registry::Slot<C, DOMAIN, B, D, T>,
    entry: Record<'storage, C, DOMAIN, B, D, T>,
}

impl<C, I, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    Taken<'_, C, I, DOMAIN, B, D, T>
{
    pub(in crate::runtime) fn close(
        self,
        close: impl FnOnce(id::Handle<I, DOMAIN>, conn::Connection<DOMAIN, B, D>, C),
    ) {
        let Self {
            handle,
            slot,
            mut entry,
        } = self;
        close(handle, slot.conn, slot.connection);
        entry.plane::<{ mux::FREE_QUEUE }>().link_back();
    }
}

/// One installed generation remains stable until its whole scope is consumed.
pub(in crate::runtime) struct Scope<
    'storage,
    'id,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
> {
    pub(super) entries: Entries<'storage, 'id, C, DOMAIN, B, D, T>,
    pub(super) resets: Tokens<'storage, 'id>,
    pub(super) cids: &'storage mut registry::Table,
    pub(super) tokens: &'storage reset::Reset,
    pub(super) active: &'storage mut u32,
}

impl<'storage, 'id, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    Scope<'storage, 'id, C, DOMAIN, B, D, T>
{
    pub(in crate::runtime) fn with<R>(
        set: &'storage mut Set<C, DOMAIN, B, D, T>,
        apply: impl for<'next> FnOnce(Scope<'storage, 'next, C, DOMAIN, B, D, T>) -> R,
    ) -> R {
        let Set {
            entries,
            cids,
            reset,
            active,
        } = set;
        bound::Scope::with(entries, |root| {
            let (entries, resets) = root.split();
            apply(Scope {
                entries: Entries {
                    source: entries.resident::<{ mux::FREE_QUEUE }>(),
                },
                resets,
                cids,
                tokens: reset,
                active,
            })
        })
    }

    pub(in crate::runtime) fn bind<I: Copy>(
        &self,
        domain: id::Domain<I, DOMAIN>,
        handle: id::Handle<I, DOMAIN>,
    ) -> Option<Key<'id>> {
        if !handle.belongs_to(domain) {
            return None;
        }
        let key = self.entries.source.resolve(handle.index() as usize)?;
        if !self
            .entries
            .source
            .metadata_at(key)
            .matches(handle.generation())
        {
            return None;
        }
        self.entries.admit(key)
    }

    pub(in crate::runtime) fn resolve(&self, index: usize) -> Option<Key<'id>> {
        let key = self.entries.source.resolve(index)?;
        self.entries.admit(key)
    }

    pub(in crate::runtime) fn handle<I: Copy>(
        &self,
        domain: id::Domain<I, DOMAIN>,
        key: Key<'id>,
    ) -> id::Handle<I, DOMAIN> {
        domain.handle(
            key.0.active().position(),
            self.entries.source.metadata(key.0).get(),
        )
    }

    pub(in crate::runtime) fn get(&self, key: Key<'id>) -> &registry::Slot<C, DOMAIN, B, D, T> {
        self.entries.source.get(key.0)
    }

    pub(in crate::runtime) fn access<'loan, const TRACK: bool>(
        &'loan mut self,
        key: Key<'id>,
        brand: brand::Token<'loan>,
    ) -> registry::Access<'loan, C, DOMAIN, B, D, T, TRACK> {
        self.entries.access(key, brand)
    }

    pub(in crate::runtime) fn is_empty_in<const PLANE: usize>(&self) -> bool {
        self.entries.source.is_empty::<PLANE>()
    }

    pub(in crate::runtime) fn len_in<const PLANE: usize>(&self) -> usize {
        self.entries.source.len_in::<PLANE>()
    }

    pub(in crate::runtime) fn front<const PLANE: usize>(&self) -> Option<Key<'id>> {
        self.entries.source.front::<PLANE>().map(Key)
    }

    pub(in crate::runtime) fn iter<const PLANE: usize>(
        &self,
    ) -> impl Iterator<Item = (Key<'id>, &registry::Slot<C, DOMAIN, B, D, T>)> {
        self.entries
            .source
            .iter::<PLANE>()
            .map(|(key, slot)| (Key(key), slot))
    }

    pub(in crate::runtime) fn entry(&mut self, key: Key<'id>) -> Entry<'_, C, DOMAIN, B, D, T> {
        Entry {
            inner: self.entries.source.entry(key.0),
        }
    }

    pub(in crate::runtime) fn pop_front<const PLANE: usize>(&mut self) -> Option<Key<'id>> {
        let (key, front) = self.entries.source.front_entry::<PLANE>()?;
        front.pop();
        Some(Key(key))
    }

    pub(in crate::runtime) fn refresh(
        &mut self,
        key: Key<'id>,
        now: time::Instant,
        update: conn::DeadlineMode,
        retry: Option<time::Instant>,
    ) {
        let (timer, entry) = self.entries.select(key);
        Set::refresh(timer, entry, now, update, retry);
    }

    pub(in crate::runtime) fn resets(
        &mut self,
    ) -> (
        &mut Entries<'storage, 'id, C, DOMAIN, B, D, T>,
        &Tokens<'storage, 'id>,
        &reset::Reset,
    ) {
        (&mut self.entries, &self.resets, self.tokens)
    }

    pub(in crate::runtime) fn routing<'loan>(
        &'loan mut self,
        brand: brand::Token<'loan>,
        key: Key<'id>,
        apply: impl FnOnce(registry::Access<'_, C, DOMAIN, B, D, T, false>, Group<'_>, &reset::Reset),
    ) -> Option<Drain<'loan, 'storage, 'id, C, DOMAIN, B, D, T>> {
        let slot = self.entries.source.get_mut(key.0);
        let group = self.resets.group(key.0.active());
        apply(slot.access(brand.reborrow()), group, self.tokens);
        let drain = slot
            .access::<false>(brand.reborrow())
            .conn
            .routing()
            .drain()?;
        Some(Drain {
            scope: self,
            key,
            drain,
            brand,
        })
    }

    pub(in crate::runtime) fn into_taken<I: Copy>(
        mut self,
        key: Key<'id>,
        domain: id::Domain<I, DOMAIN>,
    ) -> Taken<'storage, C, I, DOMAIN, B, D, T> {
        let handle = self.handle(domain, key);
        node::detach(&mut self, key);
        let Self {
            entries,
            resets,
            active,
            ..
        } = self;
        let (timer, mut entry) = entries.source.into_select(key.0, resets);
        if let indexed::Entry::Occupied(timer) = timer {
            timer.retire();
        }
        entry.unlink::<{ mux::NOTIFY_QUEUE }>();
        entry.unlink::<{ mux::FLUSH_QUEUE }>();
        entry.unlink::<{ mux::REAP_QUEUE }>();
        entry.unlink::<{ mux::APPLICATION_QUEUE }>();
        let (slot, entry) = entry.take();
        *active -= 1;
        Taken {
            handle,
            slot,
            entry,
        }
    }
}

/// Shared scope operations never mutate routing topology or expose its storage.
unsafe impl<C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T> depot::raw::TagStore
    for Scope<'_, '_, C, DOMAIN, B, D, T>
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

/// A published initialized child retains its installed parent in the same active prefix.
unsafe impl<'loan, 'storage, 'id, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    depot::raw::Project<links::Index, links::Chain>
    for &'loan Scope<'storage, 'id, C, DOMAIN, B, D, T>
{
    type Output = &'loan Assigned;
    unsafe fn project(self, index: links::Index) -> Self::Output {
        let row = routes::parent(index);
        let source = unsafe {
            depot::raw::Proof::<_, Initialized<Live<'storage, 'id, C, DOMAIN, B, D, T>>>::new((
                &self.entries.source,
                row,
            ))
        };
        let slot: &'loan registry::Slot<C, DOMAIN, B, D, T> = source.into();
        unsafe { depot::raw::Proof::<_, Initialized<Assigned>>::new((slot, index)) }.into()
    }
}
