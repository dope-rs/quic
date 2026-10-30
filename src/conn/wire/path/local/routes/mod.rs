use std::{
    mem::{align_of, size_of},
    num,
};

use crate::conn::wire::path::local::{self, key};
use crate::runtime::brand;
use crate::security::secrets;
use crate::wire::packet::cid;
use crate::{conn, conn::wire::path, stream};
use o3::{buffer, depot, mem};

#[derive(Clone, Copy)]
pub(super) struct Index(u8);

impl Index {
    pub(super) fn iter() -> impl Iterator<Item = Self> {
        (0..conn::MAX_ACTIVE_CONNECTION_IDS as u8).map(Self)
    }

    pub(super) const fn from_key(key: path::LocalCidKey) -> Self {
        Self(key.slot() as u8)
    }

    pub(super) const fn get(self) -> usize {
        self.0 as usize
    }

    const fn bit(self) -> u8 {
        1 << self.0
    }

    pub(super) const fn key(self, epoch: u32) -> path::LocalCidKey {
        let raw = ((epoch as u64) << 32) | self.0 as u64;
        key::LocalCidKey(num::NonZero::<u64>::MIN.saturating_add(raw))
    }

    fn pop(mask: &mut u8) -> Option<Self> {
        if *mask == 0 {
            return None;
        }
        let index = mask.trailing_zeros() as u8;
        *mask &= *mask - 1;
        Some(Self(index))
    }
}

// SAFETY: every constructor retains a local slot in 0..MAX_ACTIVE_CONNECTION_IDS.
// Packed keys preserve that slot independently of their generation; reconstruction
// accepts only a position in the same fixed domain.
unsafe impl depot::raw::BitIndex<{ conn::MAX_ACTIVE_CONNECTION_IDS }> for Index {
    fn index(self) -> usize {
        self.0 as usize
    }

    unsafe fn from_index(index: usize) -> Self {
        Self(index as u8)
    }
}

#[repr(transparent)]
pub(super) struct Issued(Index);

impl Issued {
    pub(super) const fn new(index: Index) -> Self {
        Self(index)
    }

    pub(super) const fn index(&self) -> Index {
        self.0
    }

    const fn key(&self, epoch: u32) -> path::RouteKey {
        key::RouteKey(self.0.key(epoch))
    }
}

#[derive(Default)]
#[repr(transparent)]
pub(super) struct Issues(u8);

impl Issues {
    pub(super) fn insert(&mut self, issued: Issued) {
        self.0 |= issued.0.bit();
    }

    fn pop(&mut self) -> Option<Issued> {
        Index::pop(&mut self.0).map(Issued)
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

#[derive(Default)]
pub(super) struct Pending {
    removals: u8,
}

impl Pending {
    pub(super) fn remove(&mut self, index: Index) {
        self.removals |= index.bit();
    }

    pub(super) const fn has_removal(&self, index: Index) -> bool {
        self.removals & index.bit() != 0
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.removals == 0
    }
}

#[must_use = "a pending route update must be committed or deferred"]
pub(crate) enum Update<'a> {
    Issue(Prepared<'a>),
    Remove(Remove<'a>),
}

/// A selected metadata slot retained by the private whole routing owner.
/// This value alone does not grant access to a CID cell or its metadata.
#[must_use = "a local CID issue must be assigned or deferred"]
pub(crate) struct Prepared<'a> {
    _brand: brand::Token<'a>,
    key: path::RouteKey,
    index: Issued,
}

impl<'a> Prepared<'a> {
    pub(crate) const fn key(&self) -> path::LocalCidKey {
        self.key.local()
    }
}

/// The original token destination borrowed only after its CID was published.
pub(crate) struct Completion<'a> {
    cid: mem::raw::Occupied<'a, local::LocalCid>,
    secret: &'a secrets::Reset,
}

impl Completion<'_> {
    pub(crate) fn finish(mut self, value: cid::Id) {
        self.cid.get_mut().reset_token = self.secret.token_for(value.as_slice());
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub(crate) struct Remove<'a>(brand::Branded<'a, path::LocalCidKey>);

impl<'a> Remove<'a> {
    pub(crate) const fn key(&self) -> path::LocalCidKey {
        *self.0.value()
    }
}

/// The existing remove-before-fill traversal, retained by one routing owner.
pub(crate) struct Drain {
    filled: bool,
}

impl Drain {
    pub(super) const fn new() -> Self {
        Self { filled: false }
    }

    pub(crate) fn next<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>(
        &mut self,
        conn: &mut conn::Connection<DOMAIN, B, D>,
        brand: brand::Token<'a>,
    ) -> Option<Update<'a>> {
        let state = &mut conn.machine_mut().path.local;
        while let Some(index) = Index::pop(&mut state.pending.removals) {
            let Some(slot) = state.cids.slots.get_mut(index.get()) else {
                continue;
            };
            if slot.cid.get().is_some() {
                continue;
            }
            let key = index.key(slot.generation);
            match slot.generation.checked_add(1) {
                Some(next) => slot.generation = next,
                None => state.cids.burned |= index.bit(),
            }
            return Some(Update::Remove(Remove(brand::Branded::new(brand, key))));
        }
        let issue = state.issuance.get_mut()?;
        if !self.filled {
            self.filled = true;
            state.cids.fill(issue, &state.pending);
        }
        let mut slots = state.cids.slots.iter_mut();
        let mut start = 0;
        loop {
            let issued = issue.issues.pop()?;
            let index = issued.index();
            let Some(slot) = slots.nth(index.get() - start) else {
                continue;
            };
            start = index.get() + 1;
            if slot.cid.get().is_none() || slot.node.vacant().is_none() {
                continue;
            }
            let key = issued.key(slot.generation);
            return Some(Update::Issue(Prepared {
                _brand: brand,
                key,
                index: issued,
            }));
        }
    }
}

pub(crate) mod raw;

const _: () = {
    assert!(conn::MAX_ACTIVE_CONNECTION_IDS <= u8::BITS as usize);
    assert!(size_of::<Index>() == 1);
    assert!(size_of::<Issued>() == 1);
    assert!(size_of::<Issues>() == 1);
    assert!(size_of::<Pending>() == 1);
    assert!(size_of::<Remove<'static>>() == size_of::<path::LocalCidKey>());
    assert!(align_of::<Remove<'static>>() == align_of::<path::LocalCidKey>());
};
