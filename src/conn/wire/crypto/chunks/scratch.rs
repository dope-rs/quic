use std::{marker, mem};

use o3::alloc::{self, VecExt as _};

use crate::conn::wire::crypto::fragment;
use crate::wire::{frame, ranges};

/// The actual plan payload retained by its matching CRYPTO frame record.
pub(in crate::conn) struct Step<'id> {
    pub(super) kind: Kind,
    owner: marker::PhantomData<*mut &'id ()>,
}

/// One exclusive record loan consumed by the prepared control traversal.
pub(in crate::conn) struct Access<'step, 'id> {
    pub(super) step: &'step mut Step<'id>,
}

impl<'id> Step<'id> {
    pub(in crate::conn::wire) const fn new(_body: &frame::Body<'_, 'id>) -> Self {
        Self {
            kind: Kind::Ignore,
            owner: marker::PhantomData,
        }
    }

    pub(in crate::conn::wire) fn borrow(&mut self) -> Access<'_, 'id> {
        Access { step: self }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Ignore,
    Direct {
        start: usize,
        len: u32,
    },
    Reset {
        start: usize,
        len: u32,
    },
    Buffered {
        start: usize,
        insert: fragment::Insert,
        drain: Option<fragment::Span>,
        reset: bool,
    },
}

pub(in crate::conn) struct Scratch {
    pub(super) spans: Vec<fragment::Span>,
}

impl Scratch {
    pub(super) fn clear(&mut self) {
        self.spans.clear();
    }

    pub(in crate::conn) fn try_new() -> Result<Self, alloc::Error> {
        Ok(Self {
            spans: Vec::try_new(ranges::MAX)?,
        })
    }
}

const _: () = assert!(mem::size_of::<Scratch>() == 3 * mem::size_of::<usize>());
