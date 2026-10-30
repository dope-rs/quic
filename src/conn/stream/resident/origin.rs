//! Connection-resident lexical identity.

use std::{cell, mem, num};

use crate::conn::id;
use crate::conn::stream::resident::Exhausted;

thread_local! {
    static NEXT_ORIGIN: cell::Cell<u64> = const { cell::Cell::new(1) };
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin(id::Local<num::NonZero<u64>>);

impl Origin {
    pub(in crate::conn) fn try_new(max: u64) -> Result<Self, Exhausted> {
        NEXT_ORIGIN.with(|next| {
            id::Local::allocate(next, max).map(Self).ok_or(Exhausted {
                next: next.get(),
                maximum: max,
            })
        })
    }

    #[doc(hidden)]
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match num::NonZero::<u64>::new(raw) {
            Some(raw) => Some(Self(id::Local::new(raw))),
            None => None,
        }
    }

    pub(in crate::conn) const fn from_index(index: u64) -> Self {
        Self(id::Local::new(
            num::NonZero::<u64>::MIN.saturating_add(index),
        ))
    }

    #[doc(hidden)]
    pub const fn raw(self) -> u64 {
        self.0.value().get()
    }
}

const _: () = assert!(mem::size_of::<Origin>() == mem::size_of::<u64>());
