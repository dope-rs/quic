use std::{marker, mem};

use crate::wire::packet::kind;

mod boundary;

pub(crate) use boundary::Boundary;

/// Evidence that packet protection consumed `T` and completed successfully.
#[repr(transparent)]
pub(crate) struct Protected<T>(T);

impl<T> Protected<T> {
    pub(super) const fn new(proof: T) -> Self {
        Self(proof)
    }

    pub(crate) const fn auth(&self) -> &T {
        &self.0
    }
}

/// A protected packet borrowing its exact in-place wire allocation.
#[must_use = "protected wire evidence must be consumed before buffer reuse"]
pub(crate) struct Wire<'packet, K: kind::Kind = kind::OneRtt> {
    bytes: &'packet mut [u8],
    marker: marker::PhantomData<fn() -> K>,
}

impl<'packet, K: kind::Kind> Wire<'packet, K> {
    pub(super) fn new(bytes: &'packet mut [u8]) -> Self {
        Self {
            bytes,
            marker: marker::PhantomData,
        }
    }

    pub(crate) fn into_len(self) -> usize {
        self.bytes.len()
    }
}

pub struct Open;

pub(crate) struct Seal;

const _: () = assert!(mem::size_of::<Protected<u64>>() == mem::size_of::<u64>());
const _: () = assert!(!mem::needs_drop::<Protected<u64>>());
const _: () =
    assert!(mem::size_of::<Wire<'static, kind::Initial>>() == 2 * mem::size_of::<usize>());
