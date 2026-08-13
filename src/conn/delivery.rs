use std::marker;
use std::mem;
use std::num;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Control {
    HandshakeDone,
    NewConnectionId(u64),
    RetireConnectionId(u64),
    StopSending(u64, u64),
    ResetStream(u64, u64, u64),
    MaxData(u64),
    MaxStreamData(u64, u64),
    MaxStreams(bool, u64),
    PathResponse([u8; 8]),
    PathChallenge([u8; 8]),
    DataBlocked(u64),
    StreamDataBlocked(u64, u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Stream {
    pub(super) stream_id: u64,
    pub(super) offset: u64,
    pub(super) len: u64,
    pub(super) fin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Crypto {
    pub(super) offset: u64,
    pub(super) len: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Handle<T>(num::NonZeroU64, marker::PhantomData<fn() -> T>);

impl<T> Clone for Handle<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Handle<T> {}

impl<T> Handle<T> {
    pub(super) fn new(index: usize, generation: u32) -> Option<Self> {
        let encoded_index = u32::try_from(index).ok()?.checked_add(1)?;
        let raw = (u64::from(generation) << 32) | u64::from(encoded_index);
        Some(Self(num::NonZeroU64::new(raw)?, marker::PhantomData))
    }

    pub(super) fn index(self) -> usize {
        ((self.0.get() as u32) - 1) as usize
    }

    pub(super) fn generation(self) -> u32 {
        (self.0.get() >> 32) as u32
    }
}

const _: () = assert!(mem::size_of::<Option<Handle<u8>>>() == mem::size_of::<u64>());
