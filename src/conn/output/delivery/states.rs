use std::{marker, mem, num};

use o3::base::num::bounded;
use path::local;

use crate::{
    conn,
    conn::wire::path,
    errors,
    stream::outbound,
    wire::{stream, varint},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::conn) enum Control {
    HandshakeDone,
    NewConnectionId(local::Announcement),
    RetireConnectionId(varint::VarInt),
    StopSending(stream::Id, errors::Code),
    ResetStream(stream::Id, errors::Code, varint::VarInt),
    MaxData(varint::VarInt),
    MaxStreamData(stream::Id, varint::VarInt),
    MaxStreams(
        stream::Direction,
        bounded::U64<0, { conn::MAX_STREAM_COUNT }>,
    ),
    PathResponse(path::ControlKey),
    /// Application-requested challenge, retransmitted by ordinary PTO/loss.
    PathChallenge(path::ControlKey),
    /// Candidate-path probe, replaced with fresh entropy by the path deadline.
    PathValidation(path::ControlKey),
    DataBlocked(varint::VarInt),
    StreamDataBlocked(stream::Id, varint::VarInt),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::conn) struct Stream {
    pub(in crate::conn) id: stream::Id,
    pub(in crate::conn) range: outbound::Range,
    /// Exact frame bytes observed at the sole STREAM encoder boundary.
    /// `pmtud::MAX_PMTU < u16::MAX`; this occupies pre-existing tail padding.
    pub(in crate::conn) wire_len: num::NonZero<u16>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::conn) struct Crypto {
    offset: u64,
    len: num::NonZero<usize>,
}

impl Crypto {
    pub(in crate::conn) fn new(offset: u64, len: usize) -> Option<Self> {
        let len = num::NonZero::<usize>::new(len)?;
        offset.checked_add(u64::try_from(len.get()).ok()?)?;
        Some(Self { offset, len })
    }

    pub(in crate::conn) const fn offset(self) -> u64 {
        self.offset
    }

    pub(in crate::conn) const fn len(self) -> usize {
        self.len.get()
    }

    pub(in crate::conn) fn end(self) -> u64 {
        self.offset + self.len.get() as u64
    }

    pub(in crate::conn) fn split(self, max: usize) -> Option<(Self, Option<Self>)> {
        let len = num::NonZero::new(max.min(self.len()))?;
        let prefix = Self {
            offset: self.offset,
            len,
        };
        let suffix = num::NonZero::new(self.len() - len.get()).map(|len| Self {
            offset: prefix.end(),
            len,
        });
        Some((prefix, suffix))
    }
}

#[derive(PartialEq, Eq)]
pub(in crate::conn) struct Handle<T>(num::NonZero<u64>, marker::PhantomData<fn() -> T>);

impl<T> Clone for Handle<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Handle<T> {}

impl<T> Handle<T> {
    pub(in crate::conn) fn from_slot(index: u16, epoch: u32) -> Self {
        let raw = (u64::from(epoch) << 32) | (u64::from(index) + 1);
        Self(
            num::NonZero::<u64>::MIN.saturating_add(raw - 1),
            marker::PhantomData,
        )
    }

    pub(in crate::conn) fn index(self) -> usize {
        self.index_u32() as usize
    }

    pub(in crate::conn) fn index_u32(self) -> u32 {
        (self.0.get() as u32) - 1
    }

    pub(in crate::conn) fn generation(self) -> u32 {
        (self.0.get() >> 32) as u32
    }
}

const _: () = assert!(mem::size_of::<Control>() == 4 * mem::size_of::<u64>());
const _: () = assert!(std::mem::size_of::<Stream>() == 4 * std::mem::size_of::<u64>());
const _: () = assert!(mem::size_of::<Option<Handle<u8>>>() == mem::size_of::<u64>());
