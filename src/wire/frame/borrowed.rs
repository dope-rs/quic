use std::ops;

use crate::wire::frame::ack::ranges;
use crate::wire::frame::close;
use crate::wire::frame::decode::error;
use crate::wire::{frame, packet::cid, stream, varint};

/// A validated outbound frame that borrows payload and ACK storage from its
/// caller. The lifetime makes retaining or encoding after that storage dies a
/// compile-time error; construction and encoding allocate nothing.
#[repr(transparent)]
#[derive(PartialEq, Eq)]
pub struct Borrowed<'a>(
    frame::Frame<&'a [u8], &'a [(varint::VarInt, varint::VarInt)], cid::Ref<'a>>,
);

impl<'a> Borrowed<'a> {
    pub fn ack(
        largest: varint::VarInt,
        delay: varint::VarInt,
        first: varint::VarInt,
        rest: &'a [(varint::VarInt, varint::VarInt)],
    ) -> Result<Self, error::Fault> {
        let count = ranges::validate_pairs(largest, first, rest)?;
        Ok(Self(frame::Frame(frame::Repr::Ack {
            largest,
            delay,
            first_range: first,
            count,
            additional_ranges: rest,
        })))
    }

    pub fn crypto(offset: varint::VarInt, data: &'a [u8]) -> Result<Self, error::Fault> {
        let len = varint::VarInt::from_usize(data.len()).ok_or(error::Fault::InvalidLength {
            offset: offset.get(),
            length: data.len() as u64,
        })?;
        error::Fault::check_span(offset, len)?;
        Ok(Self(frame::Frame(frame::Repr::Crypto {
            offset,
            len,
            data,
        })))
    }

    pub(crate) fn datagram(data: &'a [u8]) -> Self {
        Self(frame::Frame(frame::Repr::Datagram { data }))
    }

    pub(crate) fn try_close(code: close::Code, reason: &'a [u8]) -> Result<Self, error::Fault> {
        let len = varint::VarInt::from_usize(reason.len()).ok_or(error::Fault::InvalidLength {
            offset: 0,
            length: reason.len() as u64,
        })?;
        Ok(Self(frame::Frame(frame::Repr::ConnectionClose {
            code,
            len,
            reason,
        })))
    }

    pub fn stream(
        stream: stream::Id,
        offset: varint::VarInt,
        boundary: frame::Boundary,
        length: frame::Length,
        data: &'a [u8],
    ) -> Result<Self, error::Fault> {
        let len = varint::VarInt::from_usize(data.len()).ok_or(error::Fault::InvalidLength {
            offset: offset.get(),
            length: data.len() as u64,
        })?;
        error::Fault::check_span(offset, len)?;
        Ok(Self(frame::Frame(frame::Repr::Stream {
            stream_id: stream,
            offset,
            boundary,
            length,
            len,
            data,
        })))
    }
}

impl<'a> ops::Deref for Borrowed<'a> {
    type Target = frame::Frame<&'a [u8], &'a [(varint::VarInt, varint::VarInt)], cid::Ref<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
