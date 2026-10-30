use crate::wire::frame::close;
use crate::wire::frame::decode;
use crate::{
    errors,
    wire::{frame, packet::cid, stream, varint},
};
use frame::{Length, View, ack::ranges};
use o3::alloc::{self, array::Plan};

#[derive(PartialEq, Eq)]
pub(crate) enum Repr<Data, Ranges, C> {
    Padding,
    Ping,
    Ack {
        largest: varint::VarInt,
        delay: varint::VarInt,
        first_range: varint::VarInt,
        count: u16,
        additional_ranges: Ranges,
    },
    Crypto {
        offset: varint::VarInt,
        len: varint::VarInt,
        data: Data,
    },
    NewToken {
        len: varint::VarInt,
        token: Data,
    },
    Datagram {
        data: Data,
    },
    DatagramLen {
        len: varint::VarInt,
        data: Data,
    },
    HandshakeDone,
    ConnectionClose {
        code: close::Code,
        len: varint::VarInt,
        reason: Data,
    },
    NewConnectionId {
        notice: decode::Notice<C>,
        retire: decode::Retire,
    },
    RetireConnectionId {
        sequence_number: varint::VarInt,
    },
    PathChallenge {
        data: [u8; 8],
    },
    PathResponse {
        data: [u8; 8],
    },
    Stream {
        stream_id: stream::Id,
        offset: varint::VarInt,
        boundary: frame::Boundary,
        length: frame::Length,
        len: varint::VarInt,
        data: Data,
    },
    ResetStream {
        stream_id: stream::Id,
        error_code: errors::Code,
        final_size: varint::VarInt,
    },
    StopSending {
        stream_id: stream::Id,
        error_code: errors::Code,
    },
    MaxData {
        maximum_data: varint::VarInt,
    },
    MaxStreamData {
        stream_id: stream::Id,
        maximum_stream_data: varint::VarInt,
    },
    DataBlocked {
        maximum_data: varint::VarInt,
    },
    StreamDataBlocked {
        stream_id: stream::Id,
        maximum_stream_data: varint::VarInt,
    },
    MaxStreams {
        direction: stream::Direction,
        max_streams: varint::VarInt,
    },
    StreamsBlocked {
        direction: stream::Direction,
        max_streams: varint::VarInt,
    },
}

pub(super) fn try_ranges(
    ranges: ranges::Set<'_>,
) -> Result<Vec<(varint::VarInt, varint::VarInt)>, alloc::Error> {
    let block = Plan::try_new(ranges.len())?.try_allocate(())?;
    // SAFETY: Set's private construction validated this exact count and order
    // against its immutable borrowed bytes. Consuming it yields one pair per
    // admitted slot, and the callback only transfers that pair into the slot.
    let block = unsafe {
        alloc::raw::AssumeInit::try_map(block, ranges, |slot, pair| {
            Ok::<_, alloc::Error>(slot.insert(pair))
        })
    }?;
    Ok(block.into_vec())
}

impl<Data, Ranges, C> Repr<Data, Ranges, C> {
    pub(crate) fn view(&self) -> View<'_, Data, Ranges, C> {
        match self {
            Repr::Padding => View::Padding,
            Repr::Ping => View::Ping,
            Repr::Ack {
                largest,
                delay,
                first_range: first,
                additional_ranges: ranges,
                ..
            } => View::Ack {
                largest: *largest,
                delay: *delay,
                first_range: *first,
                additional_ranges: ranges,
            },
            Repr::Crypto { offset, data, .. } => View::Crypto {
                offset: *offset,
                data,
            },
            Repr::NewToken { token, .. } => View::NewToken { token },
            Repr::Datagram { data } => View::Datagram {
                length: Length::Implicit,
                data,
            },
            Repr::DatagramLen { data, .. } => View::Datagram {
                length: Length::Explicit,
                data,
            },
            Repr::HandshakeDone => View::HandshakeDone,
            Repr::ConnectionClose { code, reason, .. } => View::ConnectionClose {
                code: *code,
                reason,
            },
            Repr::NewConnectionId { notice, retire } => View::NewConnectionId { notice, retire },
            Repr::RetireConnectionId {
                sequence_number: sequence,
            } => View::RetireConnectionId {
                sequence_number: *sequence,
            },
            Repr::PathChallenge { data } => View::PathChallenge { data },
            Repr::PathResponse { data } => View::PathResponse { data },
            Repr::Stream {
                stream_id: id,
                offset,
                boundary,
                length,
                data,
                ..
            } => View::Stream {
                stream_id: *id,
                offset: *offset,
                boundary: *boundary,
                length: *length,
                data,
            },
            Repr::ResetStream {
                stream_id: id,
                error_code: code,
                final_size: final_,
            } => View::ResetStream {
                stream_id: *id,
                error_code: *code,
                final_size: *final_,
            },
            Repr::StopSending {
                stream_id: id,
                error_code: code,
            } => View::StopSending {
                stream_id: *id,
                error_code: *code,
            },
            Repr::MaxData { maximum_data: max } => View::MaxData { maximum_data: *max },
            Repr::MaxStreamData {
                stream_id: id,
                maximum_stream_data: max,
            } => View::MaxStreamData {
                stream_id: *id,
                maximum_stream_data: *max,
            },
            Repr::DataBlocked { maximum_data: max } => View::DataBlocked { maximum_data: *max },
            Repr::StreamDataBlocked {
                stream_id: id,
                maximum_stream_data: max,
            } => View::StreamDataBlocked {
                stream_id: *id,
                maximum_stream_data: *max,
            },
            Repr::MaxStreams {
                direction: dir,
                max_streams: max,
            } => View::MaxStreams {
                direction: *dir,
                max_streams: *max,
            },
            Repr::StreamsBlocked {
                direction: dir,
                max_streams: max,
            } => View::StreamsBlocked {
                direction: *dir,
                max_streams: *max,
            },
        }
    }

    pub(crate) const fn kind(&self) -> frame::Kind {
        match self {
            Self::Padding => frame::Kind::Padding,
            Self::Ping => frame::Kind::Ping,
            Self::Ack { .. } => frame::Kind::Ack,
            Self::Crypto { .. } => frame::Kind::Crypto,
            Self::NewToken { .. } => frame::Kind::NewToken,
            Self::Datagram { .. } | Self::DatagramLen { .. } => frame::Kind::Datagram,
            Self::HandshakeDone => frame::Kind::HandshakeDone,
            Self::ConnectionClose {
                code: close::Code::Transport { .. },
                ..
            } => frame::Kind::TransportClose,
            Self::ConnectionClose {
                code: close::Code::Application(_),
                ..
            } => frame::Kind::ApplicationClose,
            Self::NewConnectionId { .. } => frame::Kind::NewConnectionId,
            Self::RetireConnectionId { .. } => frame::Kind::RetireConnectionId,
            Self::PathChallenge { .. } => frame::Kind::PathChallenge,
            Self::PathResponse { .. } => frame::Kind::PathResponse,
            Self::Stream { .. } => frame::Kind::Stream,
            Self::ResetStream { .. } => frame::Kind::ResetStream,
            Self::StopSending { .. } => frame::Kind::StopSending,
            Self::MaxData { .. } => frame::Kind::MaxData,
            Self::MaxStreamData { .. } => frame::Kind::MaxStreamData,
            Self::DataBlocked { .. } => frame::Kind::DataBlocked,
            Self::StreamDataBlocked { .. } => frame::Kind::StreamDataBlocked,
            Self::MaxStreams { .. } => frame::Kind::MaxStreams,
            Self::StreamsBlocked { .. } => frame::Kind::StreamsBlocked,
        }
    }
}

const _: () = assert!(
    std::mem::size_of::<frame::Frame>()
        == std::mem::size_of::<Repr<Vec<u8>, Vec<(varint::VarInt, varint::VarInt)>, cid::Id>>()
);
const _: () = {
    use frame::ack::ranges;
    use std::{mem, ops};

    assert!(mem::size_of::<usize>() <= mem::size_of::<u64>());
    assert!(mem::size_of::<frame::Frame>() == 64);
    assert!(mem::size_of::<frame::Borrowed<'_>>() == 56);
    assert!(mem::size_of::<frame::Frame<ops::Range<usize>, ranges::Proof<'_>>>() == 56);
};
