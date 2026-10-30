use crate::wire::frame::decode;
use crate::wire::frame::{self, close};
use crate::{
    errors,
    wire::{stream, varint},
};

/// Borrow-only observation; only [`crate::wire::frame::Frame`] carries validation auth.
#[derive(Clone, Copy)]
pub enum View<'frame, Data, Ranges, C> {
    Padding,
    Ping,
    Ack {
        largest: varint::VarInt,
        delay: varint::VarInt,
        first_range: varint::VarInt,
        additional_ranges: &'frame Ranges,
    },
    Crypto {
        offset: varint::VarInt,
        data: &'frame Data,
    },
    NewToken {
        token: &'frame Data,
    },
    Datagram {
        length: frame::Length,
        data: &'frame Data,
    },
    HandshakeDone,
    ConnectionClose {
        code: close::Code,
        reason: &'frame Data,
    },
    NewConnectionId {
        notice: &'frame decode::Notice<C>,
        retire: &'frame decode::Retire,
    },
    RetireConnectionId {
        sequence_number: varint::VarInt,
    },
    PathChallenge {
        data: &'frame [u8; 8],
    },
    PathResponse {
        data: &'frame [u8; 8],
    },
    Stream {
        stream_id: stream::Id,
        offset: varint::VarInt,
        boundary: frame::Boundary,
        length: frame::Length,
        data: &'frame Data,
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
