use self::{ack::ranges, decode::error};
use crate::wire::{packet::cid, stream, varint};
use o3::{
    alloc::{self, BoxSliceExt as _},
    buffer::write::Sink,
};
use std::convert;

pub mod ack;
mod body;
mod borrowed;
pub mod close;
pub mod decode;
mod kind;
mod repr;
mod view;

pub(crate) use body::Body;

#[derive(Clone, Debug)]
pub struct Projection;
pub use borrowed::Borrowed;
pub(crate) use kind::Kind;
pub(crate) use repr::Repr;
pub use view::View;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Debug)]
pub enum Boundary {
    More,
    End,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Debug)]
pub enum Length {
    Implicit,
    Explicit,
}

pub const TYPE_PADDING: u8 = 0x00;
pub const TYPE_PING: u8 = 0x01;
pub const TYPE_ACK: u8 = 0x02;
pub const TYPE_ACK_ECN: u8 = 0x03;
pub const TYPE_RESET_STREAM: u8 = 0x04;
pub const TYPE_STOP_SENDING: u8 = 0x05;
pub const TYPE_CRYPTO: u8 = 0x06;
pub const TYPE_NEW_TOKEN: u8 = 0x07;
pub const TYPE_STREAM_BASE: u8 = 0x08;
pub const STREAM_FLAG_OFF: u8 = 0x04;
pub const STREAM_FLAG_LEN: u8 = 0x02;
pub const STREAM_FLAG_FIN: u8 = 0x01;
pub const TYPE_MAX_DATA: u8 = 0x10;
pub const TYPE_MAX_STREAM_DATA: u8 = 0x11;
pub const TYPE_MAX_STREAMS_BIDI: u8 = 0x12;
pub const TYPE_MAX_STREAMS_UNI: u8 = 0x13;
pub const TYPE_DATA_BLOCKED: u8 = 0x14;
pub const TYPE_STREAM_DATA_BLOCKED: u8 = 0x15;
pub const TYPE_STREAMS_BLOCKED_BIDI: u8 = 0x16;
pub const TYPE_STREAMS_BLOCKED_UNI: u8 = 0x17;
pub const TYPE_NEW_CONNECTION_ID: u8 = 0x18;
pub const TYPE_RETIRE_CONNECTION_ID: u8 = 0x19;
pub const TYPE_CONNECTION_CLOSE: u8 = 0x1c;
pub const TYPE_CONNECTION_CLOSE_APP: u8 = 0x1d;
pub const TYPE_HANDSHAKE_DONE: u8 = 0x1e;
pub const TYPE_PATH_CHALLENGE: u8 = 0x1a;
pub const TYPE_PATH_RESPONSE: u8 = 0x1b;
pub const TYPE_DATAGRAM: u8 = 0x30;
pub const TYPE_DATAGRAM_LEN: u8 = 0x31;
pub(crate) const MAX_ADDITIONAL_ACK_RANGES: usize = 256;

const _: () = assert!(std::mem::size_of::<Boundary>() == std::mem::size_of::<bool>());
const _: () = assert!(std::mem::align_of::<Boundary>() == std::mem::align_of::<bool>());
const _: () = assert!(std::mem::size_of::<Length>() == std::mem::size_of::<bool>());
const _: () = assert!(std::mem::align_of::<Length>() == std::mem::align_of::<bool>());

/// A structurally and semantically valid QUIC frame.
/// The private representation prevents forging the proof.
/// Backing lifetimes remain in `Data` and `Ranges` without extra storage.
#[repr(transparent)]
#[derive(PartialEq, Eq)]
pub struct Frame<Data = Vec<u8>, Ranges = Vec<(varint::VarInt, varint::VarInt)>, C = cid::Id>(
    Repr<Data, Ranges, C>,
);

pub(crate) struct StreamHead;

impl<Data, Ranges, C> Frame<Data, Ranges, C> {
    pub fn view(&self) -> View<'_, Data, Ranges, C> {
        self.0.view()
    }

    pub(crate) fn into_repr(self) -> Repr<Data, Ranges, C> {
        self.0
    }

    pub(crate) const fn kind(&self) -> Kind {
        self.0.kind()
    }
}

impl Frame {
    pub(crate) fn write_stream<W: Sink>(
        out: &mut W,
        id: stream::Id,
        offset: u64,
        boundary: Boundary,
        length: usize,
    ) -> Result<Option<StreamHead>, W::Error> {
        let (Some(offset), Some(len)) = (
            varint::VarInt::new(offset),
            varint::VarInt::from_usize(length),
        ) else {
            return Ok(None);
        };
        if len.get() > varint::VarInt::MAX - offset.get() {
            return Ok(None);
        }
        Self::write_parts(out, id, offset, boundary, Length::Explicit, len, &[])?;
        Ok(Some(StreamHead))
    }

    fn write_parts<W: Sink>(
        out: &mut W,
        id: stream::Id,
        offset: varint::VarInt,
        boundary: Boundary,
        length: Length,
        len: varint::VarInt,
        data: &[u8],
    ) -> Result<(), W::Error> {
        let mut ty = TYPE_STREAM_BASE;
        let offset = if offset != varint::VarInt::ZERO {
            ty |= STREAM_FLAG_OFF;
            offset.pack()
        } else {
            Default::default()
        };
        let len = if matches!(length, Length::Explicit) {
            ty |= STREAM_FLAG_LEN;
            len.pack()
        } else {
            Default::default()
        };
        if matches!(boundary, Boundary::End) {
            ty |= STREAM_FLAG_FIN;
        }
        out.write_slices([
            &[ty],
            id.varint().pack().as_ref(),
            offset.as_ref(),
            len.as_ref(),
            data,
        ])
    }
}

impl<Data: AsRef<[u8]>, Ranges: ack::Storage, C: AsRef<[u8]>> Frame<Data, Ranges, C> {
    /// Encodes a frame whose constructor or decoder proved its structure.
    /// Each fixed frame is one complete sink write; ACK ranges follow the
    /// header and may leave a written prefix on failure.
    pub fn encode<W: Sink>(&self, out: &mut W) -> Result<(), W::Error> {
        match &self.0 {
            Repr::Padding => out.write_byte(TYPE_PADDING),
            Repr::Ping => out.write_byte(TYPE_PING),
            Repr::Ack {
                largest,
                delay,
                first_range: first,
                count,
                additional_ranges: ranges,
            } => {
                out.write_slices([
                    &[TYPE_ACK],
                    largest.pack().as_ref(),
                    delay.pack().as_ref(),
                    varint::VarInt::from_u16(*count).pack().as_ref(),
                    first.pack().as_ref(),
                ])?;
                ranges.encode_pairs(out)
            }
            Repr::Crypto { offset, len, data } => out.write_slices([
                &[TYPE_CRYPTO],
                offset.pack().as_ref(),
                len.pack().as_ref(),
                data.as_ref(),
            ]),
            Repr::NewToken { len, token } => {
                out.write_slices([&[TYPE_NEW_TOKEN], len.pack().as_ref(), token.as_ref()])
            }
            Repr::Datagram { data } => out.write_slices([&[TYPE_DATAGRAM], data.as_ref()]),
            Repr::DatagramLen { len, data } => {
                out.write_slices([&[TYPE_DATAGRAM_LEN], len.pack().as_ref(), data.as_ref()])
            }
            Repr::HandshakeDone => out.write_byte(TYPE_HANDSHAKE_DONE),
            Repr::NewConnectionId { notice, retire } => notice.encode(out, *retire),
            Repr::RetireConnectionId {
                sequence_number: sequence,
            } => out.write_slices([&[TYPE_RETIRE_CONNECTION_ID], sequence.pack().as_ref()]),
            Repr::PathChallenge { data } => out.write_slices([&[TYPE_PATH_CHALLENGE], data]),
            Repr::PathResponse { data } => out.write_slices([&[TYPE_PATH_RESPONSE], data]),
            Repr::Stream {
                stream_id: id,
                offset,
                boundary,
                length,
                len,
                data,
            } => Frame::write_parts(out, *id, *offset, *boundary, *length, *len, data.as_ref()),
            Repr::ResetStream {
                stream_id: id,
                error_code: code,
                final_size: final_,
            } => out.write_slices([
                &[TYPE_RESET_STREAM],
                id.varint().pack().as_ref(),
                code.as_varint().pack().as_ref(),
                final_.pack().as_ref(),
            ]),
            Repr::StopSending {
                stream_id: id,
                error_code: code,
            } => out.write_slices([
                &[TYPE_STOP_SENDING],
                id.varint().pack().as_ref(),
                code.as_varint().pack().as_ref(),
            ]),
            Repr::MaxData { maximum_data: max } => {
                out.write_slices([&[TYPE_MAX_DATA], max.pack().as_ref()])
            }
            Repr::MaxStreamData {
                stream_id: id,
                maximum_stream_data: max,
            } => out.write_slices([
                &[TYPE_MAX_STREAM_DATA],
                id.varint().pack().as_ref(),
                max.pack().as_ref(),
            ]),
            Repr::DataBlocked { maximum_data: max } => {
                out.write_slices([&[TYPE_DATA_BLOCKED], max.pack().as_ref()])
            }
            Repr::StreamDataBlocked {
                stream_id: id,
                maximum_stream_data: max,
            } => out.write_slices([
                &[TYPE_STREAM_DATA_BLOCKED],
                id.varint().pack().as_ref(),
                max.pack().as_ref(),
            ]),
            Repr::MaxStreams {
                direction: dir,
                max_streams: max,
            } => out.write_slices([
                &[match dir {
                    stream::Direction::Bidi => TYPE_MAX_STREAMS_BIDI,
                    stream::Direction::Uni => TYPE_MAX_STREAMS_UNI,
                }],
                max.pack().as_ref(),
            ]),
            Repr::StreamsBlocked {
                direction: dir,
                max_streams: max,
            } => out.write_slices([
                &[match dir {
                    stream::Direction::Bidi => TYPE_STREAMS_BLOCKED_BIDI,
                    stream::Direction::Uni => TYPE_STREAMS_BLOCKED_UNI,
                }],
                max.pack().as_ref(),
            ]),
            Repr::ConnectionClose { code, len, reason } => {
                let (ty, code, kind) = match code {
                    close::Code::Application(code) => (
                        TYPE_CONNECTION_CLOSE_APP,
                        code.as_varint().pack(),
                        Default::default(),
                    ),
                    close::Code::Transport {
                        error_code: code,
                        frame_type: kind,
                    } => (TYPE_CONNECTION_CLOSE, code.pack(), kind.pack()),
                };
                out.write_slices([
                    &[ty],
                    code.as_ref(),
                    kind.as_ref(),
                    len.pack().as_ref(),
                    reason.as_ref(),
                ])
            }
        }
    }
}

impl Frame {
    fn read<'wire>(input: &mut &'wire [u8]) -> Result<decode::Decoded<Self>, error::Error> {
        decode::Decoder::new(
            |data| Box::<[u8]>::try_copy(data).map_err(alloc::Error::from),
            |proof: ranges::Validated<'wire>| repr::try_ranges(proof.into_ranges()),
            decode::Notice::into_owned,
        )
        .decode::<_, _, _, _, _, error::Error>(input)
    }

    pub fn decode(mut input: &[u8]) -> Result<(Self, usize), error::Error> {
        let (frame, used) = Self::read(&mut input)?;
        Ok((frame, used.get()))
    }

    pub fn decode_all(mut input: &[u8]) -> Result<Vec<Self>, error::Error> {
        let mut out = Vec::new();
        while !input.is_empty() {
            let (f, _) = Self::read(&mut input)?;
            if !matches!(f.view(), View::Padding) {
                alloc::Vacant::try_new(&mut out)?.insert(f);
            }
        }
        Ok(out)
    }
}

impl<'a> Frame<&'a [u8], ranges::Set<'a>, cid::Ref<'a>> {
    pub fn decode_ref(mut input: &'a [u8]) -> Result<(Self, usize), error::Fault> {
        let (frame, used) = decode::Decoder::new(
            Ok::<_, error::Fault>,
            |proof: ranges::Validated<'a>| Ok(proof.into_ranges()),
            convert::identity,
        )
        .decode::<_, _, _, _, _, error::Fault>(&mut input)?;
        Ok((frame, used.get()))
    }
}

const _: () = assert!(std::mem::size_of::<usize>() <= std::mem::size_of::<u64>());
