use crate::varint;
use crate::varint::VarInt;

pub(crate) mod decode;

use decode::FrameDecoder;

pub const TYPE_PADDING: u8 = 0x00;
pub const TYPE_PING: u8 = 0x01;
pub const TYPE_ACK: u8 = 0x02;
pub const TYPE_ACK_ECN: u8 = 0x03;
pub const TYPE_RESET_STREAM: u8 = 0x04;
pub const TYPE_STOP_SENDING: u8 = 0x05;
pub const TYPE_CRYPTO: u8 = 0x06;
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
pub(crate) const MAX_ACK_RANGES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Underflow,
    BadVarInt,
    BadType,
    InvalidAckRange,
}

impl_error!(FrameError {
    Self::Underflow => "truncated frame",
    Self::BadVarInt => "invalid frame integer",
    Self::BadType => "invalid frame type",
    Self::InvalidAckRange => "invalid ACK range",
});

impl From<varint::Error> for FrameError {
    fn from(_: varint::Error) -> Self {
        Self::BadVarInt
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRanges<'a> {
    input: &'a [u8],
    remaining: usize,
}

impl<'a> AckRanges<'a> {
    pub(crate) fn new(input: &'a [u8], remaining: usize) -> Self {
        Self { input, remaining }
    }
}

impl Iterator for AckRanges<'_> {
    type Item = (VarInt, VarInt);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let Ok((gap, gap_len)) = VarInt::decode(self.input) else {
            self.remaining = 0;
            return None;
        };
        let input = &self.input[gap_len..];
        let Ok((range, range_len)) = VarInt::decode(input) else {
            self.remaining = 0;
            return None;
        };
        self.input = &input[range_len..];
        self.remaining -= 1;
        Some((gap, range))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for AckRanges<'_> {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<Data = Vec<u8>, Ranges = Vec<(VarInt, VarInt)>> {
    Padding,
    Ping,
    Ack {
        largest: VarInt,
        delay: VarInt,
        first_range: VarInt,
        additional_ranges: Ranges,
    },
    Crypto {
        offset: VarInt,
        data: Data,
    },
    Datagram {
        length_prefixed: bool,
        data: Data,
    },
    HandshakeDone,
    ConnectionClose {
        is_application: bool,
        error_code: VarInt,
        frame_type: VarInt,
        reason: Data,
    },
    NewConnectionId {
        sequence_number: VarInt,
        retire_prior_to: VarInt,
        connection_id: Data,
        stateless_reset_token: [u8; 16],
    },
    RetireConnectionId {
        sequence_number: VarInt,
    },
    PathChallenge {
        data: [u8; 8],
    },
    PathResponse {
        data: [u8; 8],
    },
    Stream {
        stream_id: VarInt,
        offset: VarInt,
        fin: bool,
        length_prefixed: bool,
        data: Data,
    },
    ResetStream {
        stream_id: VarInt,
        error_code: VarInt,
        final_size: VarInt,
    },
    StopSending {
        stream_id: VarInt,
        error_code: VarInt,
    },
    MaxData {
        maximum_data: VarInt,
    },
    MaxStreamData {
        stream_id: VarInt,
        maximum_stream_data: VarInt,
    },
    DataBlocked {
        maximum_data: VarInt,
    },
    StreamDataBlocked {
        stream_id: VarInt,
        maximum_stream_data: VarInt,
    },
    MaxStreams {
        is_uni: bool,
        max_streams: VarInt,
    },
    StreamsBlocked {
        is_uni: bool,
        max_streams: VarInt,
    },
}

impl<Data, Ranges> Frame<Data, Ranges> {
    pub(crate) fn map<MappedData, MappedRanges>(
        self,
        map_data: impl Copy + Fn(Data) -> MappedData,
        map_ranges: impl FnOnce(Ranges) -> MappedRanges,
    ) -> Frame<MappedData, MappedRanges> {
        match self {
            Self::Padding => Frame::Padding,
            Self::Ping => Frame::Ping,
            Self::Ack {
                largest,
                delay,
                first_range,
                additional_ranges,
            } => Frame::Ack {
                largest,
                delay,
                first_range,
                additional_ranges: map_ranges(additional_ranges),
            },
            Self::Crypto { offset, data } => Frame::Crypto {
                offset,
                data: map_data(data),
            },
            Self::Datagram {
                length_prefixed,
                data,
            } => Frame::Datagram {
                length_prefixed,
                data: map_data(data),
            },
            Self::HandshakeDone => Frame::HandshakeDone,
            Self::ConnectionClose {
                is_application,
                error_code,
                frame_type,
                reason,
            } => Frame::ConnectionClose {
                is_application,
                error_code,
                frame_type,
                reason: map_data(reason),
            },
            Self::NewConnectionId {
                sequence_number,
                retire_prior_to,
                connection_id,
                stateless_reset_token,
            } => Frame::NewConnectionId {
                sequence_number,
                retire_prior_to,
                connection_id: map_data(connection_id),
                stateless_reset_token,
            },
            Self::RetireConnectionId { sequence_number } => {
                Frame::RetireConnectionId { sequence_number }
            }
            Self::PathChallenge { data } => Frame::PathChallenge { data },
            Self::PathResponse { data } => Frame::PathResponse { data },
            Self::Stream {
                stream_id,
                offset,
                fin,
                length_prefixed,
                data,
            } => Frame::Stream {
                stream_id,
                offset,
                fin,
                length_prefixed,
                data: map_data(data),
            },
            Self::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            },
            Self::StopSending {
                stream_id,
                error_code,
            } => Frame::StopSending {
                stream_id,
                error_code,
            },
            Self::MaxData { maximum_data } => Frame::MaxData { maximum_data },
            Self::MaxStreamData {
                stream_id,
                maximum_stream_data,
            } => Frame::MaxStreamData {
                stream_id,
                maximum_stream_data,
            },
            Self::DataBlocked { maximum_data } => Frame::DataBlocked { maximum_data },
            Self::StreamDataBlocked {
                stream_id,
                maximum_stream_data,
            } => Frame::StreamDataBlocked {
                stream_id,
                maximum_stream_data,
            },
            Self::MaxStreams {
                is_uni,
                max_streams,
            } => Frame::MaxStreams {
                is_uni,
                max_streams,
            },
            Self::StreamsBlocked {
                is_uni,
                max_streams,
            } => Frame::StreamsBlocked {
                is_uni,
                max_streams,
            },
        }
    }
}

impl Frame {
    pub fn encode_stream(
        out: &mut Vec<u8>,
        stream_id: VarInt,
        offset: VarInt,
        fin: bool,
        length_prefixed: bool,
        data: &[u8],
    ) -> Result<(), FrameError> {
        Self::encode_stream_header(
            out,
            stream_id,
            offset,
            fin,
            length_prefixed.then_some(data.len()),
        )?;
        out.extend_from_slice(data);
        Ok(())
    }

    pub fn encode_stream_header(
        out: &mut Vec<u8>,
        stream_id: VarInt,
        offset: VarInt,
        fin: bool,
        length: Option<usize>,
    ) -> Result<(), FrameError> {
        let mut ty = TYPE_STREAM_BASE;
        if offset != VarInt::ZERO {
            ty |= STREAM_FLAG_OFF;
        }
        if length.is_some() {
            ty |= STREAM_FLAG_LEN;
        }
        if fin {
            ty |= STREAM_FLAG_FIN;
        }
        out.push(ty);
        stream_id.encode(out);
        if offset != VarInt::ZERO {
            offset.encode(out);
        }
        if let Some(length) = length {
            VarInt::from_usize(length)
                .ok_or(FrameError::BadVarInt)?
                .encode(out);
        }
        Ok(())
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        match self {
            Self::Padding => out.push(TYPE_PADDING),
            Self::Ping => out.push(TYPE_PING),
            Self::Ack {
                largest,
                delay,
                first_range,
                additional_ranges,
            } => {
                out.push(TYPE_ACK);
                largest.encode(out);
                delay.encode(out);
                VarInt::from_usize(additional_ranges.len())
                    .ok_or(FrameError::BadVarInt)?
                    .encode(out);
                first_range.encode(out);
                for (gap, range_len) in additional_ranges {
                    gap.encode(out);
                    range_len.encode(out);
                }
            }
            Self::Crypto { offset, data } => {
                out.push(TYPE_CRYPTO);
                offset.encode(out);
                VarInt::from_usize(data.len())
                    .ok_or(FrameError::BadVarInt)?
                    .encode(out);
                out.extend_from_slice(data);
            }
            Self::Datagram {
                length_prefixed,
                data,
            } => {
                if *length_prefixed {
                    out.push(TYPE_DATAGRAM_LEN);
                    VarInt::from_usize(data.len())
                        .ok_or(FrameError::BadVarInt)?
                        .encode(out);
                    out.extend_from_slice(data);
                } else {
                    out.push(TYPE_DATAGRAM);
                    out.extend_from_slice(data);
                }
            }
            Self::HandshakeDone => out.push(TYPE_HANDSHAKE_DONE),
            Self::NewConnectionId {
                sequence_number,
                retire_prior_to,
                connection_id,
                stateless_reset_token,
            } => {
                out.push(TYPE_NEW_CONNECTION_ID);
                sequence_number.encode(out);
                retire_prior_to.encode(out);
                out.push(connection_id.len() as u8);
                out.extend_from_slice(connection_id);
                out.extend_from_slice(stateless_reset_token);
            }
            Self::RetireConnectionId { sequence_number } => {
                out.push(TYPE_RETIRE_CONNECTION_ID);
                sequence_number.encode(out);
            }
            Self::PathChallenge { data } => {
                out.push(TYPE_PATH_CHALLENGE);
                out.extend_from_slice(data);
            }
            Self::PathResponse { data } => {
                out.push(TYPE_PATH_RESPONSE);
                out.extend_from_slice(data);
            }
            Self::Stream {
                stream_id,
                offset,
                fin,
                length_prefixed,
                data,
            } => {
                Self::encode_stream(out, *stream_id, *offset, *fin, *length_prefixed, data)?;
            }
            Self::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                out.push(TYPE_RESET_STREAM);
                stream_id.encode(out);
                error_code.encode(out);
                final_size.encode(out);
            }
            Self::StopSending {
                stream_id,
                error_code,
            } => {
                out.push(TYPE_STOP_SENDING);
                stream_id.encode(out);
                error_code.encode(out);
            }
            Self::MaxData { maximum_data } => {
                out.push(TYPE_MAX_DATA);
                maximum_data.encode(out);
            }
            Self::MaxStreamData {
                stream_id,
                maximum_stream_data,
            } => {
                out.push(TYPE_MAX_STREAM_DATA);
                stream_id.encode(out);
                maximum_stream_data.encode(out);
            }
            Self::DataBlocked { maximum_data } => {
                out.push(TYPE_DATA_BLOCKED);
                maximum_data.encode(out);
            }
            Self::StreamDataBlocked {
                stream_id,
                maximum_stream_data,
            } => {
                out.push(TYPE_STREAM_DATA_BLOCKED);
                stream_id.encode(out);
                maximum_stream_data.encode(out);
            }
            Self::MaxStreams {
                is_uni,
                max_streams,
            } => {
                out.push(if *is_uni {
                    TYPE_MAX_STREAMS_UNI
                } else {
                    TYPE_MAX_STREAMS_BIDI
                });
                max_streams.encode(out);
            }
            Self::StreamsBlocked {
                is_uni,
                max_streams,
            } => {
                out.push(if *is_uni {
                    TYPE_STREAMS_BLOCKED_UNI
                } else {
                    TYPE_STREAMS_BLOCKED_BIDI
                });
                max_streams.encode(out);
            }
            Self::ConnectionClose {
                is_application,
                error_code,
                frame_type,
                reason,
            } => {
                out.push(if *is_application {
                    TYPE_CONNECTION_CLOSE_APP
                } else {
                    TYPE_CONNECTION_CLOSE
                });
                error_code.encode(out);
                if !*is_application {
                    frame_type.encode(out);
                }
                VarInt::from_usize(reason.len())
                    .ok_or(FrameError::BadVarInt)?
                    .encode(out);
                out.extend_from_slice(reason);
            }
        }
        Ok(())
    }
}

impl Frame {
    pub fn decode(input: &[u8]) -> Result<(Self, usize), FrameError> {
        FrameDecoder::new(input, <[u8]>::to_vec, |input, count| {
            AckRanges::new(input, count).collect()
        })
        .decode()
    }

    pub fn decode_all(mut input: &[u8]) -> Result<Vec<Self>, FrameError> {
        let mut out = Vec::new();
        while !input.is_empty() {
            let (f, n) = Self::decode(input)?;
            input = &input[n..];
            if !matches!(f, Self::Padding) {
                out.push(f);
            }
        }
        Ok(out)
    }
}

impl<'a> Frame<&'a [u8], AckRanges<'a>> {
    pub fn decode_ref(input: &'a [u8]) -> Result<(Self, usize), FrameError> {
        FrameDecoder::new(input, |input| input, AckRanges::new).decode()
    }
}
