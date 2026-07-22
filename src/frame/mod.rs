use crate::varint;
use crate::varint::VarInt;

mod decode;

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
    remaining: u64,
}

impl<'a> AckRanges<'a> {
    pub(crate) fn new(input: &'a [u8], remaining: u64) -> Self {
        Self { input, remaining }
    }
}

impl Iterator for AckRanges<'_> {
    type Item = (u64, u64);

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
        let remaining = self.remaining as usize;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for AckRanges<'_> {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<Data = Vec<u8>, Ranges = Vec<(u64, u64)>> {
    Padding,
    Ping,
    Ack {
        largest: u64,
        delay: u64,
        first_range: u64,
        additional_ranges: Ranges,
    },
    Crypto {
        offset: u64,
        data: Data,
    },
    Datagram {
        length_prefixed: bool,
        data: Data,
    },
    HandshakeDone,
    ConnectionClose {
        is_application: bool,
        error_code: u64,
        frame_type: u64,
        reason: Data,
    },
    NewConnectionId {
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: Data,
        stateless_reset_token: [u8; 16],
    },
    RetireConnectionId {
        sequence_number: u64,
    },
    PathChallenge {
        data: [u8; 8],
    },
    PathResponse {
        data: [u8; 8],
    },
    Stream {
        stream_id: u64,
        offset: u64,
        fin: bool,
        length_prefixed: bool,
        data: Data,
    },
    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },
    StopSending {
        stream_id: u64,
        error_code: u64,
    },
    MaxData {
        maximum_data: u64,
    },
    MaxStreamData {
        stream_id: u64,
        maximum_stream_data: u64,
    },
    DataBlocked {
        maximum_data: u64,
    },
    StreamDataBlocked {
        stream_id: u64,
        maximum_stream_data: u64,
    },
    MaxStreams {
        is_uni: bool,
        max_streams: u64,
    },
    StreamsBlocked {
        is_uni: bool,
        max_streams: u64,
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
    pub(crate) fn decode_mapped<'a, Data, Ranges, DataMap, RangeMap>(
        input: &'a [u8],
        data: DataMap,
        ranges: RangeMap,
    ) -> Result<(Frame<Data, Ranges>, usize), FrameError>
    where
        DataMap: Copy + Fn(&'a [u8]) -> Data,
        RangeMap: Fn(&'a [u8], u64) -> Ranges,
    {
        FrameDecoder::new(input, data, ranges).decode()
    }

    pub fn encode_stream(
        out: &mut Vec<u8>,
        stream_id: u64,
        offset: u64,
        fin: bool,
        length_prefixed: bool,
        data: &[u8],
    ) -> Result<(), FrameError> {
        let mut ty = TYPE_STREAM_BASE;
        if offset != 0 {
            ty |= STREAM_FLAG_OFF;
        }
        if length_prefixed {
            ty |= STREAM_FLAG_LEN;
        }
        if fin {
            ty |= STREAM_FLAG_FIN;
        }
        out.push(ty);
        VarInt::encode(stream_id, out)?;
        if offset != 0 {
            VarInt::encode(offset, out)?;
        }
        if length_prefixed {
            VarInt::encode(data.len() as u64, out)?;
        }
        out.extend_from_slice(data);
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
                VarInt::encode(*largest, out)?;
                VarInt::encode(*delay, out)?;
                VarInt::encode(additional_ranges.len() as u64, out)?;
                VarInt::encode(*first_range, out)?;
                for (gap, range_len) in additional_ranges {
                    VarInt::encode(*gap, out)?;
                    VarInt::encode(*range_len, out)?;
                }
            }
            Self::Crypto { offset, data } => {
                out.push(TYPE_CRYPTO);
                VarInt::encode(*offset, out)?;
                VarInt::encode(data.len() as u64, out)?;
                out.extend_from_slice(data);
            }
            Self::Datagram {
                length_prefixed,
                data,
            } => {
                if *length_prefixed {
                    out.push(TYPE_DATAGRAM_LEN);
                    VarInt::encode(data.len() as u64, out)?;
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
                VarInt::encode(*sequence_number, out)?;
                VarInt::encode(*retire_prior_to, out)?;
                out.push(connection_id.len() as u8);
                out.extend_from_slice(connection_id);
                out.extend_from_slice(stateless_reset_token);
            }
            Self::RetireConnectionId { sequence_number } => {
                out.push(TYPE_RETIRE_CONNECTION_ID);
                VarInt::encode(*sequence_number, out)?;
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
                VarInt::encode(*stream_id, out)?;
                VarInt::encode(*error_code, out)?;
                VarInt::encode(*final_size, out)?;
            }
            Self::StopSending {
                stream_id,
                error_code,
            } => {
                out.push(TYPE_STOP_SENDING);
                VarInt::encode(*stream_id, out)?;
                VarInt::encode(*error_code, out)?;
            }
            Self::MaxData { maximum_data } => {
                out.push(TYPE_MAX_DATA);
                VarInt::encode(*maximum_data, out)?;
            }
            Self::MaxStreamData {
                stream_id,
                maximum_stream_data,
            } => {
                out.push(TYPE_MAX_STREAM_DATA);
                VarInt::encode(*stream_id, out)?;
                VarInt::encode(*maximum_stream_data, out)?;
            }
            Self::DataBlocked { maximum_data } => {
                out.push(TYPE_DATA_BLOCKED);
                VarInt::encode(*maximum_data, out)?;
            }
            Self::StreamDataBlocked {
                stream_id,
                maximum_stream_data,
            } => {
                out.push(TYPE_STREAM_DATA_BLOCKED);
                VarInt::encode(*stream_id, out)?;
                VarInt::encode(*maximum_stream_data, out)?;
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
                VarInt::encode(*max_streams, out)?;
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
                VarInt::encode(*max_streams, out)?;
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
                VarInt::encode(*error_code, out)?;
                if !*is_application {
                    VarInt::encode(*frame_type, out)?;
                }
                VarInt::encode(reason.len() as u64, out)?;
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
