use crate::varint;
use crate::varint::VarInt;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Underflow,
    BadVarInt,
    BadType,
}

impl From<varint::Error> for FrameError {
    fn from(_: varint::Error) -> Self {
        Self::BadVarInt
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Padding,
    Ping,
    Ack {
        largest: u64,
        delay: u64,
        first_range: u64,
        additional_ranges: Vec<(u64, u64)>,
    },
    Crypto {
        offset: u64,
        data: Vec<u8>,
    },
    Datagram {
        length_prefixed: bool,
        data: Vec<u8>,
    },
    HandshakeDone,
    ConnectionClose {
        is_application: bool,
        error_code: u64,
        frame_type: u64,
        reason: Vec<u8>,
    },
    NewConnectionId {
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: Vec<u8>,
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
        data: Vec<u8>,
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

impl Frame {
    pub fn encode_stream(
        out: &mut Vec<u8>,
        stream_id: u64,
        offset: u64,
        fin: bool,
        length_prefixed: bool,
        data: &[u8],
    ) {
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
        VarInt::encode(stream_id, out).expect("stream_id varint");
        if offset != 0 {
            VarInt::encode(offset, out).expect("stream offset varint");
        }
        if length_prefixed {
            VarInt::encode(data.len() as u64, out).expect("stream length varint");
        }
        out.extend_from_slice(data);
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
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
                VarInt::encode(*largest, out).expect("ack largest fits in varint");
                VarInt::encode(*delay, out).expect("ack delay fits in varint");
                VarInt::encode(additional_ranges.len() as u64, out).expect("ack range count fits");
                VarInt::encode(*first_range, out).expect("ack first_range fits in varint");
                for (gap, range_len) in additional_ranges {
                    VarInt::encode(*gap, out).expect("ack gap fits");
                    VarInt::encode(*range_len, out).expect("ack range_len fits");
                }
            }
            Self::Crypto { offset, data } => {
                out.push(TYPE_CRYPTO);
                VarInt::encode(*offset, out).expect("crypto offset fits in varint");
                VarInt::encode(data.len() as u64, out).expect("crypto length fits in varint");
                out.extend_from_slice(data);
            }
            Self::Datagram {
                length_prefixed,
                data,
            } => {
                if *length_prefixed {
                    out.push(TYPE_DATAGRAM_LEN);
                    VarInt::encode(data.len() as u64, out).expect("datagram length fits");
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
                VarInt::encode(*sequence_number, out).expect("seq varint");
                VarInt::encode(*retire_prior_to, out).expect("retire varint");
                out.push(connection_id.len() as u8);
                out.extend_from_slice(connection_id);
                out.extend_from_slice(stateless_reset_token);
            }
            Self::RetireConnectionId { sequence_number } => {
                out.push(TYPE_RETIRE_CONNECTION_ID);
                VarInt::encode(*sequence_number, out).expect("seq varint");
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
                Self::encode_stream(out, *stream_id, *offset, *fin, *length_prefixed, data);
            }
            Self::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                out.push(TYPE_RESET_STREAM);
                VarInt::encode(*stream_id, out).expect("stream_id varint");
                VarInt::encode(*error_code, out).expect("error_code varint");
                VarInt::encode(*final_size, out).expect("final_size varint");
            }
            Self::StopSending {
                stream_id,
                error_code,
            } => {
                out.push(TYPE_STOP_SENDING);
                VarInt::encode(*stream_id, out).expect("stream_id varint");
                VarInt::encode(*error_code, out).expect("error_code varint");
            }
            Self::MaxData { maximum_data } => {
                out.push(TYPE_MAX_DATA);
                VarInt::encode(*maximum_data, out).expect("max_data varint");
            }
            Self::MaxStreamData {
                stream_id,
                maximum_stream_data,
            } => {
                out.push(TYPE_MAX_STREAM_DATA);
                VarInt::encode(*stream_id, out).expect("stream_id varint");
                VarInt::encode(*maximum_stream_data, out).expect("max_stream_data varint");
            }
            Self::DataBlocked { maximum_data } => {
                out.push(TYPE_DATA_BLOCKED);
                VarInt::encode(*maximum_data, out).expect("max_data varint");
            }
            Self::StreamDataBlocked {
                stream_id,
                maximum_stream_data,
            } => {
                out.push(TYPE_STREAM_DATA_BLOCKED);
                VarInt::encode(*stream_id, out).expect("stream_id varint");
                VarInt::encode(*maximum_stream_data, out).expect("max_stream_data varint");
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
                VarInt::encode(*max_streams, out).expect("max_streams varint");
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
                VarInt::encode(*max_streams, out).expect("max_streams varint");
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
                VarInt::encode(*error_code, out).expect("error_code varint");
                if !*is_application {
                    VarInt::encode(*frame_type, out).expect("frame_type varint");
                }
                VarInt::encode(reason.len() as u64, out).expect("reason length");
                out.extend_from_slice(reason);
            }
        }
    }

    pub fn decode(input: &[u8]) -> Result<(Self, usize), FrameError> {
        let ty = *input.first().ok_or(FrameError::Underflow)?;
        let mut pos = 1;
        match ty {
            TYPE_PADDING => Ok((Self::Padding, pos)),
            TYPE_PING => Ok((Self::Ping, pos)),
            TYPE_RESET_STREAM => {
                let (stream_id, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let (error_code, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let (final_size, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                Ok((
                    Self::ResetStream {
                        stream_id,
                        error_code,
                        final_size,
                    },
                    pos,
                ))
            }
            TYPE_STOP_SENDING => {
                let (stream_id, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let (error_code, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                Ok((
                    Self::StopSending {
                        stream_id,
                        error_code,
                    },
                    pos,
                ))
            }
            TYPE_MAX_DATA => {
                let (maximum_data, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                Ok((Self::MaxData { maximum_data }, pos))
            }
            TYPE_MAX_STREAM_DATA => {
                let (stream_id, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let (maximum_stream_data, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                Ok((
                    Self::MaxStreamData {
                        stream_id,
                        maximum_stream_data,
                    },
                    pos,
                ))
            }
            TYPE_DATA_BLOCKED => {
                let (maximum_data, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                Ok((Self::DataBlocked { maximum_data }, pos))
            }
            TYPE_STREAM_DATA_BLOCKED => {
                let (stream_id, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let (maximum_stream_data, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                Ok((
                    Self::StreamDataBlocked {
                        stream_id,
                        maximum_stream_data,
                    },
                    pos,
                ))
            }
            TYPE_MAX_STREAMS_BIDI | TYPE_MAX_STREAMS_UNI => {
                let (max_streams, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                Ok((
                    Self::MaxStreams {
                        is_uni: ty == TYPE_MAX_STREAMS_UNI,
                        max_streams,
                    },
                    pos,
                ))
            }
            TYPE_STREAMS_BLOCKED_BIDI | TYPE_STREAMS_BLOCKED_UNI => {
                let (max_streams, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                Ok((
                    Self::StreamsBlocked {
                        is_uni: ty == TYPE_STREAMS_BLOCKED_UNI,
                        max_streams,
                    },
                    pos,
                ))
            }
            t if t & 0xF8 == TYPE_STREAM_BASE => {
                let has_off = t & STREAM_FLAG_OFF != 0;
                let has_len = t & STREAM_FLAG_LEN != 0;
                let fin = t & STREAM_FLAG_FIN != 0;
                let (stream_id, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let offset = if has_off {
                    let (o, n) = VarInt::decode(&input[pos..])?;
                    pos += n;
                    o
                } else {
                    0
                };
                let data = if has_len {
                    let (length, n) = VarInt::decode(&input[pos..])?;
                    pos += n;
                    let length = length as usize;
                    if input.len() < pos + length {
                        return Err(FrameError::Underflow);
                    }
                    let d = input[pos..pos + length].to_vec();
                    pos += length;
                    d
                } else {
                    let d = input[pos..].to_vec();
                    pos = input.len();
                    d
                };
                Ok((
                    Self::Stream {
                        stream_id,
                        offset,
                        fin,
                        length_prefixed: has_len,
                        data,
                    },
                    pos,
                ))
            }
            TYPE_ACK | TYPE_ACK_ECN => {
                let (largest, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let (delay, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let (range_count, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let (first_range, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let remaining = input.len().saturating_sub(pos);
                if range_count > remaining as u64 {
                    return Err(FrameError::Underflow);
                }
                let mut additional_ranges = Vec::with_capacity(range_count as usize);
                for _ in 0..range_count {
                    let (gap, n) = VarInt::decode(&input[pos..])?;
                    pos += n;
                    let (range_len, n) = VarInt::decode(&input[pos..])?;
                    pos += n;
                    additional_ranges.push((gap, range_len));
                }
                if ty == TYPE_ACK_ECN {
                    for _ in 0..3 {
                        let (_, n) = VarInt::decode(&input[pos..])?;
                        pos += n;
                    }
                }
                Ok((
                    Self::Ack {
                        largest,
                        delay,
                        first_range,
                        additional_ranges,
                    },
                    pos,
                ))
            }
            TYPE_CRYPTO => {
                let (offset, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let (length, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let length = length as usize;
                if input.len() < pos + length {
                    return Err(FrameError::Underflow);
                }
                let data = input[pos..pos + length].to_vec();
                pos += length;
                Ok((Self::Crypto { offset, data }, pos))
            }
            TYPE_DATAGRAM => {
                let data = input[pos..].to_vec();
                Ok((
                    Self::Datagram {
                        length_prefixed: false,
                        data,
                    },
                    input.len(),
                ))
            }
            TYPE_DATAGRAM_LEN => {
                let (length, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let length = length as usize;
                if input.len() < pos + length {
                    return Err(FrameError::Underflow);
                }
                let data = input[pos..pos + length].to_vec();
                pos += length;
                Ok((
                    Self::Datagram {
                        length_prefixed: true,
                        data,
                    },
                    pos,
                ))
            }
            TYPE_HANDSHAKE_DONE => Ok((Self::HandshakeDone, pos)),
            TYPE_NEW_CONNECTION_ID => {
                let (sequence_number, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let (retire_prior_to, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                if input.len() <= pos {
                    return Err(FrameError::Underflow);
                }
                let cid_len = input[pos] as usize;
                pos += 1;
                if input.len() < pos + cid_len + 16 {
                    return Err(FrameError::Underflow);
                }
                let connection_id = input[pos..pos + cid_len].to_vec();
                pos += cid_len;
                let mut stateless_reset_token = [0u8; 16];
                stateless_reset_token.copy_from_slice(&input[pos..pos + 16]);
                pos += 16;
                Ok((
                    Self::NewConnectionId {
                        sequence_number,
                        retire_prior_to,
                        connection_id,
                        stateless_reset_token,
                    },
                    pos,
                ))
            }
            TYPE_RETIRE_CONNECTION_ID => {
                let (sequence_number, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                Ok((Self::RetireConnectionId { sequence_number }, pos))
            }
            TYPE_PATH_CHALLENGE | TYPE_PATH_RESPONSE => {
                if input.len() < pos + 8 {
                    return Err(FrameError::Underflow);
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(&input[pos..pos + 8]);
                pos += 8;
                let frame = if ty == TYPE_PATH_CHALLENGE {
                    Self::PathChallenge { data }
                } else {
                    Self::PathResponse { data }
                };
                Ok((frame, pos))
            }
            TYPE_CONNECTION_CLOSE | TYPE_CONNECTION_CLOSE_APP => {
                let is_application = ty == TYPE_CONNECTION_CLOSE_APP;
                let (error_code, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let frame_type = if is_application {
                    0
                } else {
                    let (ft, n) = VarInt::decode(&input[pos..])?;
                    pos += n;
                    ft
                };
                let (reason_len, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let reason_len = reason_len as usize;
                if input.len() < pos + reason_len {
                    return Err(FrameError::Underflow);
                }
                let reason = input[pos..pos + reason_len].to_vec();
                pos += reason_len;
                Ok((
                    Self::ConnectionClose {
                        is_application,
                        error_code,
                        frame_type,
                        reason,
                    },
                    pos,
                ))
            }
            _ => Err(FrameError::BadType),
        }
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
