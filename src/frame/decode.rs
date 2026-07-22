use super::*;

fn data_end(input: &[u8], pos: usize, length: u64) -> Result<usize, FrameError> {
    let length = usize::try_from(length).map_err(|_| FrameError::Underflow)?;
    pos.checked_add(length)
        .filter(|&end| end <= input.len())
        .ok_or(FrameError::Underflow)
}

pub(super) struct FrameDecoder<'a, DataMap, RangeMap> {
    input: &'a [u8],
    data: DataMap,
    ranges: RangeMap,
}

impl<'a, DataMap, RangeMap> FrameDecoder<'a, DataMap, RangeMap> {
    pub(super) fn new(input: &'a [u8], data: DataMap, ranges: RangeMap) -> Self {
        Self {
            input,
            data,
            ranges,
        }
    }

    pub(super) fn decode<Data, Ranges>(self) -> Result<(Frame<Data, Ranges>, usize), FrameError>
    where
        DataMap: Copy + Fn(&'a [u8]) -> Data,
        RangeMap: Fn(&'a [u8], u64) -> Ranges,
    {
        let Self {
            input,
            data,
            ranges,
        } = self;
        let ty = *input.first().ok_or(FrameError::Underflow)?;
        let mut pos = 1;
        match ty {
            TYPE_PADDING => Ok((Frame::Padding, pos)),
            TYPE_PING => Ok((Frame::Ping, pos)),
            TYPE_RESET_STREAM => {
                let (stream_id, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let (error_code, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let (final_size, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                Ok((
                    Frame::ResetStream {
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
                    Frame::StopSending {
                        stream_id,
                        error_code,
                    },
                    pos,
                ))
            }
            TYPE_MAX_DATA => {
                let (maximum_data, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                Ok((Frame::MaxData { maximum_data }, pos))
            }
            TYPE_MAX_STREAM_DATA => {
                let (stream_id, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let (maximum_stream_data, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                Ok((
                    Frame::MaxStreamData {
                        stream_id,
                        maximum_stream_data,
                    },
                    pos,
                ))
            }
            TYPE_DATA_BLOCKED => {
                let (maximum_data, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                Ok((Frame::DataBlocked { maximum_data }, pos))
            }
            TYPE_STREAM_DATA_BLOCKED => {
                let (stream_id, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let (maximum_stream_data, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                Ok((
                    Frame::StreamDataBlocked {
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
                    Frame::MaxStreams {
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
                    Frame::StreamsBlocked {
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
                    let end = data_end(input, pos, length)?;
                    let d = data(&input[pos..end]);
                    pos = end;
                    d
                } else {
                    let d = data(&input[pos..]);
                    pos = input.len();
                    d
                };
                Ok((
                    Frame::Stream {
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
                if range_count > MAX_ACK_RANGES as u64 {
                    return Err(FrameError::InvalidAckRange);
                }
                let (first_range, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let mut previous_smallest = largest
                    .checked_sub(first_range)
                    .ok_or(FrameError::InvalidAckRange)?;
                let remaining = input.len().saturating_sub(pos);
                if range_count > remaining as u64 {
                    return Err(FrameError::Underflow);
                }
                let ranges_start = pos;
                for _ in 0..range_count {
                    let (gap, n) = VarInt::decode(&input[pos..])?;
                    pos += n;
                    let (range_len, n) = VarInt::decode(&input[pos..])?;
                    pos += n;
                    let skip = gap.checked_add(2).ok_or(FrameError::InvalidAckRange)?;
                    let next_largest = previous_smallest
                        .checked_sub(skip)
                        .ok_or(FrameError::InvalidAckRange)?;
                    previous_smallest = next_largest
                        .checked_sub(range_len)
                        .ok_or(FrameError::InvalidAckRange)?;
                }
                let additional_ranges = ranges(&input[ranges_start..pos], range_count);
                if ty == TYPE_ACK_ECN {
                    for _ in 0..3 {
                        let (_, n) = VarInt::decode(&input[pos..])?;
                        pos += n;
                    }
                }
                Ok((
                    Frame::Ack {
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
                let end = data_end(input, pos, length)?;
                let data = data(&input[pos..end]);
                pos = end;
                Ok((Frame::Crypto { offset, data }, pos))
            }
            TYPE_DATAGRAM => {
                let data = data(&input[pos..]);
                Ok((
                    Frame::Datagram {
                        length_prefixed: false,
                        data,
                    },
                    input.len(),
                ))
            }
            TYPE_DATAGRAM_LEN => {
                let (length, n) = VarInt::decode(&input[pos..])?;
                pos += n;
                let end = data_end(input, pos, length)?;
                let data = data(&input[pos..end]);
                pos = end;
                Ok((
                    Frame::Datagram {
                        length_prefixed: true,
                        data,
                    },
                    pos,
                ))
            }
            TYPE_HANDSHAKE_DONE => Ok((Frame::HandshakeDone, pos)),
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
                let connection_id = data(&input[pos..pos + cid_len]);
                pos += cid_len;
                let mut stateless_reset_token = [0u8; 16];
                stateless_reset_token.copy_from_slice(&input[pos..pos + 16]);
                pos += 16;
                Ok((
                    Frame::NewConnectionId {
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
                Ok((Frame::RetireConnectionId { sequence_number }, pos))
            }
            TYPE_PATH_CHALLENGE | TYPE_PATH_RESPONSE => {
                if input.len() < pos + 8 {
                    return Err(FrameError::Underflow);
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(&input[pos..pos + 8]);
                pos += 8;
                let frame = if ty == TYPE_PATH_CHALLENGE {
                    Frame::PathChallenge { data }
                } else {
                    Frame::PathResponse { data }
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
                let end = data_end(input, pos, reason_len)?;
                let reason = data(&input[pos..end]);
                pos = end;
                Ok((
                    Frame::ConnectionClose {
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
}
