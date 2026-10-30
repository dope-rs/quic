use std::num::NonZero;

use crate::wire::{frame, packet::cid, stream, varint};
use cursor::Cursor;
use frame::{ack::ranges, close};

mod cursor;
pub mod error;
mod notice;
mod retire;

pub use notice::Notice;
pub use retire::Retire;

pub(crate) type Decoded<F> = (F, NonZero<usize>);

pub(crate) struct Decoder<DataMap, RangeMap, CidMap> {
    data: DataMap,
    ranges: RangeMap,
    cids: CidMap,
}

impl<DataMap, RangeMap, CidMap> Decoder<DataMap, RangeMap, CidMap> {
    pub(crate) fn new(data: DataMap, ranges: RangeMap, cids: CidMap) -> Self {
        Self { data, ranges, cids }
    }

    pub(crate) fn decode<'a, Data, Ranges, C, P, M, E>(
        self,
        input: &mut &'a [u8],
    ) -> Result<Decoded<frame::Frame<Data, Ranges, C>>, E>
    where
        Data: From<P>,
        DataMap: Copy + Fn(&'a [u8]) -> Result<P, M>,
        RangeMap: Fn(ranges::Validated<'a>) -> Result<Ranges, M>,
        CidMap: Fn(Notice<cid::Ref<'a>>) -> Notice<C>,
        E: From<error::Fault> + From<M>,
    {
        let Self { data, ranges, cids } = self;
        let (ty, mut cursor) = Cursor::new(input)?;
        let decoded = match ty {
            frame::TYPE_PADDING => Ok(frame::Repr::Padding),
            frame::TYPE_PING => Ok(frame::Repr::Ping),
            frame::TYPE_RESET_STREAM => {
                let id = cursor.id()?;
                let code = cursor.varint()?;
                let size = cursor.varint()?;
                Ok(frame::Repr::ResetStream {
                    stream_id: id,
                    error_code: code.into(),
                    final_size: size,
                })
            }
            frame::TYPE_STOP_SENDING => {
                let id = cursor.id()?;
                let code = cursor.varint()?;
                Ok(frame::Repr::StopSending {
                    stream_id: id,
                    error_code: code.into(),
                })
            }
            frame::TYPE_MAX_DATA => {
                let max = cursor.varint()?;
                Ok(frame::Repr::MaxData { maximum_data: max })
            }
            frame::TYPE_MAX_STREAM_DATA => {
                let id = cursor.id()?;
                let max = cursor.varint()?;
                Ok(frame::Repr::MaxStreamData {
                    stream_id: id,
                    maximum_stream_data: max,
                })
            }
            frame::TYPE_DATA_BLOCKED => {
                let max = cursor.varint()?;
                Ok(frame::Repr::DataBlocked { maximum_data: max })
            }
            frame::TYPE_STREAM_DATA_BLOCKED => {
                let id = cursor.id()?;
                let max = cursor.varint()?;
                Ok(frame::Repr::StreamDataBlocked {
                    stream_id: id,
                    maximum_stream_data: max,
                })
            }
            frame::TYPE_MAX_STREAMS_BIDI | frame::TYPE_MAX_STREAMS_UNI => {
                let max = cursor.count()?;
                Ok(frame::Repr::MaxStreams {
                    direction: if ty == frame::TYPE_MAX_STREAMS_UNI {
                        stream::Direction::Uni
                    } else {
                        stream::Direction::Bidi
                    },
                    max_streams: max,
                })
            }
            frame::TYPE_STREAMS_BLOCKED_BIDI | frame::TYPE_STREAMS_BLOCKED_UNI => {
                let max = cursor.count()?;
                Ok(frame::Repr::StreamsBlocked {
                    direction: if ty == frame::TYPE_STREAMS_BLOCKED_UNI {
                        stream::Direction::Uni
                    } else {
                        stream::Direction::Bidi
                    },
                    max_streams: max,
                })
            }
            t if t & 0xF8 == frame::TYPE_STREAM_BASE => {
                let has_off = t & frame::STREAM_FLAG_OFF != 0;
                let length = if t & frame::STREAM_FLAG_LEN == 0 {
                    frame::Length::Implicit
                } else {
                    frame::Length::Explicit
                };
                let boundary = if t & frame::STREAM_FLAG_FIN == 0 {
                    frame::Boundary::More
                } else {
                    frame::Boundary::End
                };
                let id = cursor.id()?;
                let offset = if has_off {
                    cursor.varint()?
                } else {
                    varint::VarInt::ZERO
                };
                let (bytes, len) = match length {
                    frame::Length::Explicit => {
                        let length = cursor.varint()?;
                        let bytes = cursor.data(length)?;
                        (bytes, length)
                    }
                    frame::Length::Implicit => {
                        let bytes = cursor.tail();
                        let len = varint::VarInt::from_usize(bytes.len()).ok_or(
                            error::Fault::InvalidLength {
                                offset: offset.get(),
                                length: bytes.len() as u64,
                            },
                        )?;
                        (bytes, len)
                    }
                };
                error::Fault::check_span(offset, len)?;
                let data = Data::from(data(bytes)?);
                Ok(frame::Repr::Stream {
                    stream_id: id,
                    offset,
                    boundary,
                    length,
                    len,
                    data,
                })
            }
            frame::TYPE_ACK | frame::TYPE_ACK_ECN => {
                let largest = cursor.varint()?;
                let delay = cursor.varint()?;
                let count = cursor.varint()?;
                let first = cursor.varint()?;
                let valid = cursor.ranges(count, largest, first)?;
                let count = valid.count();
                let rest = ranges(valid)?;
                if ty == frame::TYPE_ACK_ECN {
                    for _ in 0..3 {
                        cursor.skip()?;
                    }
                }
                Ok(frame::Repr::Ack {
                    largest,
                    delay,
                    first_range: first,
                    count,
                    additional_ranges: rest,
                })
            }
            frame::TYPE_CRYPTO => {
                let offset = cursor.varint()?;
                let length = cursor.varint()?;
                let bytes = cursor.data(length)?;
                error::Fault::check_span(offset, length)?;
                let data = Data::from(data(bytes)?);
                Ok(frame::Repr::Crypto {
                    offset,
                    len: length,
                    data,
                })
            }
            frame::TYPE_NEW_TOKEN => {
                let length = cursor.varint()?;
                let bytes = cursor.data(length)?;
                if length.get() == 0 {
                    return Err(error::Fault::InvalidToken { length: 0 }.into());
                }
                let token = Data::from(data(bytes)?);
                Ok(frame::Repr::NewToken { len: length, token })
            }
            frame::TYPE_DATAGRAM => {
                let bytes = cursor.tail();
                let data = Data::from(data(bytes)?);
                Ok(frame::Repr::Datagram { data })
            }
            frame::TYPE_DATAGRAM_LEN => {
                let length = cursor.varint()?;
                let bytes = cursor.data(length)?;
                let data = Data::from(data(bytes)?);
                Ok(frame::Repr::DatagramLen { len: length, data })
            }
            frame::TYPE_HANDSHAKE_DONE => Ok(frame::Repr::HandshakeDone),
            frame::TYPE_NEW_CONNECTION_ID => {
                let seq = cursor.varint()?;
                let retire = cursor.varint()?;
                let (value, retire) = Notice::decode(&mut cursor, seq, retire)?;
                Ok(frame::Repr::NewConnectionId {
                    notice: cids(value),
                    retire,
                })
            }
            frame::TYPE_RETIRE_CONNECTION_ID => {
                let seq = cursor.varint()?;
                Ok(frame::Repr::RetireConnectionId {
                    sequence_number: seq,
                })
            }
            frame::TYPE_PATH_CHALLENGE | frame::TYPE_PATH_RESPONSE => {
                let data = *cursor.array::<8>()?;
                let frame = if ty == frame::TYPE_PATH_CHALLENGE {
                    frame::Repr::PathChallenge { data }
                } else {
                    frame::Repr::PathResponse { data }
                };
                Ok(frame)
            }
            frame::TYPE_CONNECTION_CLOSE | frame::TYPE_CONNECTION_CLOSE_APP => {
                let app = ty == frame::TYPE_CONNECTION_CLOSE_APP;
                let wire = cursor.varint()?;
                let code = if app {
                    close::Code::Application(wire.into())
                } else {
                    let ft = cursor.varint()?;
                    close::Code::Transport {
                        error_code: wire,
                        frame_type: ft,
                    }
                };
                let len = cursor.varint()?;
                let bytes = cursor.data(len)?;
                let reason = Data::from(data(bytes)?);
                Ok(frame::Repr::ConnectionClose { code, len, reason })
            }
            _ => Err(error::Fault::BadType { value: ty }),
        };
        let raw = decoded?;
        *input = cursor.rest();
        Ok((frame::Frame(raw), cursor.used()))
    }
}
