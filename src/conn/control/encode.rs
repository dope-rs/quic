use std::ops::DerefMut;

use crate::conn::delivery::{Control, Handle};
use crate::frame::Frame;
use crate::varint::VarInt;

use super::{PREFIX, Pending, SUFFIX};

pub(in crate::conn) struct Encoder<'a> {
    pending: &'a Pending,
    path: &'a crate::conn::path::Path,
}

impl<'a> Encoder<'a> {
    pub(in crate::conn) fn new(pending: &'a Pending, path: &'a crate::conn::path::Path) -> Self {
        Self { pending, path }
    }
    pub(in crate::conn) fn encode_pending<const MASK: u16, Out>(
        &self,
        out: &mut Out,
        limit: usize,
        handle: Handle<Control>,
        record: Control,
    ) -> bool
    where
        Out: DerefMut<Target = Vec<u8>>,
    {
        if MASK == PREFIX {
            match record {
                Control::HandshakeDone => Self::append(out, limit, &Frame::HandshakeDone),
                Control::NewConnectionId(sequence_number) => {
                    let Some(key) = self.pending.local_cid_key(handle) else {
                        return false;
                    };
                    let Some((resolved_sequence, connection_id, reset_token)) =
                        self.path.local_cid_frame(key)
                    else {
                        return false;
                    };
                    debug_assert_eq!(sequence_number, resolved_sequence);
                    let start = out.len();
                    out.push(0x18);
                    let Some(sequence_number) = VarInt::new(sequence_number) else {
                        out.truncate(start);
                        return false;
                    };
                    sequence_number.encode(&mut **out);
                    VarInt::ZERO.encode(&mut **out);
                    out.push(connection_id.len() as u8);
                    out.extend_from_slice(connection_id);
                    out.extend_from_slice(&reset_token);
                    if out.len() <= limit {
                        true
                    } else {
                        out.truncate(start);
                        false
                    }
                }
                Control::RetireConnectionId(sequence_number) => {
                    let Some(sequence_number) = VarInt::new(sequence_number) else {
                        return false;
                    };
                    Self::append(out, limit, &Frame::RetireConnectionId { sequence_number })
                }
                _ => unreachable!("prefix cursor emitted a suffix control"),
            }
        } else {
            debug_assert_eq!(MASK, SUFFIX);
            match record {
                Control::StopSending(stream_id, error_code) => {
                    let (Some(stream_id), Some(error_code)) =
                        (VarInt::new(stream_id), VarInt::new(error_code))
                    else {
                        return false;
                    };
                    Self::append(
                        out,
                        limit,
                        &Frame::StopSending {
                            stream_id,
                            error_code,
                        },
                    )
                }
                Control::ResetStream(stream_id, error_code, final_size) => {
                    let (Some(stream_id), Some(error_code), Some(final_size)) = (
                        VarInt::new(stream_id),
                        VarInt::new(error_code),
                        VarInt::new(final_size),
                    ) else {
                        return false;
                    };
                    Self::append(
                        out,
                        limit,
                        &Frame::ResetStream {
                            stream_id,
                            error_code,
                            final_size,
                        },
                    )
                }
                Control::MaxData(maximum_data) => {
                    let Some(maximum_data) = VarInt::new(maximum_data) else {
                        return false;
                    };
                    Self::append(out, limit, &Frame::MaxData { maximum_data })
                }
                Control::MaxStreamData(stream_id, maximum_stream_data) => {
                    let (Some(stream_id), Some(maximum_stream_data)) =
                        (VarInt::new(stream_id), VarInt::new(maximum_stream_data))
                    else {
                        return false;
                    };
                    Self::append(
                        out,
                        limit,
                        &Frame::MaxStreamData {
                            stream_id,
                            maximum_stream_data,
                        },
                    )
                }
                Control::MaxStreams(is_uni, max_streams) => {
                    let Some(max_streams) = VarInt::new(max_streams) else {
                        return false;
                    };
                    Self::append(
                        out,
                        limit,
                        &Frame::MaxStreams {
                            is_uni,
                            max_streams,
                        },
                    )
                }
                Control::PathResponse(data) => {
                    Self::append(out, limit, &Frame::PathResponse { data })
                }
                Control::PathChallenge(data) => {
                    Self::append(out, limit, &Frame::PathChallenge { data })
                }
                _ => unreachable!("suffix cursor emitted a non-suffix control"),
            }
        }
    }

    pub(in crate::conn) fn encode_probe<Out>(
        &self,
        out: &mut Out,
        limit: usize,
        handle: Handle<Control>,
        record: Control,
    ) -> bool
    where
        Out: DerefMut<Target = Vec<u8>>,
    {
        match record {
            Control::HandshakeDone
            | Control::NewConnectionId(_)
            | Control::RetireConnectionId(_) => {
                self.encode_pending::<PREFIX, _>(out, limit, handle, record)
            }
            Control::StopSending(_, _)
            | Control::ResetStream(_, _, _)
            | Control::MaxData(_)
            | Control::MaxStreamData(_, _)
            | Control::MaxStreams(_, _)
            | Control::PathResponse(_)
            | Control::PathChallenge(_) => {
                self.encode_pending::<SUFFIX, _>(out, limit, handle, record)
            }
            Control::DataBlocked(_) | Control::StreamDataBlocked(_, _) => {
                self.encode_blocked(out, limit, record)
            }
        }
    }

    pub(in crate::conn) fn encode_blocked<Out>(
        &self,
        out: &mut Out,
        limit: usize,
        record: Control,
    ) -> bool
    where
        Out: DerefMut<Target = Vec<u8>>,
    {
        match record {
            Control::DataBlocked(maximum_data) => {
                let Some(maximum_data) = VarInt::new(maximum_data) else {
                    return false;
                };
                Self::append(out, limit, &Frame::DataBlocked { maximum_data })
            }
            Control::StreamDataBlocked(stream_id, maximum_stream_data) => {
                let (Some(stream_id), Some(maximum_stream_data)) =
                    (VarInt::new(stream_id), VarInt::new(maximum_stream_data))
                else {
                    return false;
                };
                Self::append(
                    out,
                    limit,
                    &Frame::StreamDataBlocked {
                        stream_id,
                        maximum_stream_data,
                    },
                )
            }
            _ => unreachable!("blocked encoder received a regular control"),
        }
    }

    fn append<Out>(out: &mut Out, limit: usize, frame: &Frame) -> bool
    where
        Out: DerefMut<Target = Vec<u8>>,
    {
        let start = out.len();
        if frame.encode(out).is_ok() && out.len() <= limit {
            true
        } else {
            out.truncate(start);
            false
        }
    }
}
