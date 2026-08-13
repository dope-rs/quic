use std::ops;

use crate::conn::delivery;
use crate::frame;
use crate::varint;

use crate::conn::control;

pub(in crate::conn) struct Encoder<'a> {
    pending: &'a control::Pending,
    path: &'a crate::conn::path::Path,
}

impl<'a> Encoder<'a> {
    pub(in crate::conn) fn new(
        pending: &'a control::Pending,
        path: &'a crate::conn::path::Path,
    ) -> Self {
        Self { pending, path }
    }
    pub(in crate::conn) fn encode_pending<const MASK: u16, Out>(
        &self,
        out: &mut Out,
        limit: usize,
        handle: delivery::Handle<delivery::Control>,
        record: delivery::Control,
    ) -> bool
    where
        Out: ops::DerefMut<Target = Vec<u8>>,
    {
        if MASK == control::PREFIX {
            match record {
                delivery::Control::HandshakeDone => {
                    Self::append(out, limit, &frame::Frame::HandshakeDone)
                }
                delivery::Control::NewConnectionId(sequence_number) => {
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
                    let Some(sequence_number) = varint::VarInt::new(sequence_number) else {
                        out.truncate(start);
                        return false;
                    };
                    sequence_number.encode(&mut **out);
                    varint::VarInt::ZERO.encode(&mut **out);
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
                delivery::Control::RetireConnectionId(sequence_number) => {
                    let Some(sequence_number) = varint::VarInt::new(sequence_number) else {
                        return false;
                    };
                    Self::append(
                        out,
                        limit,
                        &frame::Frame::RetireConnectionId { sequence_number },
                    )
                }
                _ => unreachable!("prefix cursor emitted a suffix control"),
            }
        } else {
            debug_assert_eq!(MASK, control::SUFFIX);
            match record {
                delivery::Control::StopSending(stream_id, error_code) => {
                    let (Some(stream_id), Some(error_code)) = (
                        varint::VarInt::new(stream_id),
                        varint::VarInt::new(error_code),
                    ) else {
                        return false;
                    };
                    Self::append(
                        out,
                        limit,
                        &frame::Frame::StopSending {
                            stream_id,
                            error_code,
                        },
                    )
                }
                delivery::Control::ResetStream(stream_id, error_code, final_size) => {
                    let (Some(stream_id), Some(error_code), Some(final_size)) = (
                        varint::VarInt::new(stream_id),
                        varint::VarInt::new(error_code),
                        varint::VarInt::new(final_size),
                    ) else {
                        return false;
                    };
                    Self::append(
                        out,
                        limit,
                        &frame::Frame::ResetStream {
                            stream_id,
                            error_code,
                            final_size,
                        },
                    )
                }
                delivery::Control::MaxData(maximum_data) => {
                    let Some(maximum_data) = varint::VarInt::new(maximum_data) else {
                        return false;
                    };
                    Self::append(out, limit, &frame::Frame::MaxData { maximum_data })
                }
                delivery::Control::MaxStreamData(stream_id, maximum_stream_data) => {
                    let (Some(stream_id), Some(maximum_stream_data)) = (
                        varint::VarInt::new(stream_id),
                        varint::VarInt::new(maximum_stream_data),
                    ) else {
                        return false;
                    };
                    Self::append(
                        out,
                        limit,
                        &frame::Frame::MaxStreamData {
                            stream_id,
                            maximum_stream_data,
                        },
                    )
                }
                delivery::Control::MaxStreams(is_uni, max_streams) => {
                    let Some(max_streams) = varint::VarInt::new(max_streams) else {
                        return false;
                    };
                    Self::append(
                        out,
                        limit,
                        &frame::Frame::MaxStreams {
                            is_uni,
                            max_streams,
                        },
                    )
                }
                delivery::Control::PathResponse(data) => {
                    Self::append(out, limit, &frame::Frame::PathResponse { data })
                }
                delivery::Control::PathChallenge(data) => {
                    Self::append(out, limit, &frame::Frame::PathChallenge { data })
                }
                _ => unreachable!("suffix cursor emitted a non-suffix control"),
            }
        }
    }

    pub(in crate::conn) fn encode_probe<Out>(
        &self,
        out: &mut Out,
        limit: usize,
        handle: delivery::Handle<delivery::Control>,
        record: delivery::Control,
    ) -> bool
    where
        Out: ops::DerefMut<Target = Vec<u8>>,
    {
        match record {
            delivery::Control::HandshakeDone
            | delivery::Control::NewConnectionId(_)
            | delivery::Control::RetireConnectionId(_) => {
                self.encode_pending::<{ control::PREFIX }, _>(out, limit, handle, record)
            }
            delivery::Control::StopSending(_, _)
            | delivery::Control::ResetStream(_, _, _)
            | delivery::Control::MaxData(_)
            | delivery::Control::MaxStreamData(_, _)
            | delivery::Control::MaxStreams(_, _)
            | delivery::Control::PathResponse(_)
            | delivery::Control::PathChallenge(_) => {
                self.encode_pending::<{ control::SUFFIX }, _>(out, limit, handle, record)
            }
            delivery::Control::DataBlocked(_) | delivery::Control::StreamDataBlocked(_, _) => {
                self.encode_blocked(out, limit, record)
            }
        }
    }

    pub(in crate::conn) fn encode_blocked<Out>(
        &self,
        out: &mut Out,
        limit: usize,
        record: delivery::Control,
    ) -> bool
    where
        Out: ops::DerefMut<Target = Vec<u8>>,
    {
        match record {
            delivery::Control::DataBlocked(maximum_data) => {
                let Some(maximum_data) = varint::VarInt::new(maximum_data) else {
                    return false;
                };
                Self::append(out, limit, &frame::Frame::DataBlocked { maximum_data })
            }
            delivery::Control::StreamDataBlocked(stream_id, maximum_stream_data) => {
                let (Some(stream_id), Some(maximum_stream_data)) = (
                    varint::VarInt::new(stream_id),
                    varint::VarInt::new(maximum_stream_data),
                ) else {
                    return false;
                };
                Self::append(
                    out,
                    limit,
                    &frame::Frame::StreamDataBlocked {
                        stream_id,
                        maximum_stream_data,
                    },
                )
            }
            _ => unreachable!("blocked encoder received a regular control"),
        }
    }

    fn append<Out>(out: &mut Out, limit: usize, frame: &frame::Frame) -> bool
    where
        Out: ops::DerefMut<Target = Vec<u8>>,
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
