use crate::conn::receive_workspace::ReceiveAdmission;
use crate::conn::{
    Connection, Epoch, Error, MAX_STREAM_COUNT, State, handshake, recovery, streams,
};
use crate::frame::Frame;
use crate::frame::ack_ranges::Ranges;
use crate::stream::ReceiveBuffer;

use super::plan::Plan;
use super::source::Source;
use super::{PacketCid, PacketDisposition, PacketMeta};
use crate::conn::ingress::admitted_packet::AdmittedPacket;

pub(super) trait Commit<const DOMAIN: u8, B: ReceiveBuffer> {
    fn process<R, S>(
        &mut self,
        meta: PacketMeta,
        packet_cid: Option<PacketCid<'_>>,
        body: &[u8],
        read: &mut R,
        plan: &mut Plan<'_>,
        source: &mut S,
    ) -> Result<PacketDisposition, Error>
    where
        R: handshake::Reader<DOMAIN>,
        S: Source<B>;
}

impl<const DOMAIN: u8, B: ReceiveBuffer> Commit<DOMAIN, B> for AdmittedPacket<'_, DOMAIN, B> {
    fn process<R, S>(
        &mut self,
        meta: PacketMeta,
        packet_cid: Option<PacketCid<'_>>,
        body: &[u8],
        read: &mut R,
        plan: &mut Plan<'_>,
        source: &mut S,
    ) -> Result<PacketDisposition, Error>
    where
        R: handshake::Reader<DOMAIN>,
        S: Source<B>,
    {
        let PacketMeta { epoch, now, .. } = meta;
        let result = (|| {
            let (connection, discarded_received) = self.state();
            let Connection {
                egress,
                control,
                handshake,
                path,
                streams,
                is_client,
                incoming_datagrams,
                peer_transport_params,
                recv_crypto,
                ..
            } = connection;
            let stream_state = &mut streams.state;
            let stream_events = &mut streams.events;
            let is_client = *is_client;
            let reservation = plan.reserve(stream_state, is_client)?;
            let workspace = plan.workspace();
            let parsed_frames = &mut workspace.parsed_frames;
            let admissions = &mut workspace.admissions;
            let payloads = &mut workspace.payloads;
            let stream_frames = workspace.stream_frames.as_mut_slice();
            let segments = &mut workspace.segments;
            let parts = &mut workspace.parts;
            let mut event_permit = stream_events
                .reserve(reservation.event_slots)
                .ok_or(Error::EventCapacity)?;
            recv_crypto[epoch as usize].prepare(parsed_frames.iter().filter_map(|frame| {
                let Frame::Crypto { offset, data } = frame else {
                    return None;
                };
                Some((offset.get(), &body[data.clone()]))
            }))?;
            source.prepare(reservation.admitted_bytes, |output| {
                for (frame_index, parsed) in parsed_frames.iter().enumerate() {
                    if admissions.get(frame_index) != ReceiveAdmission::Datagram {
                        continue;
                    }
                    let Frame::Datagram { data, .. } = parsed else {
                        return Err(Error::FrameDecode);
                    };
                    payloads
                        .set_start(frame_index, output.len())
                        .ok_or(Error::StreamBufferExceeded)?;
                    output
                        .try_extend(&body[data.clone()])
                        .map_err(|_| Error::StreamBufferExceeded)?;
                }
                let mut group_start = 0;
                while group_start < stream_frames.len() {
                    let stream_id =
                        Plan::stream_frame_id(&parsed_frames[stream_frames[group_start].get()])
                            .ok_or(Error::FrameDecode)?;
                    let group_end = stream_frames[group_start..]
                        .iter()
                        .position(|&frame_index| {
                            Plan::stream_frame_id(&parsed_frames[frame_index.get()])
                                != Some(stream_id)
                        })
                        .map_or(stream_frames.len(), |offset| group_start + offset);
                    stream_state.materialize_stream_frames(
                        streams::receive::FrameGroup::new(
                            &stream_frames[group_start..group_end],
                            parsed_frames,
                        ),
                        streams::receive::MaterializeContext::new(
                            admissions, payloads, segments, parts, body, output,
                        ),
                    )?;
                    group_start = group_end;
                }
                Ok(())
            })?;
            for (frame_index, parsed) in parsed_frames.iter().enumerate() {
                match (admissions.get(frame_index), parsed) {
                    (ReceiveAdmission::Datagram, Frame::Datagram { data, .. }) => {
                        let bytes = source.take_datagram(
                            data.clone(),
                            payloads.get(frame_index),
                            &body[data.clone()],
                        );
                        incoming_datagrams.push_back(bytes);
                    }
                    (
                        ReceiveAdmission::Stream,
                        Frame::Stream {
                            stream_id,
                            offset,
                            fin,
                            data,
                            ..
                        },
                    ) => {
                        let stream_id = stream_id.get();
                        stream_state
                            .validate_or_open_peer_reserved(
                                stream_id,
                                streams::Access::Receive,
                                is_client,
                            )
                            .expect("the receive plan validated stream access");
                        let bytes = source.take_stream(
                            data.clone(),
                            payloads.get(frame_index),
                            &body[data.clone()],
                        );
                        stream_state
                            .ingest_stream_reserved(
                                streams::receive::IncomingStream::new(
                                    stream_id,
                                    offset.get(),
                                    *fin,
                                    is_client,
                                ),
                                bytes,
                                parts,
                                &mut event_permit,
                            )
                            .expect("the receive plan reserved every commit resource");
                    }
                    (
                        ReceiveAdmission::StreamTransient,
                        Frame::Stream {
                            stream_id,
                            offset,
                            fin,
                            data,
                            ..
                        },
                    ) => {
                        let stream_id = stream_id.get();
                        stream_state
                            .validate_or_open_peer_reserved(
                                stream_id,
                                streams::Access::Receive,
                                is_client,
                            )
                            .expect("the receive plan validated transient stream access");
                        stream_state
                            .ingest_stream_transient_reserved(
                                stream_id,
                                offset.get(),
                                data.len(),
                                *fin,
                                is_client,
                                &mut event_permit,
                            )
                            .expect("the receive plan reserved every transient stream resource");
                    }
                    (
                        ReceiveAdmission::Reset,
                        Frame::ResetStream {
                            stream_id,
                            error_code,
                            final_size,
                        },
                    ) => {
                        let stream_id = stream_id.get();
                        stream_state
                            .validate_or_open_peer_reserved(
                                stream_id,
                                streams::Access::Receive,
                                is_client,
                            )
                            .expect("the receive plan validated reset access");
                        stream_state
                            .ingest_reset_reserved(
                                stream_id,
                                error_code.get(),
                                final_size.get(),
                                is_client,
                                control,
                                &mut event_permit,
                            )
                            .expect("the receive plan reserved every reset resource");
                    }
                    (
                        ReceiveAdmission::Stop,
                        Frame::StopSending {
                            stream_id,
                            error_code,
                        },
                    ) => {
                        let stream_id = stream_id.get();
                        stream_state
                            .validate_or_open_peer_reserved(
                                stream_id,
                                streams::Access::Send,
                                is_client,
                            )
                            .expect("the receive plan validated stop access");
                        stream_state.ingest_stop_reserved(
                            stream_id,
                            error_code.get(),
                            peer_transport_params.as_ref(),
                            is_client,
                            control,
                            &mut event_permit,
                        );
                    }
                    (
                        ReceiveAdmission::Drop,
                        Frame::Datagram { .. }
                        | Frame::Stream { .. }
                        | Frame::ResetStream { .. }
                        | Frame::StopSending { .. },
                    ) => {}
                    (
                        ReceiveAdmission::StreamTransient,
                        Frame::Datagram { .. }
                        | Frame::ResetStream { .. }
                        | Frame::StopSending { .. },
                    ) => return Err(Error::FrameDecode),
                    (_, parsed) => {
                        let shin_epoch = match epoch {
                            Epoch::Initial => shin::connection::Epoch::Plaintext,
                            Epoch::Handshake => shin::connection::Epoch::Handshake,
                            Epoch::Application => shin::connection::Epoch::Application,
                        };
                        let frame = parsed.clone().map(
                            |range| &body[range],
                            |ranges| Ranges::new(&body[ranges.bytes], ranges.count),
                        );
                        match frame {
                            Frame::Crypto { offset, data } => {
                                recv_crypto[epoch as usize].accept(
                                    offset.get(),
                                    data,
                                    |message| {
                                        let outcome =
                                            read.read(handshake, shin_epoch, message, is_client)?;
                                        if outcome.reject_early_data {
                                            recovery::early::EarlyData::new(
                                                egress,
                                                control,
                                                handshake,
                                                stream_state,
                                                event_permit.events(),
                                                is_client,
                                            )
                                            .reject();
                                        }
                                        if outcome.done
                                            && (handshake::Establishment {
                                                egress,
                                                handshake,
                                                path,
                                                streams: stream_state,
                                                peer_transport_params,
                                                is_client,
                                            })
                                            .complete()
                                            .is_err()
                                        {
                                            egress.state = State::Closed;
                                        }
                                        Ok(())
                                    },
                                )?;
                            }
                            Frame::Ack {
                                largest,
                                delay,
                                first_range,
                                additional_ranges,
                            } => {
                                let largest = largest.get();
                                if largest >= egress.spaces[epoch as usize].next_pn {
                                    return Err(Error::ProtocolViolation);
                                }
                                let space = &mut egress.spaces[epoch as usize];
                                space.largest_acked =
                                    Some(space.largest_acked.unwrap_or(0).max(largest));
                                recovery::ack::Ack::new(
                                    egress,
                                    control,
                                    handshake,
                                    stream_state,
                                    event_permit.events(),
                                    is_client,
                                )
                                .apply(
                                    epoch,
                                    recovery::ack::Receipt {
                                        largest,
                                        delay_microseconds: delay.get(),
                                        first_range: first_range.get(),
                                        additional_ranges,
                                    },
                                    now,
                                );
                            }
                            Frame::HandshakeDone if epoch == Epoch::Application && is_client => {
                                egress.handshake_confirmed = true;
                                recovery::epochs::Transition::new(egress, handshake)
                                    .discard_initial();
                                discarded_received.record(Epoch::Initial);
                                recovery::epochs::Transition::new(egress, handshake)
                                    .discard_handshake();
                                discarded_received.record(Epoch::Handshake);
                                recv_crypto[Epoch::Initial as usize].discard();
                                recv_crypto[Epoch::Handshake as usize].discard();
                            }
                            Frame::ConnectionClose { .. } => {
                                egress.state = State::Closed;
                            }
                            Frame::NewConnectionId {
                                sequence_number,
                                retire_prior_to,
                                connection_id,
                                stateless_reset_token,
                            } if packet_cid.is_some() => {
                                path.accept_peer_cid(
                                    sequence_number.get(),
                                    retire_prior_to.get(),
                                    connection_id,
                                    stateless_reset_token,
                                    control,
                                )?;
                            }
                            Frame::RetireConnectionId { sequence_number }
                                if packet_cid.is_some() =>
                            {
                                let packet_cid = packet_cid
                                    .expect("a guarded 1-RTT frame has packet CID identity");
                                let issued = path.retire_local_cid(
                                    sequence_number.get(),
                                    packet_cid.routed,
                                    packet_cid.bytes,
                                    control,
                                )?;
                                egress.derived_controls.arm_new_connection_ids(issued);
                            }
                            Frame::NewConnectionId { .. } | Frame::RetireConnectionId { .. } => {
                                return Err(Error::ProtocolViolation);
                            }
                            Frame::PathChallenge { data } if epoch == Epoch::Application => {
                                path.queue_response(data, control);
                            }
                            Frame::MaxData { maximum_data }
                                if epoch == Epoch::Application
                                    && maximum_data.get()
                                        > stream_state.transmit.peer_data_credit.limit() =>
                            {
                                stream_state
                                    .transmit
                                    .peer_data_credit
                                    .raise(maximum_data.get(), control);
                            }
                            Frame::MaxStreamData {
                                stream_id,
                                maximum_stream_data,
                            } if epoch == Epoch::Application => {
                                let stream_id = stream_id.get();
                                stream_state.validate_or_open_peer_reserved(
                                    stream_id,
                                    streams::Access::Send,
                                    is_client,
                                )?;
                                stream_state.raise_stream_credit_reserved(
                                    stream_id,
                                    maximum_stream_data.get(),
                                    peer_transport_params.as_ref(),
                                    is_client,
                                    control,
                                );
                            }
                            Frame::DataBlocked { .. } if epoch == Epoch::Application => {}
                            Frame::StreamDataBlocked { stream_id, .. }
                                if epoch == Epoch::Application =>
                            {
                                stream_state.validate_or_open_peer_reserved(
                                    stream_id.get(),
                                    streams::Access::Receive,
                                    is_client,
                                )?;
                            }
                            Frame::MaxStreams {
                                is_uni,
                                max_streams,
                            } if epoch == Epoch::Application => {
                                let maximum = max_streams.get();
                                if maximum > MAX_STREAM_COUNT {
                                    return Err(Error::ProtocolViolation);
                                }
                                let limit =
                                    &mut stream_state.local_initiated.peer_max[usize::from(is_uni)];
                                *limit = (*limit).max(maximum);
                            }
                            Frame::StreamsBlocked { .. } if epoch == Epoch::Application => {}
                            Frame::PathResponse { data } if epoch == Epoch::Application => {
                                path.record_response(data, control);
                            }
                            _ => {}
                        }
                    }
                }
            }
            Ok(PacketDisposition::Commit)
        })();

        match result {
            Err(Error::EventCapacity | Error::StreamBufferExceeded) => Ok(PacketDisposition::Drop),
            result => result,
        }
    }
}
