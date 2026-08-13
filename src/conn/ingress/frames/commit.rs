use crate::conn;
use crate::conn::handshake;
use crate::conn::recovery;
use crate::conn::streams;

use crate::stream;

use crate::conn::ingress::admitted_packet;
use crate::conn::ingress::frames;
use crate::conn::ingress::frames::plan;
use crate::conn::ingress::frames::source;

pub(super) trait Commit<const DOMAIN: u8, B: stream::ReceiveBuffer> {
    fn process<R, S>(
        &mut self,
        meta: frames::PacketMeta,
        packet_cid: Option<frames::PacketCid<'_>>,
        body: &[u8],
        read: &mut R,
        plan: &mut plan::Plan<'_>,
        source: &mut S,
    ) -> Result<frames::PacketDisposition, conn::Error>
    where
        R: handshake::Reader<DOMAIN>,
        S: source::Source<B>;
}

impl<const DOMAIN: u8, B: stream::ReceiveBuffer> Commit<DOMAIN, B>
    for admitted_packet::AdmittedPacket<'_, DOMAIN, B>
{
    fn process<R, S>(
        &mut self,
        meta: frames::PacketMeta,
        packet_cid: Option<frames::PacketCid<'_>>,
        body: &[u8],
        read: &mut R,
        plan: &mut plan::Plan<'_>,
        source: &mut S,
    ) -> Result<frames::PacketDisposition, conn::Error>
    where
        R: handshake::Reader<DOMAIN>,
        S: source::Source<B>,
    {
        let frames::PacketMeta { epoch, now, .. } = meta;
        let result = (|| {
            let (connection, discarded_received) = self.state();
            let crate::conn::session::Connection {
                egress,
                control,
                handshake,
                path,
                streams,
                receive,
                peer,
                ..
            } = connection;
            let stream_state = &mut streams.state;
            let stream_events = &mut streams.events;
            let is_client = peer.is_client;
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
                .ok_or(conn::Error::EventCapacity)?;
            receive.crypto[epoch as usize].prepare(parsed_frames.iter().filter_map(|frame| {
                let crate::frame::Frame::Crypto { offset, data } = frame else {
                    return None;
                };
                Some((offset.get(), &body[data.clone()]))
            }))?;
            source.prepare(reservation.admitted_bytes, |output| {
                for (frame_index, parsed) in parsed_frames.iter().enumerate() {
                    if admissions.get(frame_index)
                        != crate::conn::receive_workspace::ReceiveAdmission::Datagram
                    {
                        continue;
                    }
                    let crate::frame::Frame::Datagram { data, .. } = parsed else {
                        return Err(conn::Error::FrameDecode);
                    };
                    payloads
                        .set_start(frame_index, output.len())
                        .ok_or(conn::Error::StreamBufferExceeded)?;
                    output
                        .try_extend(&body[data.clone()])
                        .map_err(|_| conn::Error::StreamBufferExceeded)?;
                }
                let mut group_start = 0;
                while group_start < stream_frames.len() {
                    let stream_id = plan::Plan::stream_frame_id(
                        &parsed_frames[stream_frames[group_start].get()],
                    )
                    .ok_or(conn::Error::FrameDecode)?;
                    let group_end = stream_frames[group_start..]
                        .iter()
                        .position(|&frame_index| {
                            plan::Plan::stream_frame_id(&parsed_frames[frame_index.get()])
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
                    (
                        crate::conn::receive_workspace::ReceiveAdmission::Datagram,
                        crate::frame::Frame::Datagram { data, .. },
                    ) => {
                        let bytes = source.take_datagram(
                            data.clone(),
                            payloads.get(frame_index),
                            &body[data.clone()],
                        );
                        receive.datagrams.push_back(bytes);
                    }
                    (
                        crate::conn::receive_workspace::ReceiveAdmission::Stream,
                        crate::frame::Frame::Stream {
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
                        crate::conn::receive_workspace::ReceiveAdmission::StreamTransient,
                        crate::frame::Frame::Stream {
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
                        crate::conn::receive_workspace::ReceiveAdmission::Reset,
                        crate::frame::Frame::ResetStream {
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
                        crate::conn::receive_workspace::ReceiveAdmission::Stop,
                        crate::frame::Frame::StopSending {
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
                            peer.transport_params.as_ref(),
                            is_client,
                            control,
                            &mut event_permit,
                        );
                    }
                    (
                        crate::conn::receive_workspace::ReceiveAdmission::Drop,
                        crate::frame::Frame::Datagram { .. }
                        | crate::frame::Frame::Stream { .. }
                        | crate::frame::Frame::ResetStream { .. }
                        | crate::frame::Frame::StopSending { .. },
                    ) => {}
                    (
                        crate::conn::receive_workspace::ReceiveAdmission::StreamTransient,
                        crate::frame::Frame::Datagram { .. }
                        | crate::frame::Frame::ResetStream { .. }
                        | crate::frame::Frame::StopSending { .. },
                    ) => return Err(conn::Error::FrameDecode),
                    (_, parsed) => {
                        let shin_epoch = match epoch {
                            crate::conn::Epoch::Initial => shin::connection::Epoch::Plaintext,
                            crate::conn::Epoch::Handshake => shin::connection::Epoch::Handshake,
                            crate::conn::Epoch::Application => shin::connection::Epoch::Application,
                        };
                        let frame = parsed.clone().map(
                            |range| &body[range],
                            |ranges| {
                                crate::frame::ack_ranges::Ranges::new(
                                    &body[ranges.bytes],
                                    ranges.count,
                                )
                            },
                        );
                        match frame {
                            crate::frame::Frame::Crypto { offset, data } => {
                                receive.crypto[epoch as usize].accept(
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
                                                peer_transport_params: &mut peer.transport_params,
                                                is_client,
                                            })
                                            .complete()
                                            .is_err()
                                        {
                                            egress.lifecycle.state = crate::conn::State::Closed;
                                        }
                                        Ok(())
                                    },
                                )?;
                            }
                            crate::frame::Frame::Ack {
                                largest,
                                delay,
                                first_range,
                                additional_ranges,
                            } => {
                                let largest = largest.get();
                                if largest >= egress.recovery.spaces[epoch as usize].next_pn {
                                    return Err(conn::Error::ProtocolViolation);
                                }
                                let space = &mut egress.recovery.spaces[epoch as usize];
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
                            crate::frame::Frame::HandshakeDone
                                if epoch == crate::conn::Epoch::Application && is_client =>
                            {
                                egress.lifecycle.handshake_confirmed = true;
                                recovery::epochs::Transition::new(egress, handshake)
                                    .discard_initial();
                                discarded_received.record(crate::conn::Epoch::Initial);
                                recovery::epochs::Transition::new(egress, handshake)
                                    .discard_handshake();
                                discarded_received.record(crate::conn::Epoch::Handshake);
                                receive.crypto[crate::conn::Epoch::Initial as usize].discard();
                                receive.crypto[crate::conn::Epoch::Handshake as usize].discard();
                            }
                            crate::frame::Frame::ConnectionClose { .. } => {
                                egress.lifecycle.state = crate::conn::State::Closed;
                            }
                            crate::frame::Frame::NewConnectionId {
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
                            crate::frame::Frame::RetireConnectionId { sequence_number }
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
                            crate::frame::Frame::NewConnectionId { .. }
                            | crate::frame::Frame::RetireConnectionId { .. } => {
                                return Err(conn::Error::ProtocolViolation);
                            }
                            crate::frame::Frame::PathChallenge { data }
                                if epoch == crate::conn::Epoch::Application =>
                            {
                                path.queue_response(data, control);
                            }
                            crate::frame::Frame::MaxData { maximum_data }
                                if epoch == crate::conn::Epoch::Application
                                    && maximum_data.get()
                                        > stream_state.transmit.peer_data_credit.limit() =>
                            {
                                stream_state
                                    .transmit
                                    .peer_data_credit
                                    .raise(maximum_data.get(), control);
                            }
                            crate::frame::Frame::MaxStreamData {
                                stream_id,
                                maximum_stream_data,
                            } if epoch == crate::conn::Epoch::Application => {
                                let stream_id = stream_id.get();
                                stream_state.validate_or_open_peer_reserved(
                                    stream_id,
                                    streams::Access::Send,
                                    is_client,
                                )?;
                                stream_state.raise_stream_credit_reserved(
                                    stream_id,
                                    maximum_stream_data.get(),
                                    peer.transport_params.as_ref(),
                                    is_client,
                                    control,
                                );
                            }
                            crate::frame::Frame::DataBlocked { .. }
                                if epoch == crate::conn::Epoch::Application => {}
                            crate::frame::Frame::StreamDataBlocked { stream_id, .. }
                                if epoch == crate::conn::Epoch::Application =>
                            {
                                stream_state.validate_or_open_peer_reserved(
                                    stream_id.get(),
                                    streams::Access::Receive,
                                    is_client,
                                )?;
                            }
                            crate::frame::Frame::MaxStreams {
                                is_uni,
                                max_streams,
                            } if epoch == crate::conn::Epoch::Application => {
                                let maximum = max_streams.get();
                                if maximum > crate::conn::MAX_STREAM_COUNT {
                                    return Err(conn::Error::ProtocolViolation);
                                }
                                let limit =
                                    &mut stream_state.local_initiated.peer_max[usize::from(is_uni)];
                                *limit = (*limit).max(maximum);
                            }
                            crate::frame::Frame::StreamsBlocked { .. }
                                if epoch == crate::conn::Epoch::Application => {}
                            crate::frame::Frame::PathResponse { data }
                                if epoch == crate::conn::Epoch::Application =>
                            {
                                path.record_response(data, control);
                            }
                            _ => {}
                        }
                    }
                }
            }
            Ok(frames::PacketDisposition::Commit)
        })();

        match result {
            Err(conn::Error::EventCapacity | conn::Error::StreamBufferExceeded) => {
                Ok(frames::PacketDisposition::Drop)
            }
            result => result,
        }
    }
}
