use crate::conn::commit;
use crate::conn::delivery;
use crate::conn::packet;
use crate::conn::stream_journal;

use crate::stream;

use crate::conn::transmit::builder::ack::Ack as _;
use crate::conn::transmit::builder::application;
use crate::conn::transmit::builder::crypto::Crypto as _;

pub(in crate::conn::transmit) trait BuildOneRtt {
    fn build_one_rtt<const PTO_PROBE: bool>(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
    ) -> Option<(usize, commit::Packet)>;
}

impl<const DOMAIN: u8, B: stream::ReceiveBuffer> BuildOneRtt
    for application::Application<'_, DOMAIN, B>
{
    fn build_one_rtt<const PTO_PROBE: bool>(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
    ) -> Option<(usize, commit::Packet)> {
        let pn = self.packet.connection.egress.recovery.spaces
            [crate::conn::Epoch::Application as usize]
            .next_pn;
        let packet_start = dst.len();
        let pn_off = crate::packet::ShortHeaderRef {
            dcid: self.packet.connection.path.peer_cid(),
            packet_number: pn,
            pn_len: crate::conn::PN_LEN,
        }
        .encode_into(dst)
        .ok()?;
        let payload_start = dst.len();
        let payload_limit =
            payload_start.checked_add(self.packet.short_payload_limit(max_packet_bytes))?;
        let mut frames = packet::Payload::new(dst, payload_start);
        let mut commit = commit::Packet::new(crate::conn::Epoch::Application, pn);
        let track_delivery = self.packet.can_track_packet();
        if PTO_PROBE {
            commit.properties.ack_included = self.packet.append_ack_frame(
                crate::conn::Epoch::Application,
                &mut frames,
                payload_limit,
            );
            let frame_room = payload_limit.saturating_sub(frames.len());
            if let Some((delivery, data)) = self
                .packet
                .crypto_probe(crate::conn::Epoch::Application, frame_room)
                && crate::conn::transmit::builder::Builder::<DOMAIN, B>::encode_crypto(
                    &mut frames,
                    delivery.record.offset,
                    data,
                )
            {
                commit.crypto = Some(delivery);
                commit.properties.ack_eliciting = true;
            }
            while !commit.controls.is_full() {
                let next = self.packet.connection.control.next_probe(
                    crate::conn::Epoch::Application,
                    |handle| {
                        commit
                            .controls
                            .as_slice()
                            .iter()
                            .any(|delivery| delivery.handle == handle)
                    },
                );
                let Some((handle, record)) = next else {
                    break;
                };
                if !crate::conn::control::encode::Encoder::new(
                    &self.packet.connection.control,
                    &self.packet.connection.path,
                )
                .encode_probe(&mut frames, payload_limit, handle, record)
                {
                    break;
                }
                commit.push_control_delivery(record, handle);
                commit.properties.ack_eliciting = true;
            }
            while !commit.streams.is_full() {
                let next = self
                    .packet
                    .connection
                    .streams
                    .transmit
                    .deliveries
                    .next_probe(|handle| {
                        commit
                            .streams
                            .as_slice()
                            .iter()
                            .any(|delivery| delivery.tracked == Some(handle))
                    });
                let Some((handle, send_handle, record)) = next else {
                    break;
                };
                let room = payload_limit.saturating_sub(
                    frames
                        .len()
                        .saturating_add(crate::conn::STREAM_FRAME_OVERHEAD),
                );
                if record.len as usize > room {
                    break;
                }
                let Some((stream_id, stream)) = self
                    .packet
                    .connection
                    .streams
                    .transmit
                    .map
                    .resolve(send_handle)
                else {
                    self.packet
                        .connection
                        .streams
                        .transmit
                        .deliveries
                        .discard_group(handle);
                    continue;
                };
                if stream_id != record.stream_id {
                    self.packet
                        .connection
                        .streams
                        .transmit
                        .deliveries
                        .discard_group(handle);
                    continue;
                }
                let Ok(len) = usize::try_from(record.len) else {
                    continue;
                };
                if !crate::conn::transmit::builder::Builder::<DOMAIN, B>::append_stream_frame(
                    &mut frames,
                    payload_limit,
                    record.stream_id,
                    record.offset,
                    record.fin,
                    stream,
                    len,
                ) {
                    break;
                }
                commit.push_stream_delivery(commit::Delivery {
                    record,
                    tracked: Some(handle),
                });
                commit.properties.ack_eliciting = true;
            }
            if !commit.properties.ack_eliciting {
                if !crate::conn::transmit::builder::Builder::<DOMAIN, B>::append_frame(
                    &mut frames,
                    payload_limit,
                    &crate::frame::Frame::Ping,
                ) {
                    return None;
                }
                commit.properties.ack_eliciting = true;
            }
            commit.properties.pto_probe = true;
        } else {
            commit.properties.ack_included = self.packet.append_ack_frame(
                crate::conn::Epoch::Application,
                &mut frames,
                payload_limit,
            );
            let has_control = track_delivery && !self.packet.connection.control.is_empty();
            if has_control && let Some(cursor) = self.packet.connection.control.ready().prefix() {
                crate::conn::transmit::builder::Builder::<DOMAIN, B>::append_pending_controls(
                    &self.packet.connection.control,
                    &self.packet.connection.path,
                    &mut frames,
                    payload_limit,
                    &mut commit,
                    cursor,
                );
            }
            let frame_room = payload_limit.saturating_sub(frames.len());
            let crypto = track_delivery
                .then(|| {
                    crate::conn::transmit::builder::Builder::<DOMAIN, B>::peek_crypto_chunk(
                        self.packet.connection.handshake.crypto(),
                        crate::conn::Epoch::Application,
                        frame_room,
                    )
                })
                .flatten();
            if let Some((crypto, data)) = crypto
                && crate::conn::transmit::builder::Builder::<DOMAIN, B>::encode_crypto(
                    &mut frames,
                    crypto.record.offset,
                    data,
                )
            {
                commit.crypto = Some(crypto);
                commit.properties.ack_eliciting = true;
            }
            if has_control
                && let Some(records) = self.packet.connection.control.ready().only_path_responses()
            {
                crate::conn::transmit::builder::Builder::<DOMAIN, B>::append_path_controls(
                    &self.packet.connection.control,
                    &self.packet.connection.path,
                    records,
                    &mut frames,
                    payload_limit,
                    &mut commit,
                );
            } else if has_control
                && let Some(records) = self
                    .packet
                    .connection
                    .control
                    .ready()
                    .only_path_challenges()
            {
                crate::conn::transmit::builder::Builder::<DOMAIN, B>::append_path_controls(
                    &self.packet.connection.control,
                    &self.packet.connection.path,
                    records,
                    &mut frames,
                    payload_limit,
                    &mut commit,
                );
            } else if has_control
                && let Some(cursor) = self.packet.connection.control.ready().suffix()
            {
                crate::conn::transmit::builder::Builder::<DOMAIN, B>::append_pending_controls(
                    &self.packet.connection.control,
                    &self.packet.connection.path,
                    &mut frames,
                    payload_limit,
                    &mut commit,
                    cursor,
                );
            }
            let mut retry_remaining = crate::conn::PACKET_STREAM_CAPACITY;
            let mut retry_work = stream_journal::RetryWork::new(&mut retry_remaining);
            while track_delivery && !commit.streams.is_full() {
                let room = payload_limit.saturating_sub(
                    frames
                        .len()
                        .saturating_add(crate::conn::STREAM_FRAME_OVERHEAD),
                );
                let next = self
                    .packet
                    .connection
                    .streams
                    .transmit
                    .deliveries
                    .next_retransmit(room, &mut retry_work, |handle| {
                        commit
                            .streams
                            .as_slice()
                            .iter()
                            .any(|delivery| delivery.tracked == Some(handle))
                    });
                let Some((handle, send_handle, record)) = next else {
                    break;
                };
                let Some((stream_id, stream)) = self
                    .packet
                    .connection
                    .streams
                    .transmit
                    .map
                    .resolve(send_handle)
                else {
                    self.packet
                        .connection
                        .streams
                        .transmit
                        .deliveries
                        .discard_group(handle);
                    continue;
                };
                if stream_id != record.stream_id {
                    self.packet
                        .connection
                        .streams
                        .transmit
                        .deliveries
                        .discard_group(handle);
                    continue;
                }
                let Ok(len_usize) = usize::try_from(record.len) else {
                    continue;
                };
                if !crate::conn::transmit::builder::Builder::<DOMAIN, B>::append_stream_frame(
                    &mut frames,
                    payload_limit,
                    record.stream_id,
                    record.offset,
                    record.fin,
                    stream,
                    len_usize,
                ) {
                    break;
                }
                commit.push_stream_delivery(commit::Delivery {
                    record,
                    tracked: Some(handle),
                });
                commit.properties.ack_eliciting = true;
            }
            let transmit = &mut self.packet.connection.streams.state.transmit;
            let mut idx = 0;
            while track_delivery
                && idx < transmit.scratch_pending.len()
                && !commit.streams.is_full()
                && transmit.deliveries.has_room(
                    commit
                        .streams
                        .as_slice()
                        .iter()
                        .filter(|delivery| delivery.tracked.is_none())
                        .count()
                        + 1,
                )
            {
                let handle = transmit.scratch_pending[idx];
                let Some((id, entry)) = transmit.map.resolve_mut(handle) else {
                    idx += 1;
                    continue;
                };
                let stream_limit = entry.credit.limit();
                let stream = &entry.stream;
                let stream_budget = stream_limit.saturating_sub(stream.next_offset());
                let packet_fresh_bytes = commit
                    .streams
                    .as_slice()
                    .iter()
                    .filter(|delivery| delivery.tracked.is_none())
                    .map(|delivery| delivery.record.len)
                    .sum::<u64>();
                let conn_budget = transmit
                    .peer_data_credit
                    .limit()
                    .saturating_sub(transmit.peer_total_sent.saturating_add(packet_fresh_bytes));
                let flow_take = stream_budget.min(conn_budget);
                let fin_only = stream.unsent_len() == 0 && stream.would_fin(0);
                if flow_take == 0 && !fin_only {
                    let has_pending = stream.has_pending();
                    if conn_budget == 0
                        && !commit.controls.is_full()
                        && self
                            .packet
                            .connection
                            .control
                            .ready()
                            .data_blocked_sendable(&transmit.peer_data_credit)
                        && !commit.contains_control(delivery::Control::DataBlocked(
                            transmit.peer_data_credit.limit(),
                        ))
                    {
                        let record =
                            delivery::Control::DataBlocked(transmit.peer_data_credit.limit());
                        let handle = self
                            .packet
                            .connection
                            .control
                            .queue_data_blocked(&mut transmit.peer_data_credit);
                        if let Some(handle) = handle
                            && crate::conn::control::encode::Encoder::new(
                                &self.packet.connection.control,
                                &self.packet.connection.path,
                            )
                            .encode_blocked(
                                &mut frames,
                                payload_limit,
                                record,
                            )
                        {
                            commit.push_control_delivery(record, handle);
                            commit.properties.ack_eliciting = true;
                        }
                    }
                    if stream_budget == 0
                        && has_pending
                        && !commit.controls.is_full()
                        && self
                            .packet
                            .connection
                            .control
                            .ready()
                            .stream_data_blocked_sendable(&entry.credit, id)
                    {
                        let record = delivery::Control::StreamDataBlocked(id, stream_limit);
                        let handle = self
                            .packet
                            .connection
                            .control
                            .queue_stream_data_blocked(&mut entry.credit, id);
                        if let Some(handle) = handle
                            && crate::conn::control::encode::Encoder::new(
                                &self.packet.connection.control,
                                &self.packet.connection.path,
                            )
                            .encode_blocked(
                                &mut frames,
                                payload_limit,
                                record,
                            )
                        {
                            commit.push_control_delivery(record, handle);
                            commit.properties.ack_eliciting = true;
                        }
                    }
                    idx += 1;
                    continue;
                }
                let packet_room = payload_limit.saturating_sub(
                    frames
                        .len()
                        .saturating_add(crate::conn::STREAM_FRAME_OVERHEAD),
                );
                let take = flow_take.min(packet_room as u64) as usize;
                if take == 0 && !fin_only {
                    break;
                }
                if stream.blocked() {
                    idx += 1;
                    continue;
                }
                let offset = stream.next_offset();
                let n = take.min(stream.unsent_len());
                if n == 0 && !stream.would_fin(0) {
                    idx += 1;
                    continue;
                }
                let fin_now = stream.would_fin(n);
                if !crate::conn::transmit::builder::Builder::<DOMAIN, B>::append_stream_frame(
                    &mut frames,
                    payload_limit,
                    id,
                    offset,
                    fin_now,
                    stream,
                    n,
                ) {
                    break;
                }
                commit.push_stream(delivery::Stream {
                    stream_id: id,
                    offset,
                    len: n as u64,
                    fin: fin_now,
                });
                commit.properties.ack_eliciting = true;
                idx += 1;
            }
        }

        if frames.is_empty() {
            return None;
        }

        let seg = self
            .packet
            .connection
            .handshake
            .write_key(crate::conn::Epoch::Application)?
            .protect_short_in_place(
                frames.out_mut(),
                packet_start,
                payload_start,
                pn,
                pn_off,
                crate::conn::PN_LEN as usize,
            )
            .ok()?;

        commit.bytes = seg;
        commit.properties.in_flight = commit.properties.ack_eliciting;
        Some((seg, commit))
    }
}
