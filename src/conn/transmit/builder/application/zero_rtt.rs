use crate::conn::commit;
use crate::conn::delivery;

use crate::stream;

use crate::conn::transmit::builder::application;

pub(in crate::conn::transmit) trait BuildZeroRtt {
    fn build_zero_rtt(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
        pto_probe: bool,
    ) -> Option<(usize, commit::Packet)>;
}

impl<const DOMAIN: u8, B: stream::ReceiveBuffer> BuildZeroRtt
    for application::Application<'_, DOMAIN, B>
{
    fn build_zero_rtt(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
        pto_probe: bool,
    ) -> Option<(usize, commit::Packet)> {
        self.packet.connection.handshake.zero_rtt_write_key()?;
        if !(if pto_probe {
            self.packet.can_track_probe(crate::conn::Epoch::Application)
        } else {
            self.packet.can_track_packet()
        }) {
            return None;
        }
        let payload_limit = self.packet.handshake_payload_limit(max_packet_bytes);
        let pn = self.packet.connection.egress.recovery.spaces
            [crate::conn::Epoch::Application as usize]
            .next_pn;
        let mut frames = std::mem::take(&mut self.packet.connection.scratch.frames);
        frames.clear();
        let mut commit = commit::Packet::new(crate::conn::Epoch::Application, pn);
        commit.properties.early_data = true;
        if pto_probe {
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
                    self.packet.connection.scratch.frames = frames;
                    return None;
                }
                commit.properties.ack_eliciting = true;
            }
            commit.properties.pto_probe = true;
        }
        let mut packet_fresh_bytes = 0u64;
        for index in 0..if pto_probe {
            0
        } else {
            self.packet
                .connection
                .streams
                .transmit
                .scratch_pending
                .len()
        } {
            if commit.streams.is_full()
                || !self.packet.connection.streams.transmit.deliveries.has_room(
                    commit
                        .streams
                        .as_slice()
                        .iter()
                        .filter(|delivery| delivery.tracked.is_none())
                        .count()
                        + 1,
                )
            {
                break;
            }
            let handle = self.packet.connection.streams.transmit.scratch_pending[index];
            let Some((id, entry)) = self.packet.connection.streams.transmit.map.resolve(handle)
            else {
                continue;
            };
            let stream_limit = entry.credit.limit();
            let stream = &entry.stream;
            let stream_budget = stream_limit.saturating_sub(stream.next_offset());
            let conn_budget = self
                .packet
                .connection
                .peer
                .transport_params
                .as_ref()
                .map_or(u64::MAX, |_| {
                    self.packet
                        .connection
                        .streams
                        .transmit
                        .peer_data_credit
                        .limit()
                        .saturating_sub(
                            self.packet
                                .connection
                                .streams
                                .transmit
                                .peer_total_sent
                                .saturating_add(packet_fresh_bytes),
                        )
                });
            let packet_room = payload_limit.saturating_sub(
                frames
                    .len()
                    .saturating_add(crate::conn::STREAM_FRAME_OVERHEAD),
            );
            let take = stream_budget.min(conn_budget).min(packet_room as u64) as usize;
            let fin_only = stream.unsent_len() == 0 && stream.would_fin(0);
            if take == 0 && !fin_only {
                continue;
            }
            if stream.blocked() {
                continue;
            }
            let offset = stream.next_offset();
            let n = take.min(stream.unsent_len());
            if n == 0 && !stream.would_fin(0) {
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
            packet_fresh_bytes = packet_fresh_bytes.saturating_add(n as u64);
            commit.properties.ack_eliciting = true;
            if payload_limit.saturating_sub(frames.len()) <= crate::conn::STREAM_FRAME_OVERHEAD {
                break;
            }
        }
        if frames.is_empty() {
            self.packet.connection.scratch.frames = frames;
            return None;
        }
        let body_len_after_pn = frames.len() + crate::conn::TAG_LEN;
        let mut header = std::mem::take(&mut self.packet.connection.scratch.header);
        header.clear();
        let pn_off = crate::packet::LongHeader {
            version: crate::packet::QUIC_V1,
            packet_type: crate::packet::LONG_ZERO_RTT,
            dcid: self.packet.connection.path.peer_cid(),
            scid: self.packet.connection.path.local_cid(),
            token: None,
            packet_number: pn,
            packet_number_len: crate::conn::PN_LEN,
        }
        .encode_into(&mut header, body_len_after_pn)
        .ok()?;
        let n = self
            .packet
            .connection
            .handshake
            .zero_rtt_write_key()?
            .encrypt_long_into(
                dst,
                &header,
                &frames,
                pn,
                pn_off,
                crate::conn::PN_LEN as usize,
            )
            .ok()?;
        header.clear();
        self.packet.connection.scratch.header = header;
        frames.clear();
        self.packet.connection.scratch.frames = frames;
        commit.bytes = n;
        commit.properties.in_flight = true;
        Some((n, commit))
    }
}
