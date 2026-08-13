use std::time;

use crate::stream;
use crate::{conn, pmtud};

pub(super) mod builder;
pub(crate) mod eligibility;
mod transaction;

use builder::application::datagram::BuildDatagram as _;
use builder::application::one_rtt::BuildOneRtt as _;
use builder::application::terminal::BuildTerminal as _;
use builder::application::zero_rtt::BuildZeroRtt as _;

pub struct Emission<'a, const DOMAIN: u8, B: stream::ReceiveBuffer = Vec<u8>> {
    connection: &'a mut conn::session::Connection<DOMAIN, B>,
}

impl<'a, const DOMAIN: u8, B: stream::ReceiveBuffer> Emission<'a, DOMAIN, B> {
    pub(in crate::conn) fn new(connection: &'a mut conn::session::Connection<DOMAIN, B>) -> Self {
        Self { connection }
    }

    pub fn send(&mut self, now: time::Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(
            self.connection
                .egress
                .pending_datagrams
                .len()
                .min(conn::MAX_BATCH_PACKETS),
        );
        self.fill_batch(
            &mut out,
            now,
            conn::MAX_BATCH_PACKETS,
            pmtud::MAX_PMTU as usize,
        );
        out
    }

    pub fn send_batch(
        &mut self,
        batch: &mut conn::packet::Batch,
        now: time::Instant,
        max_packets: usize,
        max_packet_bytes: usize,
    ) {
        self.send_into_batch(batch, now, max_packets, max_packet_bytes);
    }

    pub(crate) fn send_gso_batch(
        &mut self,
        batch: &mut conn::packet::Gso,
        now: time::Instant,
        max_packets: usize,
        max_packet_bytes: usize,
    ) {
        self.send_into_batch(batch, now, max_packets, max_packet_bytes);
    }

    fn send_into_batch(
        &mut self,
        batch: &mut impl conn::packet::Sink,
        now: time::Instant,
        max_packets: usize,
        max_packet_bytes: usize,
    ) {
        let packet_bytes = max_packet_bytes.min(self.connection.egress.pmtud.current() as usize);
        let packet_slots = max_packets.min(conn::MAX_BATCH_PACKETS);
        batch.reset(packet_slots, packet_bytes);
        let probe_aware_packet_ceiling = max_packet_bytes;
        self.fill_batch(batch, now, packet_slots, probe_aware_packet_ceiling);
    }

    pub(crate) fn send_one(
        &mut self,
        packet: &mut Vec<u8>,
        now: time::Instant,
        max_packet_bytes: usize,
    ) -> bool {
        let mut sink = conn::packet::Slot {
            packet,
            emitted: false,
        };
        self.fill_batch(&mut sink, now, 1, max_packet_bytes);
        sink.emitted
    }

    fn snapshot_pending_streams(&mut self, control_work: usize) {
        let conn::streams::Streams {
            state:
                conn::streams::State {
                    transmit:
                        conn::streams::TransmitState {
                            scratch_pending,
                            schedule,
                            map,
                            ..
                        },
                    ..
                },
            ..
        } = &mut self.connection.streams;
        schedule.snapshot(
            map,
            scratch_pending,
            &mut self.connection.control,
            control_work,
        );
    }

    fn has_only_uncongested_datagrams(&self) -> bool {
        self.connection
            .handshake
            .write_key(conn::Epoch::Application)
            .is_some()
            && self.connection.egress.datagram_congestion_control
                == conn::datagram::CongestionControl::Uncongested
            && !self.connection.egress.pending_datagrams.is_empty()
            && self.connection.egress.pto_probe_allowance == 0
            && self.connection.egress.pending_close.is_none()
            && (!eligibility::Eligibility::new(self.connection).has_initial_crypto()
                && !self.connection.received[conn::Epoch::Initial as usize].ack_pending)
            && (!eligibility::Eligibility::new(self.connection).has_handshake_crypto()
                && !self.connection.received[conn::Epoch::Handshake as usize].ack_pending)
            && self.connection.control.is_empty()
            && !self.connection.path.controls_pending()
            && !self
                .connection
                .handshake
                .crypto()
                .has_sendable(conn::Epoch::Application)
            && !self.connection.streams.transmit.deliveries.has_retransmit()
            && self.connection.streams.transmit.schedule.is_empty()
            && self.connection.egress.pmtud.next_probe().is_none()
    }

    fn emit_pending_datagrams<const FAST: bool, S: conn::packet::Sink>(
        &mut self,
        sink: &mut S,
        now: time::Instant,
        remaining: &mut usize,
        packet_bytes: usize,
    ) -> bool {
        while *remaining != 0 && !self.connection.egress.pending_datagrams.is_empty() {
            let validated = self.connection.egress.peer_address_validated;
            if (FAST
                && !validated
                && !eligibility::Eligibility::new(self.connection).anti_amplification_allows())
                || (!FAST
                    && !eligibility::Eligibility::new(self.connection)
                        .allows_emit_for(conn::packet::Cargo::DatagramOnly, now))
            {
                break;
            }
            let packet_ceiling = if FAST && validated {
                packet_bytes
            } else {
                let Some(packet_ceiling) =
                    eligibility::Eligibility::new(self.connection).emission_ceiling(packet_bytes)
                else {
                    break;
                };
                packet_ceiling
            };
            let Some(commit) = sink.emit(packet_ceiling, |dst, packet_ceiling| {
                if S::FRESH_PACKETS {
                    let data = self.connection.egress.pending_datagrams.front()?;
                    dst.reserve(
                        1 + self.connection.path.peer_cid().len()
                            + conn::PN_LEN as usize
                            + 1
                            + data.len()
                            + conn::TAG_LEN,
                    );
                }
                builder::application::Application::new(self.connection)
                    .build_datagram(dst, packet_ceiling)
            }) else {
                break;
            };
            if !transaction::Transaction::new(self.connection).datagram(&commit, now) {
                return false;
            }
            *remaining -= 1;
        }
        true
    }

    fn fill_batch<S: conn::packet::Sink>(
        &mut self,
        sink: &mut S,
        now: time::Instant,
        max_packets: usize,
        max_packet_bytes: usize,
    ) {
        if self.connection.control.take_overflowed()
            && self.connection.egress.pending_close.is_none()
        {
            self.connection.egress.pending_close = Some(conn::egress::PendingClose {
                is_application: false,
                error_code: conn::INTERNAL_ERROR,
                frame_type: 0,
                reason: conn::CONTROL_CAPACITY_REASON.to_vec(),
            });
        }
        if self.connection.egress.state == conn::State::Closed {
            return;
        }
        self.connection
            .egress
            .derived_controls
            .reconcile(&mut self.connection.path, &mut self.connection.control);
        let control_work = max_packets
            .min(conn::MAX_BATCH_PACKETS)
            .saturating_mul(conn::PACKET_CONTROL_CAPACITY);
        self.connection
            .path
            .reconcile_controls(&mut self.connection.control, control_work);
        conn::streams::receive::ReceiveControlDrain::new(
            &mut self.connection.streams.state,
            &mut self.connection.control,
            control_work,
        )
        .drain();
        let normal_packet_bytes =
            max_packet_bytes.min(self.connection.egress.pmtud.current() as usize);
        let mut remaining = max_packets;
        if self.has_only_uncongested_datagrams() {
            self.emit_pending_datagrams::<true, S>(sink, now, &mut remaining, normal_packet_bytes);
            return;
        }
        let mut sent_handshake_packet = false;
        let mut sent_handshake_done = false;

        self.snapshot_pending_streams(control_work);

        while remaining != 0 && self.connection.egress.pto_probe_allowance != 0 {
            let Some(packet_ceiling) = eligibility::Eligibility::new(self.connection)
                .emission_ceiling(normal_packet_bytes)
            else {
                break;
            };
            let Some(commit) = sink.emit(packet_ceiling, |dst, packet_ceiling| {
                builder::Builder::new(self.connection).build_pto_probe(dst, packet_ceiling)
            }) else {
                break;
            };
            if !transaction::Transaction::new(self.connection).packet(&commit, now) {
                return;
            }
            remaining -= 1;
        }

        if self
            .connection
            .handshake
            .write_key(conn::Epoch::Initial)
            .is_some()
        {
            while remaining != 0 {
                if !eligibility::Eligibility::new(self.connection)
                    .allows_emit_for(conn::packet::Cargo::CryptoOrAck, now)
                {
                    break;
                }
                let has_crypto =
                    eligibility::Eligibility::new(self.connection).has_initial_crypto();
                let has_ack = self.connection.received[conn::Epoch::Initial as usize].ack_pending;
                if !has_crypto && !has_ack {
                    break;
                }
                let Some(packet_ceiling) = eligibility::Eligibility::new(self.connection)
                    .emission_ceiling(normal_packet_bytes)
                else {
                    break;
                };
                let Some(commit) = sink.emit(packet_ceiling, |dst, packet_ceiling| {
                    builder::Builder::new(self.connection).build_crypto_packet(
                        dst,
                        packet_ceiling,
                        conn::Epoch::Initial,
                        conn::packet::CryptoMode::Regular,
                    )
                }) else {
                    break;
                };
                if !transaction::Transaction::new(self.connection).packet(&commit, now) {
                    return;
                }
                remaining -= 1;
                self.connection.egress.sent_initial = true;
            }
        }

        if remaining != 0
            && self.connection.handshake.zero_rtt_write_key().is_some()
            && self
                .connection
                .handshake
                .write_key(conn::Epoch::Application)
                .is_none()
        {
            while remaining != 0
                && eligibility::Eligibility::new(self.connection)
                    .allows_emit_for(conn::packet::Cargo::CryptoOrAck, now)
            {
                let Some(packet_ceiling) = eligibility::Eligibility::new(self.connection)
                    .emission_ceiling(normal_packet_bytes)
                else {
                    break;
                };
                let Some(commit) = sink.emit(packet_ceiling, |dst, packet_ceiling| {
                    builder::application::Application::new(self.connection).build_zero_rtt(
                        dst,
                        packet_ceiling,
                        false,
                    )
                }) else {
                    break;
                };
                if !transaction::Transaction::new(self.connection).packet(&commit, now) {
                    return;
                }
                remaining -= 1;
            }
        }

        if self
            .connection
            .handshake
            .write_key(conn::Epoch::Handshake)
            .is_some()
        {
            while remaining != 0 {
                if !eligibility::Eligibility::new(self.connection)
                    .allows_emit_for(conn::packet::Cargo::CryptoOrAck, now)
                {
                    break;
                }
                let has_crypto =
                    eligibility::Eligibility::new(self.connection).has_handshake_crypto();
                let has_ack = self.connection.received[conn::Epoch::Handshake as usize].ack_pending;
                if !has_crypto && !has_ack {
                    break;
                }
                let Some(packet_ceiling) = eligibility::Eligibility::new(self.connection)
                    .emission_ceiling(normal_packet_bytes)
                else {
                    break;
                };
                let Some(commit) = sink.emit(packet_ceiling, |dst, packet_ceiling| {
                    builder::Builder::new(self.connection).build_crypto_packet(
                        dst,
                        packet_ceiling,
                        conn::Epoch::Handshake,
                        conn::packet::CryptoMode::Regular,
                    )
                }) else {
                    break;
                };
                if !transaction::Transaction::new(self.connection).packet(&commit, now) {
                    return;
                }
                remaining -= 1;
                sent_handshake_packet = true;
            }
        }

        if self
            .connection
            .handshake
            .write_key(conn::Epoch::Application)
            .is_some()
        {
            if remaining != 0 && self.connection.egress.pending_close.is_some() {
                let commit = eligibility::Eligibility::new(self.connection)
                    .emission_ceiling(normal_packet_bytes)
                    .and_then(|packet_ceiling| {
                        sink.emit(packet_ceiling, |dst, packet_ceiling| {
                            builder::application::Application::new(self.connection)
                                .build_one_rtt_close(dst, packet_ceiling)
                        })
                    });
                if let Some(commit) = commit {
                    if !transaction::Transaction::new(self.connection).packet(&commit, now) {
                        return;
                    }
                    return;
                }
            }

            for _ in 0..4096u32 {
                if remaining == 0 {
                    break;
                }
                let has_app_ack =
                    self.connection.received[conn::Epoch::Application as usize].ack_pending;
                let has_datagrams = !self.connection.egress.pending_datagrams.is_empty();
                let has_streams = !self.connection.streams.transmit.scratch_pending.is_empty();
                let has_lifecycle = self
                    .connection
                    .handshake
                    .crypto()
                    .has_sendable(conn::Epoch::Application)
                    || self.connection.streams.transmit.deliveries.has_retransmit();

                let one_shot = !self.connection.control.is_empty()
                    || has_lifecycle
                    || (has_app_ack && !has_datagrams);
                if (!one_shot && !has_streams)
                    || !eligibility::Eligibility::new(self.connection)
                        .allows_emit_for(conn::packet::Cargo::CryptoOrAck, now)
                {
                    break;
                }
                let before = self.connection.egress.cc.bytes_in_flight;
                let Some(packet_ceiling) = eligibility::Eligibility::new(self.connection)
                    .emission_ceiling(normal_packet_bytes)
                else {
                    break;
                };
                let Some(commit) = sink.emit(packet_ceiling, |dst, packet_ceiling| {
                    builder::application::Application::new(self.connection)
                        .build_one_rtt::<false>(dst, packet_ceiling)
                }) else {
                    break;
                };
                let did_handshake_done = commit
                    .controls
                    .as_slice()
                    .iter()
                    .any(|delivery| delivery.record == conn::delivery::Control::HandshakeDone);
                if !transaction::Transaction::new(self.connection).packet(&commit, now) {
                    return;
                }
                remaining -= 1;
                if did_handshake_done {
                    sent_handshake_done = true;
                }
                if !one_shot && self.connection.egress.cc.bytes_in_flight == before {
                    break;
                }
            }
            if !self.emit_pending_datagrams::<false, S>(
                sink,
                now,
                &mut remaining,
                normal_packet_bytes,
            ) {
                return;
            }
            if remaining != 0
                && let Some(probe_size) = self.connection.egress.pmtud.next_probe()
                && eligibility::Eligibility::new(self.connection)
                    .allows_emit_for(conn::packet::Cargo::CryptoOrAck, now)
            {
                let commit = eligibility::Eligibility::new(self.connection)
                    .emission_ceiling(max_packet_bytes)
                    .and_then(|packet_ceiling| {
                        sink.emit(packet_ceiling, |dst, packet_ceiling| {
                            builder::application::Application::new(self.connection)
                                .build_one_rtt_probe(dst, probe_size, packet_ceiling)
                        })
                    });
                if let Some(commit) = commit
                    && !transaction::Transaction::new(self.connection).packet(&commit, now)
                {
                    return;
                }
            }
        }

        if sent_handshake_packet
            && self
                .connection
                .handshake
                .write_key(conn::Epoch::Initial)
                .is_some()
        {
            conn::recovery::epochs::Epochs::new(self.connection).discard_initial();
        }
        if sent_handshake_done && !self.connection.is_client {
            conn::recovery::epochs::Epochs::new(self.connection).discard_handshake();
        }

        if !sink.is_empty() {
            conn::recovery::timer::Timer::update(&mut self.connection.egress);
        }
    }
}
