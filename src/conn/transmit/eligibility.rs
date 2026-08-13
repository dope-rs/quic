use std::time::Instant;

use crate::conn::{Connection, Epoch, State, datagram, packet, recovery};
use crate::stream::ReceiveBuffer;

use super::Emission;

pub(super) trait Eligibility {
    fn has_initial_crypto(&self) -> bool;
    fn has_handshake_crypto(&self) -> bool;
    fn allows_emit_for(&self, cargo: packet::Cargo, now: Instant) -> bool;
}

impl<const DOMAIN: u8, B: ReceiveBuffer> Eligibility for Emission<'_, DOMAIN, B> {
    fn has_initial_crypto(&self) -> bool {
        self.connection
            .handshake
            .crypto()
            .has_sendable(Epoch::Initial)
    }

    fn has_handshake_crypto(&self) -> bool {
        self.connection
            .handshake
            .crypto()
            .has_sendable(Epoch::Handshake)
    }

    fn allows_emit_for(&self, cargo: packet::Cargo, now: Instant) -> bool {
        if !anti_amplification_allows(self.connection) {
            return false;
        }
        match cargo {
            packet::Cargo::CryptoOrAck => {
                self.connection.egress.cc.allows_send()
                    && self.connection.egress.pacer.allows_send(now)
            }
            packet::Cargo::DatagramOnly => match self.connection.egress.datagram_congestion_control
            {
                datagram::CongestionControl::Standard => {
                    self.connection.egress.cc.allows_send()
                        && self.connection.egress.pacer.allows_send(now)
                }
                datagram::CongestionControl::Uncongested => true,
            },
        }
    }
}

pub(crate) fn has_pending_output<const DOMAIN: u8, B: ReceiveBuffer>(
    connection: &Connection<DOMAIN, B>,
) -> bool {
    if connection.egress.state == State::Closed {
        return false;
    }
    if connection.egress.pto_probe_allowance != 0 {
        return true;
    }
    if connection.handshake.write_key(Epoch::Initial).is_some()
        && (super::has_crypto(connection, Epoch::Initial)
            || connection.received[Epoch::Initial as usize].ack_pending)
    {
        return true;
    }
    if connection.handshake.zero_rtt_write_key().is_some()
        && connection.handshake.write_key(Epoch::Application).is_none()
        && !connection.streams.transmit.schedule.is_empty()
    {
        return true;
    }
    if connection.handshake.write_key(Epoch::Handshake).is_some()
        && (super::has_crypto(connection, Epoch::Handshake)
            || connection.received[Epoch::Handshake as usize].ack_pending)
    {
        return true;
    }
    connection.handshake.write_key(Epoch::Application).is_some()
        && (connection.egress.pending_close.is_some()
            || connection.control.overflowed()
            || connection.received[Epoch::Application as usize].ack_pending
            || !connection.egress.pending_datagrams.is_empty()
            || connection.egress.derived_controls.is_pending()
            || connection.path.controls_pending()
            || connection.streams.state.receive_controls_pending()
            || !connection.control.is_empty()
            || connection
                .handshake
                .crypto()
                .has_sendable(Epoch::Application)
            || connection.streams.transmit.deliveries.has_retransmit()
            || !connection.streams.transmit.schedule.is_empty()
            || connection.egress.pmtud.next_probe().is_some())
}

fn has_sendable_stream<const DOMAIN: u8, B: ReceiveBuffer>(
    connection: &Connection<DOMAIN, B>,
) -> bool {
    if connection.streams.transmit.deliveries.has_retransmit() {
        return true;
    }
    let connection_budget = connection
        .streams
        .transmit
        .peer_data_credit
        .limit()
        .saturating_sub(connection.streams.transmit.peer_total_sent);
    connection
        .streams
        .transmit
        .schedule
        .iter(&connection.streams.transmit.map)
        .any(|handle| {
            let Some((stream_id, entry)) = connection.streams.transmit.map.resolve(handle) else {
                return false;
            };
            if entry.has_deferred_reset() {
                return connection.control.remaining_capacity() != 0;
            }
            let stream = &entry.stream;
            if !stream.has_pending() || stream.blocked() {
                return false;
            }
            if stream.unsent_len() == 0 && stream.would_fin(0) {
                return true;
            }
            let stream_limit = entry.credit.limit();
            let stream_budget = stream_limit.saturating_sub(stream.next_offset());
            (connection_budget != 0 && stream_budget != 0)
                || (connection_budget == 0
                    && connection
                        .control
                        .data_blocked_sendable(&connection.streams.transmit.peer_data_credit))
                || (stream_budget == 0
                    && connection
                        .control
                        .stream_data_blocked_sendable(&entry.credit, stream_id))
        })
}

fn has_sendable_output<const DOMAIN: u8, B: ReceiveBuffer>(
    connection: &Connection<DOMAIN, B>,
) -> bool {
    connection.egress.pto_probe_allowance != 0
        || (connection.handshake.write_key(Epoch::Initial).is_some()
            && (super::has_crypto(connection, Epoch::Initial)
                || connection.received[Epoch::Initial as usize].ack_pending))
        || (connection.handshake.zero_rtt_write_key().is_some()
            && connection.handshake.write_key(Epoch::Application).is_none()
            && has_sendable_stream(connection))
        || (connection.handshake.write_key(Epoch::Handshake).is_some()
            && (super::has_crypto(connection, Epoch::Handshake)
                || connection.received[Epoch::Handshake as usize].ack_pending))
        || (connection.handshake.write_key(Epoch::Application).is_some()
            && (connection.egress.pending_close.is_some()
                || connection.control.overflowed()
                || connection.received[Epoch::Application as usize].ack_pending
                || !connection.egress.pending_datagrams.is_empty()
                || connection
                    .egress
                    .derived_controls
                    .is_sendable(&connection.path, &connection.control)
                || connection.path.controls_sendable(&connection.control)
                || connection
                    .streams
                    .state
                    .receive_controls_sendable(&connection.control)
                || connection.control.has_sendable()
                || connection
                    .handshake
                    .crypto()
                    .has_sendable(Epoch::Application)
                || has_sendable_stream(connection)
                || connection.egress.pmtud.next_probe().is_some()))
}

pub(crate) fn send_deadline<const DOMAIN: u8, B: ReceiveBuffer>(
    connection: &Connection<DOMAIN, B>,
    now: Instant,
) -> Option<Instant> {
    if !has_pending_output(connection) {
        return None;
    }
    if connection.egress.pto_probe_allowance != 0 {
        return anti_amplification_allows(connection).then_some(now);
    }
    if !has_sendable_output(connection) {
        return recovery::timer::Timer::new(connection).next_deadline();
    }
    if !connection.egress.pending_datagrams.is_empty()
        && connection.egress.datagram_congestion_control == datagram::CongestionControl::Uncongested
    {
        return Some(now);
    }
    if !anti_amplification_allows(connection) || !connection.egress.cc.allows_send() {
        return recovery::timer::Timer::new(connection).next_deadline();
    }
    Some(connection.egress.pacer.next_release_time().max(now))
}

pub(super) fn anti_amplification_allows<const DOMAIN: u8, B: ReceiveBuffer>(
    connection: &Connection<DOMAIN, B>,
) -> bool {
    connection.egress.peer_address_validated || anti_amplification_remaining(connection) != 0
}

fn anti_amplification_remaining<const DOMAIN: u8, B: ReceiveBuffer>(
    connection: &Connection<DOMAIN, B>,
) -> u64 {
    if connection.egress.peer_address_validated {
        return u64::MAX;
    }
    connection
        .egress
        .amplification_received
        .saturating_mul(3)
        .saturating_sub(connection.egress.amplification_sent)
}

pub(super) fn emission_ceiling<const DOMAIN: u8, B: ReceiveBuffer>(
    connection: &Connection<DOMAIN, B>,
    requested: usize,
) -> Option<usize> {
    let remaining = usize::try_from(anti_amplification_remaining(connection)).unwrap_or(usize::MAX);
    let ceiling = requested.min(remaining);
    (ceiling != 0).then_some(ceiling)
}
