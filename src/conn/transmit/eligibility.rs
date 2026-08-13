use std::time;

use crate::conn;
use crate::conn::datagram;
use crate::conn::packet;
use crate::conn::recovery;
use crate::stream;

pub(crate) struct Eligibility<'connection, const DOMAIN: u8, B: stream::ReceiveBuffer> {
    connection: &'connection crate::conn::session::Connection<DOMAIN, B>,
}

impl<const DOMAIN: u8, B: stream::ReceiveBuffer> Eligibility<'_, DOMAIN, B> {
    pub(crate) fn new(
        connection: &crate::conn::session::Connection<DOMAIN, B>,
    ) -> Eligibility<'_, DOMAIN, B> {
        Eligibility { connection }
    }

    pub(crate) fn has_initial_crypto(&self) -> bool {
        self.connection
            .handshake
            .crypto()
            .has_sendable(conn::Epoch::Initial)
    }

    pub(crate) fn has_handshake_crypto(&self) -> bool {
        self.connection
            .handshake
            .crypto()
            .has_sendable(conn::Epoch::Handshake)
    }

    pub(in crate::conn) fn allows_emit_for(
        &self,
        cargo: packet::Cargo,
        now: time::Instant,
    ) -> bool {
        if !self.anti_amplification_allows() {
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

    pub(crate) fn has_pending_output(&self) -> bool {
        let connection = self.connection;
        if connection.egress.state == crate::conn::State::Closed {
            return false;
        }
        if connection.egress.pto_probe_allowance != 0 {
            return true;
        }
        if connection
            .handshake
            .write_key(conn::Epoch::Initial)
            .is_some()
            && (self.has_crypto(conn::Epoch::Initial)
                || connection.received[conn::Epoch::Initial as usize].ack_pending)
        {
            return true;
        }
        if connection.handshake.zero_rtt_write_key().is_some()
            && connection
                .handshake
                .write_key(conn::Epoch::Application)
                .is_none()
            && !connection.streams.transmit.schedule.is_empty()
        {
            return true;
        }
        if connection
            .handshake
            .write_key(conn::Epoch::Handshake)
            .is_some()
            && (self.has_crypto(conn::Epoch::Handshake)
                || connection.received[conn::Epoch::Handshake as usize].ack_pending)
        {
            return true;
        }
        connection
            .handshake
            .write_key(conn::Epoch::Application)
            .is_some()
            && (connection.egress.pending_close.is_some()
                || connection.control.overflowed()
                || connection.received[conn::Epoch::Application as usize].ack_pending
                || !connection.egress.pending_datagrams.is_empty()
                || connection.egress.derived_controls.is_pending()
                || connection.path.controls_pending()
                || connection.streams.state.receive_controls_pending()
                || !connection.control.is_empty()
                || connection
                    .handshake
                    .crypto()
                    .has_sendable(conn::Epoch::Application)
                || connection.streams.transmit.deliveries.has_retransmit()
                || !connection.streams.transmit.schedule.is_empty()
                || connection.egress.pmtud.next_probe().is_some())
    }

    fn has_sendable_stream(&self) -> bool {
        let connection = self.connection;
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
                let Some((stream_id, entry)) = connection.streams.transmit.map.resolve(handle)
                else {
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

    fn has_sendable_output(&self) -> bool {
        let connection = self.connection;
        connection.egress.pto_probe_allowance != 0
            || (connection
                .handshake
                .write_key(conn::Epoch::Initial)
                .is_some()
                && (self.has_crypto(conn::Epoch::Initial)
                    || connection.received[conn::Epoch::Initial as usize].ack_pending))
            || (connection.handshake.zero_rtt_write_key().is_some()
                && connection
                    .handshake
                    .write_key(conn::Epoch::Application)
                    .is_none()
                && self.has_sendable_stream())
            || (connection
                .handshake
                .write_key(conn::Epoch::Handshake)
                .is_some()
                && (self.has_crypto(conn::Epoch::Handshake)
                    || connection.received[conn::Epoch::Handshake as usize].ack_pending))
            || (connection
                .handshake
                .write_key(conn::Epoch::Application)
                .is_some()
                && (connection.egress.pending_close.is_some()
                    || connection.control.overflowed()
                    || connection.received[conn::Epoch::Application as usize].ack_pending
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
                        .has_sendable(conn::Epoch::Application)
                    || self.has_sendable_stream()
                    || connection.egress.pmtud.next_probe().is_some()))
    }

    pub(crate) fn send_deadline(&self, now: time::Instant) -> Option<time::Instant> {
        let connection = self.connection;
        if !self.has_pending_output() {
            return None;
        }
        if connection.egress.pto_probe_allowance != 0 {
            return self.anti_amplification_allows().then_some(now);
        }
        if !self.has_sendable_output() {
            return recovery::timer::Timer::new(connection).next_deadline();
        }
        if !connection.egress.pending_datagrams.is_empty()
            && connection.egress.datagram_congestion_control
                == datagram::CongestionControl::Uncongested
        {
            return Some(now);
        }
        if !self.anti_amplification_allows() || !connection.egress.cc.allows_send() {
            return recovery::timer::Timer::new(connection).next_deadline();
        }
        Some(connection.egress.pacer.next_release_time().max(now))
    }

    pub(crate) fn anti_amplification_allows(&self) -> bool {
        self.connection.egress.peer_address_validated || self.anti_amplification_remaining() != 0
    }

    fn anti_amplification_remaining(&self) -> u64 {
        let connection = self.connection;
        if connection.egress.peer_address_validated {
            return u64::MAX;
        }
        connection
            .egress
            .amplification_received
            .saturating_mul(3)
            .saturating_sub(connection.egress.amplification_sent)
    }

    pub(crate) fn emission_ceiling(&self, requested: usize) -> Option<usize> {
        let remaining = self.anti_amplification_remaining();
        let ceiling = if remaining < requested as u64 {
            remaining as usize
        } else {
            requested
        };
        (ceiling != 0).then_some(ceiling)
    }

    fn has_crypto(&self, epoch: conn::Epoch) -> bool {
        self.connection.handshake.crypto().has_sendable(epoch)
    }
}
