use std::time;

use crate::stream;
use crate::{conn, transport_params};

/// A read-only view of a connection for the lifetime of its borrow.
pub struct View<'conn, const DOMAIN: u8, B: stream::ReceiveBuffer = Vec<u8>> {
    connection: &'conn conn::session::Connection<DOMAIN, B>,
}

/// Borrowed view of the bounded local connection-ID set.
#[derive(Clone, Copy)]
pub struct LocalCids<'conn> {
    path: &'conn conn::path::Path,
}

impl<'conn> LocalCids<'conn> {
    pub fn values(self) -> impl Iterator<Item = &'conn [u8]> {
        self.path.local_cids().map(|(_, cid)| cid)
    }

    pub fn entries(self) -> impl Iterator<Item = (u64, &'conn [u8])> {
        self.path.local_cids()
    }
}

impl<'conn, const DOMAIN: u8, B: stream::ReceiveBuffer> View<'conn, DOMAIN, B> {
    pub(in crate::conn) fn new(connection: &'conn conn::session::Connection<DOMAIN, B>) -> Self {
        Self { connection }
    }

    pub fn state(&self) -> conn::State {
        self.connection.egress.state
    }

    pub fn is_handshaking(&self) -> bool {
        self.state() == conn::State::Handshaking
    }

    pub fn is_established(&self) -> bool {
        self.state() == conn::State::Established
    }

    pub fn is_closed(&self) -> bool {
        self.state() == conn::State::Closed
    }

    pub fn was_stateless_reset(&self) -> bool {
        self.connection.path.was_stateless_reset()
    }

    pub fn path_validated(&self, token: &[u8; 8]) -> bool {
        self.connection.path.validated_tokens.contains(token)
    }

    pub fn path_mtu(&self) -> u64 {
        self.connection.egress.pmtud.current()
    }

    pub fn next_timer(&self) -> Option<time::Instant> {
        let timer = conn::recovery::timer::Timer::new(self.connection);
        timer.next_deadline()
    }

    pub fn next_send_time(&self) -> time::Instant {
        self.connection.egress.pacer.next_release_time()
    }

    pub fn local_cids(&self) -> LocalCids<'conn> {
        LocalCids {
            path: &self.connection.path,
        }
    }

    pub fn peer_transport_params(&self) -> Option<&'conn transport_params::Params> {
        self.connection.peer_transport_params.as_ref()
    }

    pub fn handshake_confirmed(&self) -> bool {
        self.connection.egress.handshake_confirmed
    }

    pub fn peer_address_validated(&self) -> bool {
        self.connection.egress.peer_address_validated
    }

    pub fn amplification_received(&self) -> u64 {
        self.connection.egress.amplification_received
    }

    pub fn congestion_window(&self) -> u64 {
        self.connection.egress.cc.cwnd
    }

    pub fn bytes_in_flight(&self) -> u64 {
        self.connection.egress.cc.bytes_in_flight
    }

    pub fn slow_start_threshold(&self) -> u64 {
        self.connection.egress.cc.ssthresh
    }

    pub fn unacked_count(&self, epoch_index: usize) -> usize {
        self.connection
            .egress
            .packet_journals
            .count_epoch(conn::Epoch::from_index(epoch_index))
    }

    pub fn smoothed_rtt(&self) -> Option<time::Duration> {
        self.connection.egress.rtt.smoothed_rtt
    }

    pub fn min_rtt(&self) -> Option<time::Duration> {
        self.connection.egress.rtt.min_rtt
    }
}
