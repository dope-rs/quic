use std::{collections, time};

use shin::{client, crypto, wire};

use crate::conn;
use crate::stream;
use crate::transport_params;

pub(in crate::conn) struct ReceiveState<B: stream::ReceiveBuffer> {
    pub(in crate::conn) packet_numbers: [crate::pn_space::Receive; 3],
    pub(in crate::conn) crypto: [conn::reassembly::Crypto; 3],
    pub(in crate::conn) datagrams: collections::VecDeque<B>,
    pub(in crate::conn) datagram_capacity: usize,
}

pub(in crate::conn) struct Scratch {
    pub(in crate::conn) frames: Vec<u8>,
    pub(in crate::conn) header: Vec<u8>,
}

pub(in crate::conn) struct PeerState {
    pub(in crate::conn) is_client: bool,
    pub(in crate::conn) transport_params: Option<transport_params::Params>,
    pub(in crate::conn) local_max_idle_timeout: time::Duration,
}

pub struct Connection<const DOMAIN: u8 = 0, B: stream::ReceiveBuffer = Vec<u8>> {
    pub(in crate::conn) egress: conn::egress::Egress,
    pub(in crate::conn) control: conn::control::Pending,
    pub(in crate::conn) handshake: conn::handshake::Handshake<DOMAIN>,
    pub(in crate::conn) path: conn::path::Path,
    pub(in crate::conn) streams: conn::streams::Streams<B>,
    pub(in crate::conn) receive: ReceiveState<B>,
    pub(in crate::conn) scratch: Scratch,
    pub(in crate::conn) peer: PeerState,
}

impl<const DOMAIN: u8, B: stream::ReceiveBuffer> Connection<DOMAIN, B> {
    pub(crate) fn is_client(&self) -> bool {
        self.peer.is_client
    }

    /// Receives and decrypts one datagram in place.
    ///
    /// The contents of `wire` are unspecified after this call.
    pub fn recv_packet(
        &mut self,
        workspace: &mut conn::ReceiveWorkspace,
        wire: &mut [u8],
        now: time::Instant,
    ) -> Result<(), conn::Error> {
        if wire.is_empty() {
            return Ok(());
        }
        conn::ingress::Ingress::new(self, workspace).recv_client(wire, now)
    }

    pub(crate) fn try_receive_stateless_reset_token(
        &mut self,
        token: conn::path::StatelessResetToken,
    ) -> bool {
        if self.egress.lifecycle.state != conn::State::Established
            || !self.path.matches_reset(token)
        {
            return false;
        }
        self.egress.lifecycle.state = conn::State::Closed;
        self.path.mark_stateless_reset();
        true
    }

    pub(crate) fn peer_stateless_reset_tokens(
        &self,
    ) -> impl Iterator<Item = conn::path::StatelessResetToken> + '_ {
        self.path.peer_reset_tokens()
    }

    pub fn send_path_challenge(&mut self, data: [u8; 8]) {
        if self.egress.lifecycle.state == conn::State::Established {
            self.path.queue_challenge(data);
        }
    }

    pub fn streams(&mut self) -> conn::stream::Streams<'_, DOMAIN, B> {
        conn::stream::Streams::new(self)
    }

    pub fn stream_state(&self) -> conn::stream::View<'_, DOMAIN, B> {
        conn::stream::View::new(self)
    }

    pub fn stream_events(&mut self) -> conn::stream::Events<'_, DOMAIN, B> {
        conn::stream::Events::new(self)
    }

    pub fn take_session_tickets(&mut self) -> Vec<Ticket> {
        self.handshake.take_session_tickets()
    }

    pub(crate) fn enable_cid_routing(
        &mut self,
    ) -> (conn::path::LocalCidKey, crate::packet::ConnectionId) {
        self.path.enable_cid_routing()
    }

    pub(crate) fn take_cid_route_updates(&mut self) -> conn::path::RouteUpdates {
        self.path.take_route_updates()
    }

    pub fn datagrams(&mut self) -> conn::datagram::Datagrams<'_, DOMAIN, B> {
        conn::datagram::Datagrams::new(self)
    }

    pub fn transmit(&mut self) -> conn::transmit::Emission<'_, DOMAIN, B> {
        conn::transmit::Emission::new(self)
    }

    pub fn status(&self) -> conn::status::View<'_, DOMAIN, B> {
        conn::status::View::new(self)
    }

    pub fn close(&mut self, error_code: u64, reason: Vec<u8>) {
        if self.egress.lifecycle.state != conn::State::Closed
            && self.egress.lifecycle.pending_close.is_none()
        {
            self.egress.lifecycle.pending_close = Some(conn::egress::PendingClose {
                is_application: true,
                error_code,
                frame_type: 0,
                reason,
            });
        }
    }
}

impl<const DOMAIN: u8, B: stream::ReceiveBuffer> conn::handshake::Transition
    for Connection<DOMAIN, B>
{
    fn reject_early_data(&mut self) {
        let early_data = conn::recovery::early::EarlyData::new(
            &mut self.egress,
            &mut self.control,
            &mut self.handshake,
            &mut self.streams.state,
            &mut self.streams.events,
            self.peer.is_client,
        );
        early_data.reject();
    }

    fn establish(&mut self) -> Result<(), conn::Error> {
        conn::handshake::Establishment {
            egress: &mut self.egress,
            handshake: &mut self.handshake,
            path: &mut self.path,
            streams: &mut self.streams.state,
            peer_transport_params: &mut self.peer.transport_params,
            is_client: self.peer.is_client,
        }
        .complete()
    }

    fn close(&mut self) {
        self.egress.lifecycle.state = conn::State::Closed;
    }
}

#[derive(Debug)]
pub struct Ticket {
    pub ticket_lifetime: u32,
    pub ticket_age_add: u32,
    pub received_at_ms: u64,
    pub ticket: Vec<u8>,
    pub psk: crypto::material::ResumptionPsk,
    pub max_early_data: Option<u32>,
    pub cipher_suite: wire::record::CipherSuite,
    pub alpn: Option<Vec<u8>>,
}

impl Ticket {
    /// Moves persisted ticket material into the new connection's validated
    /// endpoint template. The opaque ticket and PSK are not copied.
    pub(crate) fn into_restore(
        self,
    ) -> Result<client::config::Restore<'static>, client::config::Error> {
        use std::borrow::Cow;

        use client::config::{NegotiatedAlpn, Restore};
        use shin::transport::Mode;

        let restore = Restore::try_new(
            self.psk,
            self.ticket,
            self.ticket_age_add,
            self.received_at_ms,
            self.ticket_lifetime,
        )?;
        match self.max_early_data {
            Some(maximum) => restore.try_with_early_data(
                maximum,
                self.cipher_suite,
                Mode::Quic,
                match self.alpn {
                    Some(protocol) => NegotiatedAlpn::Protocol(Cow::Owned(protocol)),
                    None => NegotiatedAlpn::Absent,
                },
            ),
            None => Ok(restore),
        }
    }
}
