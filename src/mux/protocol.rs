use std::net;
use std::time;

use crate::conn;
use crate::pmtud;
use crate::stream;

use dope::manifold::datagram;

use crate::mux;
use crate::mux::drive::{DriveOps as _, QueueOps as _};
use crate::mux::routing::reset::ResetOps as _;
use crate::mux::routing::{AcceptOps as _, CidOps as _, DeadlineOps as _, SlotOps as _};
use crate::packet;

pub struct Io<'a, 'tls, H, P, const DOMAIN: u8, B: stream::ReceiveBuffer = Vec<u8>>
where
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
{
    mux: &'a mut mux::Router<'tls, H, P, DOMAIN, B>,
}

impl<
    'a,
    'tls,
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
    const DOMAIN: u8,
    B: stream::ReceiveBuffer,
> Io<'a, 'tls, H, P, DOMAIN, B>
{
    pub(super) fn new(mux: &'a mut mux::Router<'tls, H, P, DOMAIN, B>) -> Self {
        Self { mux }
    }

    pub fn connect(
        &mut self,
        peer_addr: net::SocketAddr,
        server_pubkey: [u8; 32],
        client_config: conn::config::Options,
        initial_dcid: Vec<u8>,
        now: time::Instant,
    ) -> Result<conn::Handle, crate::errors::ConnectFailure> {
        let initial_dcid = packet::ConnectionId::try_from(initial_dcid)
            .map_err(|_| crate::errors::ConnectFailure::InvalidConfig)?;
        self.connect_id(peer_addr, server_pubkey, client_config, initial_dcid, now)
    }

    pub(crate) fn connect_id(
        &mut self,
        peer_addr: net::SocketAddr,
        server_pubkey: [u8; 32],
        client_config: conn::config::Options,
        initial_dcid: packet::ConnectionId,
        now: time::Instant,
    ) -> Result<conn::Handle, crate::errors::ConnectFailure> {
        self.mux.sync_dirty_connection();
        if self.mux.lifecycle.shutting_down {
            return Err(crate::errors::ConnectFailure::Closed);
        }
        if self.mux.registry.active_conns >= self.mux.registry.max_conns {
            return Err(crate::errors::ConnectFailure::Capacity);
        }
        client_config.validate()?;
        let max_packet_bytes =
            super::setup::connection_ceiling(&client_config, self.mux.outgoing.bytes_capacity);
        if max_packet_bytes < pmtud::BASE_PMTU as usize {
            return Err(crate::errors::ConnectFailure::InvalidConfig);
        }
        let local_cid = self
            .mux
            .gen_cid(client_config.cid_prefix)
            .ok_or(crate::errors::ConnectFailure::Capacity)?;
        let conn = conn::setup::Client::<DOMAIN>::connect_buffer::<B>(
            initial_dcid,
            local_cid,
            server_pubkey,
            client_config,
        )?;
        let handle = self
            .mux
            .insert_connection(conn, None, peer_addr, max_packet_bytes)
            .ok_or(crate::errors::ConnectFailure::Capacity)?;
        let index = self
            .mux
            .handle_index(handle)
            .ok_or(crate::errors::ConnectFailure::Capacity)?;
        let (key, local_cid) = self.mux.registry.entries[index]
            .slot_mut()
            .ok_or(crate::errors::ConnectFailure::Capacity)?
            .conn
            .enable_cid_routing();
        if !self.mux.register_local_cid(handle, key, local_cid) {
            self.mux.remove_slot(handle);
            return Err(crate::errors::ConnectFailure::Capacity);
        }
        self.mux.schedule_flush(handle);
        self.mux.refresh_deadline(handle, now);
        Ok(handle)
    }

    /// Connects with externally owned, exactly reserved TLS storage. The
    /// resulting slot cannot outlive `pool` through the Mux's `'tls` lifetime.
    pub fn connect_pooled(
        &mut self,
        peer_addr: net::SocketAddr,
        pool: &'tls conn::tls::ClientPool,
        client_config: conn::config::Options,
        initial_dcid: Vec<u8>,
        now: time::Instant,
    ) -> Result<conn::Handle, crate::errors::ConnectFailure> {
        let initial_dcid = packet::ConnectionId::try_from(initial_dcid)
            .map_err(|_| crate::errors::ConnectFailure::InvalidConfig)?;
        self.connect_pooled_id(peer_addr, pool, client_config, initial_dcid, now)
    }

    pub(crate) fn connect_pooled_id(
        &mut self,
        peer_addr: net::SocketAddr,
        pool: &'tls conn::tls::ClientPool,
        client_config: conn::config::Options,
        initial_dcid: packet::ConnectionId,
        now: time::Instant,
    ) -> Result<conn::Handle, crate::errors::ConnectFailure> {
        self.mux.sync_dirty_connection();
        if self.mux.lifecycle.shutting_down {
            return Err(crate::errors::ConnectFailure::Closed);
        }
        if self.mux.registry.active_conns >= self.mux.registry.max_conns {
            return Err(crate::errors::ConnectFailure::Capacity);
        }
        client_config.validate()?;
        let max_packet_bytes =
            super::setup::connection_ceiling(&client_config, self.mux.outgoing.bytes_capacity);
        if max_packet_bytes < pmtud::BASE_PMTU as usize {
            return Err(crate::errors::ConnectFailure::InvalidConfig);
        }
        let local_cid = self
            .mux
            .gen_cid(client_config.cid_prefix)
            .ok_or(crate::errors::ConnectFailure::Capacity)?;
        let pooled = conn::setup::Client::<DOMAIN>::connect_pooled_buffer::<B>(
            initial_dcid,
            local_cid,
            pool,
            client_config,
        )?;
        let (connection, tls) = pooled.into_parts();
        let handle = self
            .mux
            .insert_connection(
                connection,
                Some(mux::TlsSession::Client(tls)),
                peer_addr,
                max_packet_bytes,
            )
            .ok_or(crate::errors::ConnectFailure::Capacity)?;
        let index = self
            .mux
            .handle_index(handle)
            .ok_or(crate::errors::ConnectFailure::Capacity)?;
        let (key, local_cid) = self.mux.registry.entries[index]
            .slot_mut()
            .ok_or(crate::errors::ConnectFailure::Capacity)?
            .conn
            .enable_cid_routing();
        if !self.mux.register_local_cid(handle, key, local_cid) {
            self.mux.remove_slot(handle);
            return Err(crate::errors::ConnectFailure::Capacity);
        }
        self.mux.schedule_flush(handle);
        self.mux.refresh_deadline(handle, now);
        Ok(handle)
    }

    /// Receives and decrypts one datagram in place.
    ///
    /// The contents of `data` are unspecified after this call.
    pub fn recv(
        &mut self,
        from: net::SocketAddr,
        data: &mut [u8],
        now: time::Instant,
    ) -> Result<(), conn::Error> {
        self.mux.sync_dirty_connection();
        if self.mux.lifecycle.shutting_down {
            return Ok(());
        }
        let dcid = super::setup::dcid(data, super::ROUTED_CID_LEN);
        let routed = match dcid.and_then(|value| self.mux.find_cid(value)) {
            Some(routed) => routed,
            None if super::setup::is_initial(data) && self.mux.server.is_some() => {
                if self.mux.registry.active_conns >= self.mux.registry.max_conns {
                    return Ok(());
                }
                match self.mux.maybe_handle_retry_gating(from, data)? {
                    mux::RetryGate::Accept(retry_odcid) => {
                        let handle = self.mux.try_accept(from, data, retry_odcid)?;
                        super::RoutedCid {
                            handle,
                            local: None,
                        }
                    }
                    mux::RetryGate::IssuedRetry | mux::RetryGate::Drop => return Ok(()),
                }
            }
            None => {
                if self.mux.receive_stateless_reset(from, data, now) {
                    return Ok(());
                }
                self.mux.emit_stateless_reset(from, data);
                return Ok(());
            }
        };
        let handle = routed.handle;
        let index = self
            .mux
            .handle_index(handle)
            .ok_or(conn::Error::HeaderDecode)?;
        let (received, routes) = {
            let (registry, workspace) = (&mut self.mux.registry, &mut self.mux.receive_workspace);
            let slot = registry.entries[index]
                .slot_mut()
                .ok_or(conn::Error::HeaderDecode)?;
            let received = match (slot.conn.is_client(), slot.tls.as_mut()) {
                (true, None) => {
                    conn::ingress::Ingress::routed(&mut slot.conn, workspace, routed.local)
                        .recv_client(data, now)
                }
                (true, Some(mux::TlsSession::Client(tls))) => {
                    conn::ingress::Ingress::routed(&mut slot.conn, workspace, routed.local)
                        .recv_client_pooled(data, now, tls)
                }
                (false, Some(mux::TlsSession::OwnedServer(tls))) => {
                    conn::ingress::Ingress::routed(&mut slot.conn, workspace, routed.local)
                        .recv_server(data, now, tls)
                }
                (false, Some(mux::TlsSession::Server(tls))) => {
                    conn::ingress::Ingress::routed(&mut slot.conn, workspace, routed.local)
                        .recv_server_pooled(data, now, tls)
                }
                (false, None) => {
                    conn::ingress::Ingress::routed(&mut slot.conn, workspace, routed.local)
                        .recv_finished(data, now)
                }
                _ => Err(conn::Error::HeaderDecode),
            };
            if slot.tls.as_ref().is_some_and(
                |tls| matches!(tls, mux::TlsSession::Server(server) if server.is_done()),
            ) {
                slot.tls = None;
            }
            (received, slot.conn.take_cid_route_updates())
        };
        if !self.mux.sync_reset_tokens(handle) {
            self.mux.remove_slot(handle);
            return Err(conn::Error::ConnectionIdLimit);
        }
        if !self.mux.apply_cid_routes(handle, routes.as_slice()) {
            self.mux.remove_slot(handle);
            return Err(conn::Error::HeaderDecode);
        }
        received?;
        self.mux.schedule_notify(handle);
        self.mux.schedule_flush(handle);
        self.mux.refresh_deadline(handle, now);
        Ok(())
    }

    pub fn conn_mut(
        self,
        handle: conn::Handle,
    ) -> Option<mux::ConnectionMut<'a, 'tls, H, P, DOMAIN, B>> {
        self.mux.sync_dirty_connection();
        if self.mux.lifecycle.shutting_down {
            return None;
        }
        let index = self.mux.handle_index(handle)?;
        self.mux.queue_push_back(crate::mux::QueueKind::Reap, index);
        self.mux.registry.dirty_connection = Some(handle);
        Some(mux::ConnectionMut {
            mux: self.mux,
            handle,
        })
    }

    pub fn flush(&mut self, handle: conn::Handle, now: time::Instant) {
        if self.mux.lifecycle.shutting_down {
            return;
        }
        self.mux.schedule_flush(handle);
        self.mux.refresh_deadline(handle, now);
    }

    pub fn try_send_datagram(
        &mut self,
        handle: conn::Handle,
        data: Vec<u8>,
        now: time::Instant,
    ) -> Result<(), crate::errors::SendFailure<Vec<u8>>> {
        if self.mux.lifecycle.shutting_down {
            return Err(crate::errors::SendFailure::Closed(data));
        }
        let result = match self
            .mux
            .handle_index(handle)
            .and_then(|index| self.mux.registry.entries.get_mut(index))
            .and_then(crate::mux::Entry::slot_mut)
        {
            Some(slot) => slot.conn.datagrams().try_send(data),
            None => Err(crate::errors::SendFailure::Closed(data)),
        };
        self.mux.schedule_flush(handle);
        self.mux.refresh_deadline(handle, now);
        result
    }

    pub fn close(&mut self, handle: conn::Handle) {
        self.mux.remove_slot(handle);
    }
}

impl<'a, 'tls, 'd, H, P, const DOMAIN: u8> Io<'a, 'tls, H, P, DOMAIN, stream::RecvBuffer<'d>>
where
    H: mux::Handler<DOMAIN, stream::RecvBuffer<'d>>,
    P: conn::server::Policy,
{
    pub fn recv_packet<'turn>(
        &mut self,
        from: net::SocketAddr,
        mut packet: datagram::packet::Packet<'turn, 'd>,
        retainer: datagram::packet::Retainer<'_, 'd>,
        now: time::Instant,
    ) -> Result<(), conn::Error> {
        self.mux.sync_dirty_connection();
        if self.mux.lifecycle.shutting_down {
            return Ok(());
        }
        let dcid = super::setup::dcid(packet.as_ref(), super::ROUTED_CID_LEN);
        let routed = match dcid.and_then(|value| self.mux.find_cid(value)) {
            Some(routed) => routed,
            None if super::setup::is_initial(packet.as_ref()) && self.mux.server.is_some() => {
                if self.mux.registry.active_conns >= self.mux.registry.max_conns {
                    return Ok(());
                }
                match self.mux.maybe_handle_retry_gating(from, packet.as_mut())? {
                    mux::RetryGate::Accept(retry_odcid) => {
                        let handle = self.mux.try_accept(from, packet.as_mut(), retry_odcid)?;
                        super::RoutedCid {
                            handle,
                            local: None,
                        }
                    }
                    mux::RetryGate::IssuedRetry | mux::RetryGate::Drop => return Ok(()),
                }
            }
            None => {
                if self.mux.receive_stateless_reset(from, packet.as_ref(), now) {
                    return Ok(());
                }
                self.mux.emit_stateless_reset(from, packet.as_ref());
                return Ok(());
            }
        };
        let handle = routed.handle;
        let index = self
            .mux
            .handle_index(handle)
            .ok_or(conn::Error::HeaderDecode)?;
        let (received, routes) = {
            let (registry, workspace) = (&mut self.mux.registry, &mut self.mux.receive_workspace);
            let slot = registry.entries[index]
                .slot_mut()
                .ok_or(conn::Error::HeaderDecode)?;
            let received = match (slot.conn.is_client(), slot.tls.as_mut()) {
                (true, None) => {
                    conn::ingress::Retained::routed(&mut slot.conn, workspace, routed.local)
                        .recv_client_datagram(packet, retainer, now)
                }
                (true, Some(mux::TlsSession::Client(tls))) => {
                    conn::ingress::Retained::routed(&mut slot.conn, workspace, routed.local)
                        .recv_client_pooled_datagram(packet, retainer, now, tls)
                }
                (false, Some(mux::TlsSession::OwnedServer(tls))) => {
                    conn::ingress::Retained::routed(&mut slot.conn, workspace, routed.local)
                        .recv_server_datagram(packet, retainer, now, tls)
                }
                (false, Some(mux::TlsSession::Server(tls))) => {
                    conn::ingress::Retained::routed(&mut slot.conn, workspace, routed.local)
                        .recv_server_pooled_datagram(packet, retainer, now, tls)
                }
                (false, None) => {
                    conn::ingress::Retained::routed(&mut slot.conn, workspace, routed.local)
                        .recv_finished_datagram(packet, retainer, now)
                }
                _ => Err(conn::Error::HeaderDecode),
            };
            if slot.tls.as_ref().is_some_and(
                |tls| matches!(tls, mux::TlsSession::Server(server) if server.is_done()),
            ) {
                slot.tls = None;
            }
            (received, slot.conn.take_cid_route_updates())
        };
        if !self.mux.sync_reset_tokens(handle) {
            self.mux.remove_slot(handle);
            return Err(conn::Error::ConnectionIdLimit);
        }
        if !self.mux.apply_cid_routes(handle, routes.as_slice()) {
            self.mux.remove_slot(handle);
            return Err(conn::Error::HeaderDecode);
        }
        received?;
        self.mux.schedule_notify(handle);
        self.mux.schedule_flush(handle);
        self.mux.refresh_deadline(handle, now);
        Ok(())
    }
}
