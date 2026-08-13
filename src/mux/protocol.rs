use std::net::SocketAddr;
use std::time::Instant;

use crate::conn::{self, Error, Handle};
use crate::pmtud::BASE_PMTU;
use crate::stream::{ReceiveBuffer, RecvBuffer};
use crate::{ConnectError, TrySendError};
use dope::manifold::datagram;

use super::drive::{DriveOps as _, QueueOps as _};
use super::routing::reset::ResetOps as _;
use super::routing::{AcceptOps as _, CidOps as _, DeadlineOps as _, SlotOps as _};
use super::{ConnectionMut, Entry, Handler, MuxInner, QueueKind, RetryGate, TlsSession};
use crate::packet::ConnectionId;

pub struct Io<'a, 'tls, H, P, const DOMAIN: u8, B: ReceiveBuffer = Vec<u8>>
where
    H: Handler<DOMAIN, B>,
    P: conn::server::Policy,
{
    mux: &'a mut MuxInner<'tls, H, P, DOMAIN, B>,
}

impl<'a, 'tls, H: Handler<DOMAIN, B>, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer>
    Io<'a, 'tls, H, P, DOMAIN, B>
{
    pub(super) fn new(mux: &'a mut MuxInner<'tls, H, P, DOMAIN, B>) -> Self {
        Self { mux }
    }

    pub fn connect(
        &mut self,
        peer_addr: SocketAddr,
        server_pubkey: [u8; 32],
        client_config: conn::config::Options,
        initial_dcid: Vec<u8>,
        now: Instant,
    ) -> Result<Handle, ConnectError> {
        let initial_dcid =
            ConnectionId::try_from(initial_dcid).map_err(|_| ConnectError::InvalidConfig)?;
        self.connect_id(peer_addr, server_pubkey, client_config, initial_dcid, now)
    }

    pub(crate) fn connect_id(
        &mut self,
        peer_addr: SocketAddr,
        server_pubkey: [u8; 32],
        client_config: conn::config::Options,
        initial_dcid: ConnectionId,
        now: Instant,
    ) -> Result<Handle, ConnectError> {
        self.mux.sync_dirty_connection();
        if self.mux.lifecycle.shutting_down {
            return Err(ConnectError::Closed);
        }
        if self.mux.registry.active_conns >= self.mux.registry.max_conns {
            return Err(ConnectError::Capacity);
        }
        client_config.validate()?;
        let max_packet_bytes =
            super::setup::connection_ceiling(&client_config, self.mux.outgoing.bytes_capacity);
        if max_packet_bytes < BASE_PMTU as usize {
            return Err(ConnectError::InvalidConfig);
        }
        let local_cid = self
            .mux
            .gen_cid(client_config.cid_prefix)
            .ok_or(ConnectError::Capacity)?;
        let conn = conn::setup::Client::<DOMAIN>::connect_buffer::<B>(
            initial_dcid,
            local_cid,
            server_pubkey,
            client_config,
        )?;
        let handle = self
            .mux
            .insert_connection(conn, None, peer_addr, max_packet_bytes)
            .ok_or(ConnectError::Capacity)?;
        let index = self
            .mux
            .handle_index(handle)
            .ok_or(ConnectError::Capacity)?;
        let (key, local_cid) = self.mux.registry.entries[index]
            .slot_mut()
            .ok_or(ConnectError::Capacity)?
            .conn
            .enable_cid_routing();
        if !self.mux.register_local_cid(handle, key, local_cid) {
            self.mux.remove_slot(handle);
            return Err(ConnectError::Capacity);
        }
        self.mux.schedule_flush(handle);
        self.mux.refresh_deadline(handle, now);
        Ok(handle)
    }

    /// Connects with externally owned, exactly reserved TLS storage. The
    /// resulting slot cannot outlive `pool` through the Mux's `'tls` lifetime.
    pub fn connect_pooled(
        &mut self,
        peer_addr: SocketAddr,
        pool: &'tls conn::tls::ClientPool,
        client_config: conn::config::Options,
        initial_dcid: Vec<u8>,
        now: Instant,
    ) -> Result<Handle, ConnectError> {
        let initial_dcid =
            ConnectionId::try_from(initial_dcid).map_err(|_| ConnectError::InvalidConfig)?;
        self.connect_pooled_id(peer_addr, pool, client_config, initial_dcid, now)
    }

    pub(crate) fn connect_pooled_id(
        &mut self,
        peer_addr: SocketAddr,
        pool: &'tls conn::tls::ClientPool,
        client_config: conn::config::Options,
        initial_dcid: ConnectionId,
        now: Instant,
    ) -> Result<Handle, ConnectError> {
        self.mux.sync_dirty_connection();
        if self.mux.lifecycle.shutting_down {
            return Err(ConnectError::Closed);
        }
        if self.mux.registry.active_conns >= self.mux.registry.max_conns {
            return Err(ConnectError::Capacity);
        }
        client_config.validate()?;
        let max_packet_bytes =
            super::setup::connection_ceiling(&client_config, self.mux.outgoing.bytes_capacity);
        if max_packet_bytes < BASE_PMTU as usize {
            return Err(ConnectError::InvalidConfig);
        }
        let local_cid = self
            .mux
            .gen_cid(client_config.cid_prefix)
            .ok_or(ConnectError::Capacity)?;
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
                Some(TlsSession::Client(tls)),
                peer_addr,
                max_packet_bytes,
            )
            .ok_or(ConnectError::Capacity)?;
        let index = self
            .mux
            .handle_index(handle)
            .ok_or(ConnectError::Capacity)?;
        let (key, local_cid) = self.mux.registry.entries[index]
            .slot_mut()
            .ok_or(ConnectError::Capacity)?
            .conn
            .enable_cid_routing();
        if !self.mux.register_local_cid(handle, key, local_cid) {
            self.mux.remove_slot(handle);
            return Err(ConnectError::Capacity);
        }
        self.mux.schedule_flush(handle);
        self.mux.refresh_deadline(handle, now);
        Ok(handle)
    }

    /// Receives and decrypts one datagram in place.
    ///
    /// The contents of `data` are unspecified after this call.
    pub fn recv(&mut self, from: SocketAddr, data: &mut [u8], now: Instant) -> Result<(), Error> {
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
                    RetryGate::Accept(retry_odcid) => {
                        let handle = self.mux.try_accept(from, data, retry_odcid)?;
                        super::RoutedCid {
                            handle,
                            local: None,
                        }
                    }
                    RetryGate::IssuedRetry | RetryGate::Drop => return Ok(()),
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
        let index = self.mux.handle_index(handle).ok_or(Error::HeaderDecode)?;
        let (received, routes) = {
            let (registry, workspace) = (&mut self.mux.registry, &mut self.mux.receive_workspace);
            let slot = registry.entries[index]
                .slot_mut()
                .ok_or(Error::HeaderDecode)?;
            let received = match (slot.conn.is_client(), slot.tls.as_mut()) {
                (true, None) => {
                    conn::ingress::Ingress::routed(&mut slot.conn, workspace, routed.local)
                        .recv_client(data, now)
                }
                (true, Some(TlsSession::Client(tls))) => {
                    conn::ingress::Ingress::routed(&mut slot.conn, workspace, routed.local)
                        .recv_client_pooled(data, now, tls)
                }
                (false, Some(TlsSession::OwnedServer(tls))) => {
                    conn::ingress::Ingress::routed(&mut slot.conn, workspace, routed.local)
                        .recv_server(data, now, tls)
                }
                (false, Some(TlsSession::Server(tls))) => {
                    conn::ingress::Ingress::routed(&mut slot.conn, workspace, routed.local)
                        .recv_server_pooled(data, now, tls)
                }
                (false, None) => {
                    conn::ingress::Ingress::routed(&mut slot.conn, workspace, routed.local)
                        .recv_finished(data, now)
                }
                _ => Err(Error::HeaderDecode),
            };
            if slot
                .tls
                .as_ref()
                .is_some_and(|tls| matches!(tls, TlsSession::Server(server) if server.is_done()))
            {
                slot.tls = None;
            }
            (received, slot.conn.take_cid_route_updates())
        };
        if !self.mux.sync_reset_tokens(handle) {
            self.mux.remove_slot(handle);
            return Err(Error::ConnectionIdLimit);
        }
        if !self.mux.apply_cid_routes(handle, routes.as_slice()) {
            self.mux.remove_slot(handle);
            return Err(Error::HeaderDecode);
        }
        received?;
        self.mux.schedule_notify(handle);
        self.mux.schedule_flush(handle);
        self.mux.refresh_deadline(handle, now);
        Ok(())
    }

    pub fn conn_mut(self, handle: Handle) -> Option<ConnectionMut<'a, 'tls, H, P, DOMAIN, B>> {
        self.mux.sync_dirty_connection();
        if self.mux.lifecycle.shutting_down {
            return None;
        }
        let index = self.mux.handle_index(handle)?;
        self.mux.queue_push_back(QueueKind::Reap, index);
        self.mux.registry.dirty_connection = Some(handle);
        Some(ConnectionMut {
            mux: self.mux,
            handle,
        })
    }

    pub fn flush(&mut self, handle: Handle, now: Instant) {
        if self.mux.lifecycle.shutting_down {
            return;
        }
        self.mux.schedule_flush(handle);
        self.mux.refresh_deadline(handle, now);
    }

    pub fn try_send_datagram(
        &mut self,
        handle: Handle,
        data: Vec<u8>,
        now: Instant,
    ) -> Result<(), crate::TrySendError<Vec<u8>>> {
        if self.mux.lifecycle.shutting_down {
            return Err(TrySendError::Closed(data));
        }
        let result = match self
            .mux
            .handle_index(handle)
            .and_then(|index| self.mux.registry.entries.get_mut(index))
            .and_then(Entry::slot_mut)
        {
            Some(slot) => slot.conn.datagrams().try_send(data),
            None => Err(TrySendError::Closed(data)),
        };
        self.mux.schedule_flush(handle);
        self.mux.refresh_deadline(handle, now);
        result
    }

    pub fn close(&mut self, handle: Handle) {
        self.mux.remove_slot(handle);
    }
}

impl<'a, 'tls, 'd, H, P, const DOMAIN: u8> Io<'a, 'tls, H, P, DOMAIN, RecvBuffer<'d>>
where
    H: Handler<DOMAIN, RecvBuffer<'d>>,
    P: conn::server::Policy,
{
    pub fn recv_packet<'turn>(
        &mut self,
        from: SocketAddr,
        mut packet: datagram::packet::Packet<'turn, 'd>,
        retainer: datagram::packet::Retainer<'_, 'd>,
        now: Instant,
    ) -> Result<(), Error> {
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
                    RetryGate::Accept(retry_odcid) => {
                        let handle = self.mux.try_accept(from, packet.as_mut(), retry_odcid)?;
                        super::RoutedCid {
                            handle,
                            local: None,
                        }
                    }
                    RetryGate::IssuedRetry | RetryGate::Drop => return Ok(()),
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
        let index = self.mux.handle_index(handle).ok_or(Error::HeaderDecode)?;
        let (received, routes) = {
            let (registry, workspace) = (&mut self.mux.registry, &mut self.mux.receive_workspace);
            let slot = registry.entries[index]
                .slot_mut()
                .ok_or(Error::HeaderDecode)?;
            let received = match (slot.conn.is_client(), slot.tls.as_mut()) {
                (true, None) => {
                    conn::ingress::Retained::routed(&mut slot.conn, workspace, routed.local)
                        .recv_client_datagram(packet, retainer, now)
                }
                (true, Some(TlsSession::Client(tls))) => {
                    conn::ingress::Retained::routed(&mut slot.conn, workspace, routed.local)
                        .recv_client_pooled_datagram(packet, retainer, now, tls)
                }
                (false, Some(TlsSession::OwnedServer(tls))) => {
                    conn::ingress::Retained::routed(&mut slot.conn, workspace, routed.local)
                        .recv_server_datagram(packet, retainer, now, tls)
                }
                (false, Some(TlsSession::Server(tls))) => {
                    conn::ingress::Retained::routed(&mut slot.conn, workspace, routed.local)
                        .recv_server_pooled_datagram(packet, retainer, now, tls)
                }
                (false, None) => {
                    conn::ingress::Retained::routed(&mut slot.conn, workspace, routed.local)
                        .recv_finished_datagram(packet, retainer, now)
                }
                _ => Err(Error::HeaderDecode),
            };
            if slot
                .tls
                .as_ref()
                .is_some_and(|tls| matches!(tls, TlsSession::Server(server) if server.is_done()))
            {
                slot.tls = None;
            }
            (received, slot.conn.take_cid_route_updates())
        };
        if !self.mux.sync_reset_tokens(handle) {
            self.mux.remove_slot(handle);
            return Err(Error::ConnectionIdLimit);
        }
        if !self.mux.apply_cid_routes(handle, routes.as_slice()) {
            self.mux.remove_slot(handle);
            return Err(Error::HeaderDecode);
        }
        received?;
        self.mux.schedule_notify(handle);
        self.mux.schedule_flush(handle);
        self.mux.refresh_deadline(handle, now);
        Ok(())
    }
}
