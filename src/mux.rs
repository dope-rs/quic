use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use shin::sig::SigningKey;

use crate::conn::{Conn, ConnConfig, ConnError, ConnHandle, DatagramError, StreamEvent};
use crate::packet::InitialHeader;

pub trait Handler: 'static {
    fn on_established(&mut self, _conn: &mut Conn, _handle: ConnHandle) {}
    fn on_datagram(&mut self, _conn: &mut Conn, _handle: ConnHandle, _data: Vec<u8>) {}
    fn on_stream_event(&mut self, _conn: &mut Conn, _handle: ConnHandle, _event: StreamEvent) {}
    fn on_close(&mut self, _handle: ConnHandle) {}
}

struct Slot {
    conn: Conn,
    peer_addr: SocketAddr,
    notified_established: bool,
}

const DEFAULT_MAX_CONNS: usize = 1 << 18;

pub struct Mux<H: Handler> {
    slots: Vec<Option<Slot>>,
    free: Vec<u32>,
    cid_to_handle: HashMap<Vec<u8>, ConnHandle>,
    handler: H,
    server_creds: Option<(SigningKey, ConnConfig)>,
    pending_outgoing: Vec<(SocketAddr, Vec<u8>)>,
    cid_counter: u64,
    active_conns: usize,
    max_conns: usize,
}

impl<H: Handler> Mux<H> {
    fn is_initial_packet(wire: &[u8]) -> bool {
        matches!(wire.first(), Some(&b) if (b & 0xb0) == 0x80)
    }

    fn build_stateless_reset(token: [u8; 16], len: usize) -> Vec<u8> {
        use ring::rand::{SecureRandom, SystemRandom};
        let len = len.max(22);
        let mut out = vec![0u8; len];
        let _ = SystemRandom::new().fill(&mut out);
        out[0] = (out[0] & 0x3F) | 0x40;
        let tail = len - 16;
        out[tail..].copy_from_slice(&token);
        out
    }

    fn parse_dcid(wire: &[u8], short_header_dcid_len: usize) -> Option<Vec<u8>> {
        let first = *wire.first()?;
        if first & 0x80 != 0 {
            if wire.len() < 6 {
                return None;
            }
            let dcid_len = wire[5] as usize;
            if wire.len() < 6 + dcid_len {
                return None;
            }
            Some(wire[6..6 + dcid_len].to_vec())
        } else {
            if wire.len() < 1 + short_header_dcid_len {
                return None;
            }
            Some(wire[1..1 + short_header_dcid_len].to_vec())
        }
    }

    pub fn server(handler: H, signing_key: SigningKey, server_config: ConnConfig) -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            cid_to_handle: HashMap::new(),
            handler,
            server_creds: Some((signing_key, server_config)),
            pending_outgoing: Vec::new(),
            cid_counter: 0,
            active_conns: 0,
            max_conns: DEFAULT_MAX_CONNS,
        }
    }

    pub fn client(handler: H) -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
            cid_to_handle: HashMap::new(),
            handler,
            server_creds: None,
            pending_outgoing: Vec::new(),
            cid_counter: 0,
            active_conns: 0,
            max_conns: DEFAULT_MAX_CONNS,
        }
    }

    pub fn set_max_conns(&mut self, max: usize) {
        self.max_conns = max.max(1);
    }

    pub fn active_conns(&self) -> usize {
        self.active_conns
    }

    pub fn handler(&self) -> &H {
        &self.handler
    }

    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    pub fn connect(
        &mut self,
        peer_addr: SocketAddr,
        server_pubkey: [u8; 32],
        client_config: ConnConfig,
        initial_dcid: Vec<u8>,
        now: Instant,
    ) -> ConnHandle {
        let local_cid = self.gen_cid(initial_dcid.len(), client_config.cid_prefix);
        let conn = Conn::new_client(
            initial_dcid,
            local_cid.clone(),
            server_pubkey,
            client_config,
        );
        let handle = self.insert_slot(Slot {
            conn,
            peer_addr,
            notified_established: false,
        });
        self.cid_to_handle.insert(local_cid, handle);
        self.flush_conn(handle, now);
        handle
    }

    pub fn on_udp_packet(
        &mut self,
        from: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> Result<(), ConnError> {
        let dcid = Self::parse_dcid(data, 8);
        let handle = match dcid
            .as_ref()
            .and_then(|d| self.cid_to_handle.get(d).copied())
        {
            Some(h) => h,
            None if Self::is_initial_packet(data) && self.server_creds.is_some() => {
                if self.active_conns >= self.max_conns {
                    return Ok(());
                }
                match self.maybe_handle_retry_gating(from, data)? {
                    RetryGate::Accept(retry_odcid) => self.try_accept(from, data, retry_odcid)?,
                    RetryGate::IssuedRetry | RetryGate::Drop => return Ok(()),
                }
            }
            None => {
                if let Some(reset) = self.maybe_emit_stateless_reset(data) {
                    self.pending_outgoing.push((from, reset));
                }
                return Ok(());
            }
        };
        let slot = self
            .slots
            .get_mut(handle.0 as usize)
            .and_then(|s| s.as_mut())
            .ok_or(ConnError::HeaderDecode)?;
        slot.conn.recv_packet(data, now)?;
        let new_cids = slot.conn.take_cids_to_register();
        for cid in new_cids {
            self.cid_to_handle.insert(cid, handle);
        }
        self.notify(handle);
        self.flush_conn(handle, now);
        Ok(())
    }

    pub fn pull_outgoing(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        std::mem::take(&mut self.pending_outgoing)
    }

    pub fn conn_mut(&mut self, handle: ConnHandle) -> Option<&mut Conn> {
        self.slots
            .get_mut(handle.0 as usize)?
            .as_mut()
            .map(|s| &mut s.conn)
    }

    pub fn flush(&mut self, handle: ConnHandle, now: Instant) {
        self.flush_conn(handle, now);
    }

    pub fn send_datagram(
        &mut self,
        handle: ConnHandle,
        data: Vec<u8>,
        now: Instant,
    ) -> Result<(), DatagramError> {
        let result = self
            .conn_mut(handle)
            .ok_or(DatagramError::Closed)?
            .send_datagram(data);
        self.flush_conn(handle, now);
        result
    }

    pub fn close(&mut self, handle: ConnHandle) {
        self.remove_slot(handle);
    }

    pub fn reap_closed(&mut self, now: Instant) {
        let n = self.slots.len();
        for idx in 0..n {
            if self.slots[idx].is_none() {
                continue;
            }
            if let Some(slot) = self.slots[idx].as_mut() {
                slot.conn.check_loss(now);
            }
            self.flush_conn(ConnHandle(idx as u32), now);
        }
        let mut to_close: Vec<ConnHandle> = Vec::new();
        for idx in 0..n {
            if let Some(slot) = self.slots[idx].as_ref()
                && slot.conn.is_closed()
            {
                to_close.push(ConnHandle(idx as u32));
            }
        }
        for handle in to_close {
            self.remove_slot(handle);
        }
    }

    fn try_accept(
        &mut self,
        from: SocketAddr,
        data: &[u8],
        retry_odcid: Option<Vec<u8>>,
    ) -> Result<ConnHandle, ConnError> {
        let (signing_key, server_config) = self
            .server_creds
            .as_ref()
            .ok_or(ConnError::HeaderDecode)?
            .clone();
        if !matches!(data.first(), Some(&b) if b & 0xb0 == 0x80) {
            return Err(ConnError::HeaderDecode);
        }
        let cid_prefix = server_config.cid_prefix;
        let prefix = InitialHeader::decode_pre_hp(data).map_err(|_| ConnError::HeaderDecode)?;
        let initial_dcid = prefix.dcid;
        let peer_cid = prefix.scid;
        let local_cid = self.gen_cid(initial_dcid.len(), cid_prefix);
        let conn = match retry_odcid {
            Some(odcid) => Conn::new_server_retry(
                initial_dcid.clone(),
                local_cid.clone(),
                peer_cid,
                odcid,
                initial_dcid,
                signing_key,
                server_config,
            ),
            None => Conn::new_server(
                initial_dcid,
                local_cid.clone(),
                peer_cid,
                signing_key,
                server_config,
            ),
        };
        let handle = self.insert_slot(Slot {
            conn,
            peer_addr: from,
            notified_established: false,
        });
        self.cid_to_handle.insert(local_cid, handle);
        Ok(handle)
    }

    fn flush_conn(&mut self, handle: ConnHandle, now: Instant) {
        let slot = match self
            .slots
            .get_mut(handle.0 as usize)
            .and_then(|s| s.as_mut())
        {
            Some(s) => s,
            None => return,
        };
        let addr = slot.peer_addr;
        for pkt in slot.conn.send_packets(now) {
            self.pending_outgoing.push((addr, pkt));
        }
    }

    fn notify(&mut self, handle: ConnHandle) {
        let slot = match self
            .slots
            .get_mut(handle.0 as usize)
            .and_then(|s| s.as_mut())
        {
            Some(s) => s,
            None => return,
        };
        if slot.conn.is_established() && !slot.notified_established {
            slot.notified_established = true;
            self.handler.on_established(&mut slot.conn, handle);
        }
        while let Some(dg) = slot.conn.recv_datagram() {
            self.handler.on_datagram(&mut slot.conn, handle, dg);
        }
        while let Some(ev) = slot.conn.poll_stream_event() {
            self.handler.on_stream_event(&mut slot.conn, handle, ev);
        }
    }

    fn insert_slot(&mut self, slot: Slot) -> ConnHandle {
        self.active_conns = self.active_conns.saturating_add(1);
        if let Some(idx) = self.free.pop() {
            self.slots[idx as usize] = Some(slot);
            ConnHandle(idx)
        } else {
            let idx = self.slots.len() as u32;
            self.slots.push(Some(slot));
            ConnHandle(idx)
        }
    }

    fn remove_slot(&mut self, handle: ConnHandle) -> bool {
        let idx = handle.0 as usize;
        if self.slots.get_mut(idx).and_then(|s| s.take()).is_some() {
            self.active_conns = self.active_conns.saturating_sub(1);
            self.cid_to_handle.retain(|_, &mut h| h != handle);
            self.free.push(handle.0);
            self.handler.on_close(handle);
            true
        } else {
            false
        }
    }

    fn maybe_handle_retry_gating(
        &mut self,
        from: SocketAddr,
        data: &[u8],
    ) -> Result<RetryGate, ConnError> {
        let (_signing, server_config) =
            self.server_creds.as_ref().ok_or(ConnError::HeaderDecode)?;
        if !server_config.require_address_validation {
            return Ok(RetryGate::Accept(None));
        }
        let secret = match server_config.retry_token_secret {
            Some(s) => crate::secrets::RetryTokenSecret(s),
            None => return Ok(RetryGate::Accept(None)),
        };
        let prefix = crate::packet::InitialHeader::decode_pre_hp(data)
            .map_err(|_| ConnError::HeaderDecode)?;
        if prefix.token.is_empty() {
            let now_secs = crate::time::now_unix_secs();
            let expiry = now_secs.saturating_add(10);
            let token = secret.issue(&from, &prefix.dcid, expiry);
            let new_scid = self.gen_cid(prefix.dcid.len(), server_config.cid_prefix);
            let mut retry = crate::packet::RetryPacket {
                version: crate::packet::QUIC_V1,
                dcid: prefix.scid.clone(),
                scid: new_scid,
                token,
                integrity_tag: [0u8; 16],
            };
            retry.integrity_tag = retry.compute_integrity_tag(&prefix.dcid);
            self.pending_outgoing.push((from, retry.encode()));
            return Ok(RetryGate::IssuedRetry);
        }
        let now_secs = crate::time::now_unix_secs();
        match secret.validate(&from, &prefix.token, now_secs) {
            None => Ok(RetryGate::Drop),
            Some(odcid) => Ok(RetryGate::Accept(Some(odcid))),
        }
    }

    fn maybe_emit_stateless_reset(&self, trigger: &[u8]) -> Option<Vec<u8>> {
        let (_signing, server_config) = self.server_creds.as_ref()?;
        let secret = crate::secrets::StatelessResetSecret(server_config.stateless_reset_secret?);
        let dcid = Self::parse_dcid(trigger, 8)?;
        if trigger.len() < 23 {
            return None;
        }
        Some(Self::build_stateless_reset(
            secret.token_for(&dcid),
            trigger.len() - 1,
        ))
    }

    fn gen_cid(&mut self, len: usize, prefix: Option<u8>) -> Vec<u8> {
        self.cid_counter = self.cid_counter.wrapping_add(1);
        let mut out = Vec::with_capacity(len);
        let bytes = self.cid_counter.to_be_bytes();
        for i in 0..len {
            out.push(bytes[i % 8] ^ (i as u8));
        }
        if let Some(p) = prefix
            && let Some(first) = out.first_mut()
        {
            *first = p;
        }
        out
    }
}

enum RetryGate {
    Accept(Option<Vec<u8>>),
    IssuedRetry,
    Drop,
}
