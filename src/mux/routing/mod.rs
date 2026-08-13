pub(super) mod registry;
pub(super) mod reset;

use std::hash::BuildHasher;
use std::net::SocketAddr;
use std::time::Instant;

use crate::conn::path::{LocalCidKey, RouteUpdate};
use crate::conn::session::Connection;
use crate::conn::{self, Error, Handle, MAX_ACTIVE_CONNECTION_IDS};
use crate::packet::{ConnectionId, InitialHeader};
use crate::pmtud::BASE_PMTU;
use crate::stream::ReceiveBuffer;

use self::reset::ResetOps as _;
use super::drive::{DriveOps as _, QueueOps as _};
use super::{
    CidLink, CidRecord, Handler, MAX_CIDS_PER_CONN, NONE, QueueKind, RoutedCid, Router,
    ServerShard, Slot, TlsSession,
};

pub(super) trait AcceptOps {
    fn try_accept(
        &mut self,
        from: SocketAddr,
        data: &mut [u8],
        retry_odcid: Option<ConnectionId>,
    ) -> Result<Handle, Error>;
}

pub(super) trait CidOps {
    fn cid_hash(&self, value: &[u8]) -> u64;
    fn cid_bucket(&self, value: &[u8]) -> usize;
    fn cid_record(&self, link: CidLink) -> Option<&CidRecord>;
    fn cid_record_mut(&mut self, link: CidLink) -> Option<&mut CidRecord>;
    fn find_cid(&self, value: &[u8]) -> Option<RoutedCid>;
    fn register_local_cid(&mut self, handle: Handle, key: LocalCidKey, value: ConnectionId)
    -> bool;
    fn register_cid_alias(&mut self, handle: Handle, value: ConnectionId) -> bool;
    fn apply_cid_routes(&mut self, handle: Handle, updates: &[RouteUpdate]) -> bool;
    fn unregister_local_cid(&mut self, handle: Handle, key: LocalCidKey) -> bool;
    fn unregister_cids(&mut self, handle: Handle);
}

pub(super) trait DeadlineOps<H, P, const DOMAIN: u8, B: ReceiveBuffer>
where
    H: Handler<DOMAIN, B>,
    P: conn::server::Policy,
{
    fn deadline_peek(&self) -> Option<(usize, Instant)>;
    fn deadline_remove(&mut self, index: usize) -> Option<Instant>;
    fn deadline_set(&mut self, index: usize, deadline: Instant) -> bool;
    fn refresh_deadline(&mut self, handle: Handle, now: Instant);
    fn slot_deadline(
        slot: &Slot<'_, H::Connection, P, DOMAIN, B>,
        flush_linked: bool,
        now: Instant,
    ) -> Option<Instant>;
    fn notify_one(&mut self) -> bool;
}

pub(super) trait SlotOps<'tls, H, P, const DOMAIN: u8, B: ReceiveBuffer>
where
    H: Handler<DOMAIN, B>,
    P: conn::server::Policy,
{
    fn insert_connection(
        &mut self,
        conn: Connection<DOMAIN, B>,
        tls: Option<TlsSession<'tls, P, DOMAIN>>,
        peer_addr: SocketAddr,
        max_packet_bytes: usize,
    ) -> Option<Handle>;
    fn remove_slot(&mut self, handle: Handle) -> bool;
    fn finish_connection_mut(&mut self, handle: Handle);
    fn sync_dirty_connection(&mut self);
    fn sync_reset_tokens(&mut self, handle: Handle) -> bool;
    fn handle_for_index(&self, index: usize) -> Handle;
    fn handle_index(&self, handle: Handle) -> Option<usize>;
}

impl<'tls, H: Handler<DOMAIN, B>, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer>
    AcceptOps for Router<'tls, H, P, DOMAIN, B>
{
    fn try_accept(
        &mut self,
        from: SocketAddr,
        data: &mut [u8],
        retry_odcid: Option<ConnectionId>,
    ) -> Result<Handle, Error> {
        let server_config = self
            .server
            .as_ref()
            .ok_or(Error::HeaderDecode)?
            .config
            .duplicate_connection()
            .map_err(|_| Error::Tls)?;
        if !matches!(data.first(), Some(&b) if b & 0xb0 == 0x80) {
            return Err(Error::HeaderDecode);
        }
        let cid_prefix = server_config.cid_prefix;
        let prefix = InitialHeader::decode_pre_hp(data).map_err(|_| Error::HeaderDecode)?;
        let initial_dcid = prefix.dcid.into_owned();
        let peer_cid = prefix.scid.into_owned();
        let local_cid = self.gen_cid(cid_prefix).ok_or(Error::ConnectionIdLimit)?;
        let client_initial_dcid = initial_dcid;
        let max_packet_bytes =
            super::setup::connection_ceiling(&server_config, self.outgoing.bytes_capacity);
        if max_packet_bytes < BASE_PMTU as usize {
            return Err(Error::PacketCeiling);
        }
        let ids = match retry_odcid {
            Some(odcid) => {
                conn::server::Ids::retry(initial_dcid, local_cid, peer_cid, odcid, initial_dcid)
            }
            None => conn::server::Ids::initial(initial_dcid, local_cid, peer_cid),
        };
        let (connection, tls) = match &self.server.as_ref().ok_or(Error::HeaderDecode)?.shard {
            ServerShard::Owned(shard) => {
                let (connection, tls) =
                    conn::setup::build::Builder::server(ids, server_config, shard)
                        .finish()
                        .map_err(|_| Error::Tls)?
                        .into_server()
                        .ok_or(Error::Tls)?;
                (connection, TlsSession::OwnedServer(tls))
            }
            ServerShard::Pooled { pool, .. } => {
                let built = conn::setup::build::Builder::server_pooled(ids, server_config, *pool)
                    .finish()
                    .map_err(|_| Error::Tls)?;
                let conn::setup::build::Built::ServerPooled { connection, tls } = built else {
                    return Err(Error::Tls);
                };
                (connection, TlsSession::Server(tls))
            }
        };
        let handle = self
            .insert_connection(connection, Some(tls), from, max_packet_bytes)
            .ok_or(Error::EventCapacity)?;
        let index = self.handle_index(handle).ok_or(Error::HeaderDecode)?;
        let (local_key, local_cid) = self.registry.entries[index]
            .slot_mut()
            .ok_or(Error::HeaderDecode)?
            .conn
            .enable_cid_routing();
        if !self.register_local_cid(handle, local_key, local_cid) {
            self.remove_slot(handle);
            return Err(Error::HeaderDecode);
        }
        if self.find_cid(&client_initial_dcid).is_none()
            && !self.register_cid_alias(handle, client_initial_dcid)
        {
            self.remove_slot(handle);
            return Err(Error::HeaderDecode);
        }
        Ok(handle)
    }
}

impl<'tls, H: Handler<DOMAIN, B>, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer>
    CidOps for Router<'tls, H, P, DOMAIN, B>
{
    fn cid_hash(&self, value: &[u8]) -> u64 {
        self.registry.indexes.cid_hasher.hash_one(value)
    }

    fn cid_bucket(&self, value: &[u8]) -> usize {
        self.cid_hash(value) as usize & (self.registry.indexes.cid_buckets.len() - 1)
    }

    fn cid_record(&self, link: CidLink) -> Option<&CidRecord> {
        self.registry.entries[link.index()]
            .slot()?
            .identifiers
            .cids
            .get(link.ordinal())
    }

    fn cid_record_mut(&mut self, link: CidLink) -> Option<&mut CidRecord> {
        self.registry.entries[link.index()]
            .slot_mut()?
            .identifiers
            .cids
            .get_mut(link.ordinal())
    }

    fn find_cid(&self, value: &[u8]) -> Option<RoutedCid> {
        let mut current = self.registry.indexes.cid_buckets[self.cid_bucket(value)];
        while let Some(link) = current {
            let record = self.cid_record(link)?;
            if record.value.as_ref().map(ConnectionId::as_slice) == Some(value) {
                return Some(RoutedCid {
                    handle: self.handle_for_index(link.index()),
                    local: record.local,
                });
            }
            current = record.next;
        }
        None
    }

    fn register_local_cid(
        &mut self,
        handle: Handle,
        key: LocalCidKey,
        value: ConnectionId,
    ) -> bool {
        let ordinal = key.slot();
        if ordinal >= MAX_ACTIVE_CONNECTION_IDS {
            return false;
        }
        self.register_cid_at(handle, ordinal, value, Some(key))
    }

    fn register_cid_alias(&mut self, handle: Handle, value: ConnectionId) -> bool {
        let Some(index) = self.handle_index(handle) else {
            return false;
        };
        let Some(ordinal) = self.registry.entries[index].slot().and_then(|slot| {
            slot.identifiers
                .cids
                .iter()
                .skip(MAX_ACTIVE_CONNECTION_IDS)
                .position(|record| record.value.is_none())
                .map(|offset| MAX_ACTIVE_CONNECTION_IDS + offset)
        }) else {
            return false;
        };
        self.register_cid_at(handle, ordinal, value, None)
    }

    fn apply_cid_routes(&mut self, handle: Handle, updates: &[RouteUpdate]) -> bool {
        for update in updates {
            let applied = match *update {
                RouteUpdate::Add { key, cid } => self.register_local_cid(handle, key, cid),
                RouteUpdate::Remove(key) => self.unregister_local_cid(handle, key),
            };
            if !applied {
                return false;
            }
        }
        true
    }

    fn unregister_local_cid(&mut self, handle: Handle, key: LocalCidKey) -> bool {
        let Some(index) = self.handle_index(handle) else {
            return false;
        };
        let Some(link) = CidLink::new(index, key.slot()) else {
            return false;
        };
        self.unregister_cid_link(link, Some(key))
    }

    fn unregister_cids(&mut self, handle: Handle) {
        let Some(index) = self.handle_index(handle) else {
            return;
        };
        for ordinal in 0..MAX_CIDS_PER_CONN {
            if let Some(link) = CidLink::new(index, ordinal) {
                self.unregister_cid_link(link, None);
            }
        }
    }
}

impl<'tls, H: Handler<DOMAIN, B>, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer>
    Router<'tls, H, P, DOMAIN, B>
{
    fn register_cid_at(
        &mut self,
        handle: Handle,
        ordinal: usize,
        value: ConnectionId,
        local: Option<LocalCidKey>,
    ) -> bool {
        if let Some(routed) = self.find_cid(value.as_slice()) {
            return routed.handle == handle && routed.local == local;
        }
        let Some(index) = self.handle_index(handle) else {
            return false;
        };
        if self.registry.entries[index]
            .slot()
            .and_then(|slot| slot.identifiers.cids.get(ordinal))
            .is_none_or(|record| record.value.is_some())
        {
            return false;
        }
        let bucket = self.cid_bucket(value.as_slice());
        let next = self.registry.indexes.cid_buckets[bucket];
        let Some(link) = CidLink::new(index, ordinal) else {
            return false;
        };
        let Some(slot) = self.registry.entries[index].slot_mut() else {
            return false;
        };
        let record = &mut slot.identifiers.cids[ordinal];
        record.value = Some(value);
        record.local = local;
        record.prev = None;
        record.next = next;
        if let Some(next) = next {
            let Some(record) = self.cid_record_mut(next) else {
                return false;
            };
            record.prev = Some(link);
        }
        self.registry.indexes.cid_buckets[bucket] = Some(link);
        true
    }

    fn unregister_cid_link(&mut self, link: CidLink, expected: Option<LocalCidKey>) -> bool {
        let index = link.index();
        let Some((bucket, prev, next)) = self.registry.entries[index]
            .slot()
            .and_then(|slot| slot.identifiers.cids.get(link.ordinal()))
            .and_then(|record| {
                if expected.is_some() && record.local != expected {
                    return None;
                }
                record
                    .value
                    .map(|value| (self.cid_bucket(value.as_slice()), record.prev, record.next))
            })
        else {
            return expected.is_none();
        };
        if let Some(prev) = prev {
            if let Some(record) = self.cid_record_mut(prev) {
                record.next = next;
            }
        } else {
            debug_assert_eq!(self.registry.indexes.cid_buckets[bucket], Some(link));
            self.registry.indexes.cid_buckets[bucket] = next;
        }
        if let Some(next) = next
            && let Some(record) = self.cid_record_mut(next)
        {
            record.prev = prev;
        }
        if let Some(slot) = self.registry.entries[index].slot_mut() {
            slot.identifiers.cids[link.ordinal()] = CidRecord::default();
        }
        true
    }
}

impl<'tls, H: Handler<DOMAIN, B>, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer>
    DeadlineOps<H, P, DOMAIN, B> for Router<'tls, H, P, DOMAIN, B>
{
    fn deadline_peek(&self) -> Option<(usize, Instant)> {
        self.registry
            .deadlines
            .peek()
            .map(|(index, deadline)| (index, *deadline))
    }

    fn deadline_remove(&mut self, index: usize) -> Option<Instant> {
        self.registry.deadlines.remove(index)
    }

    fn deadline_set(&mut self, index: usize, deadline: Instant) -> bool {
        self.deadline_remove(index);
        self.registry.deadlines.insert(index, deadline).is_ok()
    }

    fn refresh_deadline(&mut self, handle: Handle, now: Instant) {
        let Some(index) = self.handle_index(handle) else {
            return;
        };
        self.queue_remove(QueueKind::Reap, index);
        let Some(slot) = self.registry.entries[index].slot() else {
            self.deadline_remove(index);
            return;
        };
        if slot.conn.status().is_closed() {
            self.deadline_remove(index);
            self.queue_push_back(QueueKind::Reap, index);
            return;
        }
        let deadline = Self::slot_deadline(slot, self.registry.entries[index].flush.linked, now);
        match deadline {
            Some(deadline) => {
                self.deadline_set(index, deadline);
            }
            None => {
                self.deadline_remove(index);
            }
        }
    }

    fn slot_deadline(
        slot: &Slot<'_, H::Connection, P, DOMAIN, B>,
        flush_linked: bool,
        now: Instant,
    ) -> Option<Instant> {
        if slot.conn.status().is_closed() {
            return Some(now);
        }
        let mut deadline = slot.conn.status().next_timer();
        if !flush_linked
            && let Some(send) = crate::conn::transmit::eligibility::send_deadline(&slot.conn, now)
        {
            deadline = Some(deadline.map_or(send, |timer| timer.min(send)));
        }
        deadline
    }

    fn notify_one(&mut self) -> bool {
        let Some(index) = self.queue_pop_front(QueueKind::Notify) else {
            return false;
        };
        let handle = self.handle_for_index(index);
        let pending = {
            let Some(slot) = self.registry.entries[index].slot_mut() else {
                return true;
            };
            if slot.conn.status().is_established() && !slot.notified_established {
                slot.notified_established = true;
                self.handler
                    .established(&mut slot.connection, &mut slot.conn, handle);
            } else if let Some(datagram) = slot.conn.datagrams().recv() {
                self.handler
                    .datagram(&mut slot.connection, &mut slot.conn, handle, datagram);
            } else if let Some(event) = slot.conn.stream_events().poll_event() {
                if slot.notified_established {
                    self.handler
                        .stream_event(&mut slot.connection, &mut slot.conn, handle, event);
                } else {
                    self.handler.early_stream_event(
                        &mut slot.connection,
                        &mut slot.conn,
                        handle,
                        event,
                    );
                }
            }
            (slot.conn.status().is_established() && !slot.notified_established)
                || slot.conn.datagrams().has_received()
                || slot.conn.stream_state().has_events()
        };
        if !self.sync_reset_tokens(handle) {
            self.remove_slot(handle);
            return true;
        }
        if pending {
            self.schedule_notify(handle);
        }
        self.schedule_flush(handle);
        true
    }
}

impl<'tls, H: Handler<DOMAIN, B>, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer>
    SlotOps<'tls, H, P, DOMAIN, B> for Router<'tls, H, P, DOMAIN, B>
{
    fn insert_connection(
        &mut self,
        mut conn: Connection<DOMAIN, B>,
        tls: Option<TlsSession<'tls, P, DOMAIN>>,
        peer_addr: SocketAddr,
        max_packet_bytes: usize,
    ) -> Option<Handle> {
        while self.registry.free_head != NONE {
            let index = self.registry.free_head as usize;
            let entry = &mut self.registry.entries[index];
            self.registry.free_head = entry.free_next;
            let generation = if entry.used {
                let Some(generation) = entry.generation.checked_add(1) else {
                    continue;
                };
                generation
            } else {
                entry.used = true;
                0
            };
            entry.generation = generation;
            entry.free_next = NONE;
            let handle = Handle::from_parts(index as u32, generation);
            let connection = self.handler.create_connection(&mut conn, handle);
            self.registry.entries[index].insert(Slot::new(
                conn,
                tls,
                connection,
                peer_addr,
                max_packet_bytes,
            ));
            self.registry.active_conns = self.registry.active_conns.saturating_add(1);
            if !self.sync_reset_tokens(handle) {
                self.remove_slot(handle);
                return None;
            }
            return Some(handle);
        }
        None
    }

    fn remove_slot(&mut self, handle: Handle) -> bool {
        let Some(idx) = self.handle_index(handle) else {
            return false;
        };
        if self.registry.dirty_connection == Some(handle) {
            self.registry.dirty_connection = None;
        }
        self.queue_remove(QueueKind::Notify, idx);
        self.unschedule_flush(handle);
        self.queue_remove(QueueKind::Reap, idx);
        self.deadline_remove(idx);
        self.unregister_cids(handle);
        let Some(slot) = self.registry.entries[idx].take() else {
            return false;
        };
        for token in slot.identifiers.reset_tokens.into_iter().flatten() {
            self.registry.indexes.reset.remove(token, handle);
        }
        self.registry.active_conns = self.registry.active_conns.saturating_sub(1);
        self.registry.entries[idx].free_next = self.registry.free_head;
        self.registry.free_head = idx as u32;
        self.handler.close(slot.connection, handle);
        true
    }

    fn finish_connection_mut(&mut self, handle: Handle) {
        if self.registry.dirty_connection != Some(handle) {
            return;
        }
        self.registry.dirty_connection = None;
        if !self.sync_reset_tokens(handle) {
            self.remove_slot(handle);
        }
    }

    fn sync_dirty_connection(&mut self) {
        let Some(handle) = self.registry.dirty_connection.take() else {
            return;
        };
        if self.handle_index(handle).is_some() && !self.sync_reset_tokens(handle) {
            self.remove_slot(handle);
        }
    }

    fn sync_reset_tokens(&mut self, handle: Handle) -> bool {
        let Some(index) = self.handle_index(handle) else {
            return false;
        };
        let mut current = [None; MAX_ACTIVE_CONNECTION_IDS];
        let previous = {
            let slot = self.registry.entries[index]
                .slot_mut()
                .expect("validated handle owns a live slot");
            for (len, token) in slot.conn.peer_stateless_reset_tokens().enumerate() {
                if len == current.len() || current[..len].contains(&Some(token)) {
                    return false;
                }
                current[len] = Some(token);
            }
            std::mem::replace(&mut slot.identifiers.reset_tokens, current)
        };

        for token in previous.into_iter().flatten() {
            self.registry.indexes.reset.remove(token, handle);
        }
        for token in current.into_iter().flatten() {
            if !self.registry.indexes.reset.insert(token, handle) {
                for token in current.into_iter().flatten() {
                    self.registry.indexes.reset.remove(token, handle);
                }
                return false;
            }
        }
        true
    }

    fn handle_for_index(&self, index: usize) -> Handle {
        Handle::from_parts(index as u32, self.registry.entries[index].generation)
    }

    fn handle_index(&self, handle: Handle) -> Option<usize> {
        let index = handle.index() as usize;
        self.registry
            .entries
            .get(index)
            .is_some_and(|entry| entry.generation == handle.generation() && entry.slot.is_some())
            .then_some(index)
    }
}
