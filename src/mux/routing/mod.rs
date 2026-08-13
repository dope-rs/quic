pub(super) mod registry;
pub(super) mod reset;

use std::hash::BuildHasher as _;
use std::net;
use std::time;

use crate::conn;
use crate::conn::path;
use crate::conn::session;
use crate::conn::transmit::eligibility::Eligibility;
use crate::packet;

use crate::stream;

use self::reset::ResetOps as _;
use crate::mux;
use crate::mux::drive::{DriveOps as _, QueueOps as _};

pub(super) trait AcceptOps {
    fn try_accept(
        &mut self,
        from: net::SocketAddr,
        data: &mut [u8],
        retry_odcid: Option<packet::ConnectionId>,
    ) -> Result<conn::Handle, conn::Error>;
}

pub(super) trait CidOps {
    fn cid_hash(&self, value: &[u8]) -> u64;
    fn cid_bucket(&self, value: &[u8]) -> usize;
    fn cid_record(&self, link: mux::CidLink) -> Option<&mux::CidRecord>;
    fn cid_record_mut(&mut self, link: mux::CidLink) -> Option<&mut mux::CidRecord>;
    fn find_cid(&self, value: &[u8]) -> Option<mux::RoutedCid>;
    fn register_local_cid(
        &mut self,
        handle: conn::Handle,
        key: path::LocalCidKey,
        value: packet::ConnectionId,
    ) -> bool;
    fn register_cid_alias(&mut self, handle: conn::Handle, value: packet::ConnectionId) -> bool;
    fn apply_cid_routes(&mut self, handle: conn::Handle, updates: &[path::RouteUpdate]) -> bool;
    fn unregister_local_cid(&mut self, handle: conn::Handle, key: path::LocalCidKey) -> bool;
    fn unregister_cids(&mut self, handle: conn::Handle);
}

pub(super) trait DeadlineOps<H, P, const DOMAIN: u8, B: stream::ReceiveBuffer>
where
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
{
    fn deadline_peek(&self) -> Option<(usize, time::Instant)>;
    fn deadline_remove(&mut self, index: usize) -> Option<time::Instant>;
    fn deadline_set(&mut self, index: usize, deadline: time::Instant) -> bool;
    fn refresh_deadline(&mut self, handle: conn::Handle, now: time::Instant);
    fn slot_deadline(
        slot: &mux::Slot<'_, H::Connection, P, DOMAIN, B>,
        flush_linked: bool,
        now: time::Instant,
    ) -> Option<time::Instant>;
    fn notify_one(&mut self) -> bool;
}

pub(super) trait SlotOps<'tls, H, P, const DOMAIN: u8, B: stream::ReceiveBuffer>
where
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
{
    fn insert_connection(
        &mut self,
        conn: session::Connection<DOMAIN, B>,
        tls: Option<mux::TlsSession<'tls, P, DOMAIN>>,
        peer_addr: net::SocketAddr,
        max_packet_bytes: usize,
    ) -> Option<conn::Handle>;
    fn remove_slot(&mut self, handle: conn::Handle) -> bool;
    fn finish_connection_mut(&mut self, handle: conn::Handle);
    fn sync_dirty_connection(&mut self);
    fn sync_reset_tokens(&mut self, handle: conn::Handle) -> bool;
    fn handle_for_index(&self, index: usize) -> conn::Handle;
    fn handle_index(&self, handle: conn::Handle) -> Option<usize>;
}

impl<
    'tls,
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
    const DOMAIN: u8,
    B: stream::ReceiveBuffer,
> AcceptOps for mux::Router<'tls, H, P, DOMAIN, B>
{
    fn try_accept(
        &mut self,
        from: net::SocketAddr,
        data: &mut [u8],
        retry_odcid: Option<packet::ConnectionId>,
    ) -> Result<conn::Handle, conn::Error> {
        let server_config = self
            .server
            .as_ref()
            .ok_or(conn::Error::HeaderDecode)?
            .config
            .duplicate_connection()
            .map_err(|_| conn::Error::Tls)?;
        if !matches!(data.first(), Some(&b) if b & 0xb0 == 0x80) {
            return Err(conn::Error::HeaderDecode);
        }
        let cid_prefix = server_config.cid_prefix;
        let prefix = crate::packet::InitialHeader::decode_pre_hp(data)
            .map_err(|_| conn::Error::HeaderDecode)?;
        let initial_dcid = prefix.dcid.into_owned();
        let peer_cid = prefix.scid.into_owned();
        let local_cid = self
            .gen_cid(cid_prefix)
            .ok_or(conn::Error::ConnectionIdLimit)?;
        let client_initial_dcid = initial_dcid;
        let max_packet_bytes = server_config.connection_ceiling(self.outgoing.bytes_capacity);
        if max_packet_bytes < crate::pmtud::BASE_PMTU as usize {
            return Err(conn::Error::PacketCeiling);
        }
        let ids = match retry_odcid {
            Some(odcid) => {
                conn::server::Ids::retry(initial_dcid, local_cid, peer_cid, odcid, initial_dcid)
            }
            None => conn::server::Ids::initial(initial_dcid, local_cid, peer_cid),
        };
        let (connection, tls) = match &self.server.as_ref().ok_or(conn::Error::HeaderDecode)?.shard
        {
            crate::mux::ServerShard::Owned(shard) => {
                let (connection, tls) =
                    conn::setup::build::Builder::server(ids, server_config, shard)
                        .finish()
                        .map_err(|_| conn::Error::Tls)?
                        .into_server()
                        .ok_or(conn::Error::Tls)?;
                (connection, mux::TlsSession::OwnedServer(tls))
            }
            crate::mux::ServerShard::Pooled { pool, .. } => {
                let built = conn::setup::build::Builder::server_pooled(ids, server_config, *pool)
                    .finish()
                    .map_err(|_| conn::Error::Tls)?;
                let conn::setup::build::Built::ServerPooled { connection, tls } = built else {
                    return Err(conn::Error::Tls);
                };
                (connection, mux::TlsSession::Server(tls))
            }
        };
        let handle = self
            .insert_connection(connection, Some(tls), from, max_packet_bytes)
            .ok_or(conn::Error::EventCapacity)?;
        let index = self.handle_index(handle).ok_or(conn::Error::HeaderDecode)?;
        let (local_key, local_cid) = self.registry.entries[index]
            .slot_mut()
            .ok_or(conn::Error::HeaderDecode)?
            .conn
            .enable_cid_routing();
        if !self.register_local_cid(handle, local_key, local_cid) {
            self.remove_slot(handle);
            return Err(conn::Error::HeaderDecode);
        }
        if self.find_cid(&client_initial_dcid).is_none()
            && !self.register_cid_alias(handle, client_initial_dcid)
        {
            self.remove_slot(handle);
            return Err(conn::Error::HeaderDecode);
        }
        Ok(handle)
    }
}

impl<
    'tls,
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
    const DOMAIN: u8,
    B: stream::ReceiveBuffer,
> CidOps for mux::Router<'tls, H, P, DOMAIN, B>
{
    fn cid_hash(&self, value: &[u8]) -> u64 {
        self.registry.indexes.cid_hasher.hash_one(value)
    }

    fn cid_bucket(&self, value: &[u8]) -> usize {
        self.cid_hash(value) as usize & (self.registry.indexes.cid_buckets.len() - 1)
    }

    fn cid_record(&self, link: mux::CidLink) -> Option<&mux::CidRecord> {
        self.registry.entries[link.index()]
            .slot()?
            .identifiers
            .cids
            .get(link.ordinal())
    }

    fn cid_record_mut(&mut self, link: mux::CidLink) -> Option<&mut mux::CidRecord> {
        self.registry.entries[link.index()]
            .slot_mut()?
            .identifiers
            .cids
            .get_mut(link.ordinal())
    }

    fn find_cid(&self, value: &[u8]) -> Option<mux::RoutedCid> {
        let mut current = self.registry.indexes.cid_buckets[self.cid_bucket(value)];
        while let Some(link) = current {
            let record = self.cid_record(link)?;
            if record.value.as_ref().map(packet::ConnectionId::as_slice) == Some(value) {
                return Some(mux::RoutedCid {
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
        handle: conn::Handle,
        key: path::LocalCidKey,
        value: packet::ConnectionId,
    ) -> bool {
        let ordinal = key.slot();
        if ordinal >= conn::MAX_ACTIVE_CONNECTION_IDS {
            return false;
        }
        self.register_cid_at(handle, ordinal, value, Some(key))
    }

    fn register_cid_alias(&mut self, handle: conn::Handle, value: packet::ConnectionId) -> bool {
        let Some(index) = self.handle_index(handle) else {
            return false;
        };
        let Some(ordinal) = self.registry.entries[index].slot().and_then(|slot| {
            slot.identifiers
                .cids
                .iter()
                .skip(conn::MAX_ACTIVE_CONNECTION_IDS)
                .position(|record| record.value.is_none())
                .map(|offset| conn::MAX_ACTIVE_CONNECTION_IDS + offset)
        }) else {
            return false;
        };
        self.register_cid_at(handle, ordinal, value, None)
    }

    fn apply_cid_routes(&mut self, handle: conn::Handle, updates: &[path::RouteUpdate]) -> bool {
        for update in updates {
            let applied = match *update {
                path::RouteUpdate::Add { key, cid } => self.register_local_cid(handle, key, cid),
                path::RouteUpdate::Remove(key) => self.unregister_local_cid(handle, key),
            };
            if !applied {
                return false;
            }
        }
        true
    }

    fn unregister_local_cid(&mut self, handle: conn::Handle, key: path::LocalCidKey) -> bool {
        let Some(index) = self.handle_index(handle) else {
            return false;
        };
        let Some(link) = mux::CidLink::new(index, key.slot()) else {
            return false;
        };
        self.unregister_cid_link(link, Some(key))
    }

    fn unregister_cids(&mut self, handle: conn::Handle) {
        let Some(index) = self.handle_index(handle) else {
            return;
        };
        for ordinal in 0..mux::MAX_CIDS_PER_CONN {
            if let Some(link) = mux::CidLink::new(index, ordinal) {
                self.unregister_cid_link(link, None);
            }
        }
    }
}

impl<
    'tls,
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
    const DOMAIN: u8,
    B: stream::ReceiveBuffer,
> mux::Router<'tls, H, P, DOMAIN, B>
{
    fn register_cid_at(
        &mut self,
        handle: conn::Handle,
        ordinal: usize,
        value: packet::ConnectionId,
        local: Option<path::LocalCidKey>,
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
        let Some(link) = mux::CidLink::new(index, ordinal) else {
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

    fn unregister_cid_link(
        &mut self,
        link: mux::CidLink,
        expected: Option<path::LocalCidKey>,
    ) -> bool {
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
            slot.identifiers.cids[link.ordinal()] = mux::CidRecord::default();
        }
        true
    }
}

impl<
    'tls,
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
    const DOMAIN: u8,
    B: stream::ReceiveBuffer,
> DeadlineOps<H, P, DOMAIN, B> for mux::Router<'tls, H, P, DOMAIN, B>
{
    fn deadline_peek(&self) -> Option<(usize, time::Instant)> {
        self.registry
            .deadlines
            .peek()
            .map(|(index, deadline)| (index, *deadline))
    }

    fn deadline_remove(&mut self, index: usize) -> Option<time::Instant> {
        self.registry.deadlines.remove(index)
    }

    fn deadline_set(&mut self, index: usize, deadline: time::Instant) -> bool {
        self.deadline_remove(index);
        self.registry.deadlines.insert(index, deadline).is_ok()
    }

    fn refresh_deadline(&mut self, handle: conn::Handle, now: time::Instant) {
        let Some(index) = self.handle_index(handle) else {
            return;
        };
        self.queue_remove(mux::QueueKind::Reap, index);
        let Some(slot) = self.registry.entries[index].slot() else {
            self.deadline_remove(index);
            return;
        };
        if slot.conn.status().is_closed() {
            self.deadline_remove(index);
            self.queue_push_back(mux::QueueKind::Reap, index);
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
        slot: &mux::Slot<'_, H::Connection, P, DOMAIN, B>,
        flush_linked: bool,
        now: time::Instant,
    ) -> Option<time::Instant> {
        if slot.conn.status().is_closed() {
            return Some(now);
        }
        let mut deadline = slot.conn.status().next_timer();
        if !flush_linked && let Some(send) = Eligibility::new(&slot.conn).send_deadline(now) {
            deadline = Some(deadline.map_or(send, |timer| timer.min(send)));
        }
        deadline
    }

    fn notify_one(&mut self) -> bool {
        let Some(index) = self.queue_pop_front(mux::QueueKind::Notify) else {
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

impl<
    'tls,
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
    const DOMAIN: u8,
    B: stream::ReceiveBuffer,
> SlotOps<'tls, H, P, DOMAIN, B> for mux::Router<'tls, H, P, DOMAIN, B>
{
    fn insert_connection(
        &mut self,
        mut conn: session::Connection<DOMAIN, B>,
        tls: Option<mux::TlsSession<'tls, P, DOMAIN>>,
        peer_addr: net::SocketAddr,
        max_packet_bytes: usize,
    ) -> Option<conn::Handle> {
        while self.registry.free_head != crate::mux::NONE {
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
            entry.free_next = crate::mux::NONE;
            let handle = conn::Handle::from_parts(index as u32, generation);
            let connection = self.handler.create_connection(&mut conn, handle);
            self.registry.entries[index].insert(mux::Slot::new(
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

    fn remove_slot(&mut self, handle: conn::Handle) -> bool {
        let Some(idx) = self.handle_index(handle) else {
            return false;
        };
        if self.registry.dirty_connection == Some(handle) {
            self.registry.dirty_connection = None;
        }
        self.queue_remove(mux::QueueKind::Notify, idx);
        self.unschedule_flush(handle);
        self.queue_remove(mux::QueueKind::Reap, idx);
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

    fn finish_connection_mut(&mut self, handle: conn::Handle) {
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

    fn sync_reset_tokens(&mut self, handle: conn::Handle) -> bool {
        let Some(index) = self.handle_index(handle) else {
            return false;
        };
        let mut current = [None; conn::MAX_ACTIVE_CONNECTION_IDS];
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

    fn handle_for_index(&self, index: usize) -> conn::Handle {
        conn::Handle::from_parts(index as u32, self.registry.entries[index].generation)
    }

    fn handle_index(&self, handle: conn::Handle) -> Option<usize> {
        let index = handle.index() as usize;
        self.registry
            .entries
            .get(index)
            .is_some_and(|entry| entry.generation == handle.generation() && entry.slot.is_some())
            .then_some(index)
    }
}
