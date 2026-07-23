use std::array::IntoIter;
use std::hash::{BuildHasher, RandomState};
use std::marker::PhantomData;
use std::mem::take;
use std::net::SocketAddr;
use std::num::NonZeroU128;
use std::pin::Pin;
use std::time::Instant;

use dope::DriverContext;
use dope::manifold::datagram;
use o3::collections::FixedQueue;
use o3::collections::IndexedMinHeap;
use shin::server::{ClientCertVerifier, EarlyDataGuard, NoGuard, Shard};
use shin::sig::SigningKey;
use shin::ticket::TicketKeys;

use crate::ConnectError;
use crate::TrySendError;
use crate::clock::WallClock;
use crate::conn::{
    self, Conn, ConnError, ConnHandle, Mutual, MutualAuthentication, PacketBatch, ServerPolicy,
    Standard, StreamEvent,
};
use crate::packet::InitialHeader;
use crate::packet::QUIC_V1;
use crate::packet::RetryPacket;
use crate::pmtud::BASE_PMTU;
use crate::secrets::RetryTokenSecret;
use crate::secrets::StatelessResetSecret;
use std::array::from_fn;
use std::iter;
use std::iter::Take;

pub trait Handler {
    fn established(&mut self, _conn: &mut Conn, _handle: ConnHandle) {}
    fn datagram(&mut self, _conn: &mut Conn, _handle: ConnHandle, _data: Vec<u8>) {}
    fn stream_event(&mut self, _conn: &mut Conn, _handle: ConnHandle, _event: StreamEvent) {}
    fn close(&mut self, _handle: ConnHandle) {}
    fn packet_error(&mut self, _from: SocketAddr, _err: &ConnError, _len: usize) {}
}

struct Slot {
    conn: Conn,
    peer_addr: SocketAddr,
    notified_established: bool,
    max_packet_bytes: usize,
    first_flush: bool,
    cids: [CidRecord; MAX_CIDS_PER_CONN],
}

impl Slot {
    fn new(conn: Conn, peer_addr: SocketAddr, max_packet_bytes: usize) -> Self {
        Self {
            conn,
            peer_addr,
            notified_established: false,
            max_packet_bytes,
            first_flush: true,
            cids: from_fn(|_| CidRecord::default()),
        }
    }
}

struct Entry {
    slot: Option<Slot>,
    generation: u32,
    used: bool,
    free_next: u32,
    flush: QueueLinks,
    reap: QueueLinks,
}

impl Entry {
    fn slot(&self) -> Option<&Slot> {
        self.slot.as_ref()
    }

    fn slot_mut(&mut self) -> Option<&mut Slot> {
        self.slot.as_mut()
    }

    fn insert(&mut self, slot: Slot) {
        debug_assert!(self.slot.is_none());
        self.flush = QueueLinks::default();
        self.reap = QueueLinks::default();
        self.slot = Some(slot);
    }

    fn take(&mut self) -> Option<Slot> {
        self.slot.take()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CidLink(NonZeroU128);

impl CidLink {
    fn new(handle: ConnHandle, ordinal: usize) -> Option<Self> {
        let value = ((u128::from(handle.0) << 4) | ordinal as u128) + 1;
        NonZeroU128::new(value).map(Self)
    }

    fn handle(self) -> ConnHandle {
        ConnHandle(((self.0.get() - 1) >> 4) as u64)
    }

    fn ordinal(self) -> usize {
        ((self.0.get() - 1) & 0xf) as usize
    }
}

#[derive(Default)]
struct CidRecord {
    value: Option<Vec<u8>>,
    prev: Option<CidLink>,
    next: Option<CidLink>,
}

struct QueueLinks {
    prev: u32,
    next: u32,
    linked: bool,
}

impl Default for QueueLinks {
    fn default() -> Self {
        Self {
            prev: NONE,
            next: NONE,
            linked: false,
        }
    }
}

struct QueueState {
    head: u32,
    tail: u32,
    len: usize,
}

impl Default for QueueState {
    fn default() -> Self {
        Self {
            head: NONE,
            tail: NONE,
            len: 0,
        }
    }
}

#[derive(Clone, Copy)]
enum QueueKind {
    Flush,
    Reap,
}

const DEFAULT_MAX_CONNS: usize = 1024;
const DEFAULT_OUTGOING_CAP: usize = 4096;
const DEFAULT_OUTGOING_BYTES_CAP: usize = 16 << 20;
pub(crate) const MAX_CONNECTIONS: usize = 65_536;
pub(crate) const MAX_OUTGOING_CAPACITY: usize = 65_536;
pub(crate) const MAX_OUTGOING_BYTES: usize = 1 << 30;
const FLUSH_PACKET_QUANTUM: usize = 8;
const FLUSH_BYTE_QUANTUM: usize = 64 << 10;
const MAX_CIDS_PER_CONN: usize = 10;
const NONE: u32 = u32::MAX;

enum FlushRound {
    Idle,
    More,
    Backpressure,
    Waiting,
    Closed,
}

pub struct Segments {
    values: [u32; FLUSH_PACKET_QUANTUM],
    len: u8,
}

impl Segments {
    fn from_slice(values: &[u32]) -> Self {
        debug_assert!(values.len() <= FLUSH_PACKET_QUANTUM);
        let mut segments = Self {
            values: [0; FLUSH_PACKET_QUANTUM],
            len: values.len() as u8,
        };
        segments.values[..values.len()].copy_from_slice(values);
        segments
    }

    pub fn as_slice(&self) -> &[u32] {
        &self.values[..self.len as usize]
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl IntoIterator for Segments {
    type Item = u32;
    type IntoIter = Take<IntoIter<u32, FLUSH_PACKET_QUANTUM>>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter().take(self.len as usize)
    }
}

pub enum Outgoing {
    Plain(SocketAddr, Vec<u8>),
    Batch(SocketAddr, Vec<u8>, Segments),
}

impl Outgoing {
    pub fn addr(&self) -> SocketAddr {
        match *self {
            Self::Plain(a, _) | Self::Batch(a, _, _) => a,
        }
    }

    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Plain(_, p) | Self::Batch(_, p, _) => p,
        }
    }

    fn packets(&self) -> usize {
        match self {
            Self::Plain(_, _) => 1,
            Self::Batch(_, _, segments) => segments.len(),
        }
    }

    fn bytes(&self) -> usize {
        self.payload().len()
    }
}

struct ServerRuntime<P: ServerPolicy> {
    config: conn::Config,
    shard: Shard<P::Guard, P::Verifier>,
    _policy: PhantomData<fn() -> P>,
}

impl<P: ServerPolicy> ServerRuntime<P> {
    fn new(config: conn::Config, shard: Shard<P::Guard, P::Verifier>) -> Self {
        Self {
            config,
            shard,
            _policy: PhantomData,
        }
    }
}

pub struct Mux<H: Handler, P: ServerPolicy = Standard> {
    entries: Vec<Entry>,
    free_head: u32,
    cid_buckets: Box<[Option<CidLink>]>,
    cid_hasher: RandomState,
    handler: H,
    server: Option<ServerRuntime<P>>,
    pending_outgoing: FixedQueue<Outgoing>,
    pending_outgoing_packets: usize,
    pending_outgoing_bytes: usize,
    pending_outgoing_bytes_capacity: usize,
    out_batch: PacketBatch,
    recycled_packets: Vec<Vec<u8>>,
    flush: QueueState,
    reap: QueueState,
    deadlines: IndexedMinHeap<Instant>,
    cid_counter: u64,
    active_conns: usize,
    max_conns: usize,
    gso: bool,
}

impl<H: Handler> Mux<H, Standard> {
    fn standard_server(
        signing_key: SigningKey,
        mut config: conn::Config,
    ) -> Result<ServerRuntime<Standard>, ConnectError> {
        config.validate()?;
        let shard_config = Conn::take_server_config(signing_key, &mut config)?;
        Ok(ServerRuntime::new(config, Shard::new(shard_config)))
    }

    pub fn server(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::Config,
    ) -> Result<Self, ConnectError> {
        Self::server_with_outgoing_capacity(
            handler,
            signing_key,
            server_config,
            DEFAULT_OUTGOING_CAP,
        )
    }

    pub fn server_with_outgoing_capacity(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::Config,
        outgoing_capacity: usize,
    ) -> Result<Self, ConnectError> {
        Self::server_with_outgoing_limits(
            handler,
            signing_key,
            server_config,
            outgoing_capacity,
            DEFAULT_OUTGOING_BYTES_CAP,
        )
    }

    pub fn server_with_outgoing_limits(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::Config,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<Self, ConnectError> {
        Self::server_with_limits(
            handler,
            signing_key,
            server_config,
            DEFAULT_MAX_CONNS,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }

    pub fn server_with_limits(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::Config,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<Self, ConnectError> {
        let server = Self::standard_server(signing_key, server_config)?;
        Self::with_limits(
            handler,
            Some(server),
            max_conns,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }

    pub fn client(handler: H) -> Result<Self, ConnectError> {
        Self::client_with_outgoing_capacity(handler, DEFAULT_OUTGOING_CAP)
    }

    pub fn client_with_outgoing_capacity(
        handler: H,
        outgoing_capacity: usize,
    ) -> Result<Self, ConnectError> {
        Self::client_with_outgoing_limits(handler, outgoing_capacity, DEFAULT_OUTGOING_BYTES_CAP)
    }

    pub fn client_with_outgoing_limits(
        handler: H,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<Self, ConnectError> {
        Self::client_with_limits(
            handler,
            DEFAULT_MAX_CONNS,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }

    pub fn client_with_limits(
        handler: H,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<Self, ConnectError> {
        Self::with_limits(
            handler,
            None,
            max_conns,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }
}

impl<H, G> Mux<H, Standard<G>>
where
    H: Handler,
    G: EarlyDataGuard + 'static,
{
    pub fn server_with_early_data_guard(
        handler: H,
        signing_key: SigningKey,
        mut server_config: conn::Config,
        guard: G,
    ) -> Result<Self, ConnectError> {
        server_config.validate()?;
        let shard_config = Conn::take_server_config(signing_key, &mut server_config)?;
        let server = ServerRuntime::new(
            server_config,
            Shard::with_early_data_guard(shard_config, guard),
        );
        Self::with_limits(
            handler,
            Some(server),
            DEFAULT_MAX_CONNS,
            DEFAULT_OUTGOING_CAP,
            DEFAULT_OUTGOING_BYTES_CAP,
        )
    }

    pub fn server_with_early_data_guard_and_limits(
        handler: H,
        signing_key: SigningKey,
        mut server_config: conn::Config,
        guard: G,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<Self, ConnectError> {
        server_config.validate()?;
        let shard_config = Conn::take_server_config(signing_key, &mut server_config)?;
        let server = ServerRuntime::new(
            server_config,
            Shard::with_early_data_guard(shard_config, guard),
        );
        Self::with_limits(
            handler,
            Some(server),
            max_conns,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }
}

impl<H, V> Mux<H, Mutual<NoGuard, V>>
where
    H: Handler,
    V: ClientCertVerifier + 'static,
{
    pub fn server_mutual(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::Config,
        authentication: MutualAuthentication<V>,
    ) -> Result<Self, ConnectError> {
        Self::server_mutual_with_limits(
            handler,
            signing_key,
            server_config,
            authentication,
            DEFAULT_MAX_CONNS,
            DEFAULT_OUTGOING_CAP,
            DEFAULT_OUTGOING_BYTES_CAP,
        )
    }

    pub fn server_mutual_with_limits(
        handler: H,
        signing_key: SigningKey,
        mut server_config: conn::Config,
        authentication: MutualAuthentication<V>,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<Self, ConnectError> {
        server_config.validate()?;
        let shard_config = Conn::take_server_config(signing_key, &mut server_config)?;
        let (_, auth, verifier) = authentication.into_parts();
        let server = ServerRuntime::new(
            server_config,
            Shard::with_client_auth(shard_config, auth, verifier),
        );
        Self::with_limits(
            handler,
            Some(server),
            max_conns,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }
}

impl<H, G, V> Mux<H, Mutual<G, V>>
where
    H: Handler,
    G: EarlyDataGuard + 'static,
    V: ClientCertVerifier + 'static,
{
    pub fn server_mutual_with_early_data_guard(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::Config,
        authentication: MutualAuthentication<V, G>,
    ) -> Result<Self, ConnectError> {
        Self::server_mutual_with_early_data_guard_and_limits(
            handler,
            signing_key,
            server_config,
            authentication,
            DEFAULT_MAX_CONNS,
            DEFAULT_OUTGOING_CAP,
            DEFAULT_OUTGOING_BYTES_CAP,
        )
    }

    pub fn server_mutual_with_early_data_guard_and_limits(
        handler: H,
        signing_key: SigningKey,
        mut server_config: conn::Config,
        authentication: MutualAuthentication<V, G>,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<Self, ConnectError> {
        server_config.validate()?;
        let shard_config = Conn::take_server_config(signing_key, &mut server_config)?;
        let (guard, auth, verifier) = authentication.into_parts();
        let server = ServerRuntime::new(
            server_config,
            Shard::with_early_data_guard_and_client_auth(shard_config, guard, auth, verifier),
        );
        Self::with_limits(
            handler,
            Some(server),
            max_conns,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }
}

impl<H: Handler, P: ServerPolicy> Mux<H, P> {
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

    fn parse_dcid(wire: &[u8], short_header_dcid_len: usize) -> Option<&[u8]> {
        let first = *wire.first()?;
        if first & 0x80 != 0 {
            if wire.len() < 6 {
                return None;
            }
            let dcid_len = wire[5] as usize;
            if wire.len() < 6 + dcid_len {
                return None;
            }
            Some(&wire[6..6 + dcid_len])
        } else {
            if wire.len() < 1 + short_header_dcid_len {
                return None;
            }
            Some(&wire[1..1 + short_header_dcid_len])
        }
    }

    fn with_limits(
        handler: H,
        server: Option<ServerRuntime<P>>,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<Self, ConnectError> {
        if max_conns == 0
            || max_conns > MAX_CONNECTIONS
            || outgoing_capacity == 0
            || outgoing_capacity > MAX_OUTGOING_CAPACITY
            || outgoing_bytes_capacity == 0
            || outgoing_bytes_capacity > MAX_OUTGOING_BYTES
        {
            return Err(ConnectError::InvalidConfig);
        }
        if let Some(server) = &server {
            server.config.validate()?;
        }
        Ok(Self {
            entries: Self::entry_arena(max_conns),
            free_head: 0,
            cid_buckets: vec![None; Self::cid_bucket_count(max_conns)].into_boxed_slice(),
            cid_hasher: RandomState::new(),
            handler,
            server,
            pending_outgoing: FixedQueue::with_capacity(outgoing_capacity),
            pending_outgoing_packets: 0,
            pending_outgoing_bytes: 0,
            pending_outgoing_bytes_capacity: outgoing_bytes_capacity,
            out_batch: PacketBatch::default(),
            recycled_packets: Vec::with_capacity(outgoing_capacity),
            flush: QueueState::default(),
            reap: QueueState::default(),
            deadlines: IndexedMinHeap::with_capacity(max_conns),
            cid_counter: 0,
            active_conns: 0,
            max_conns,
            gso: false,
        })
    }

    fn max_packet_bytes(config: &conn::Config) -> usize {
        config.max_pmtu as usize
    }

    fn connection_packet_ceiling(&self, config: &conn::Config) -> usize {
        Self::max_packet_bytes(config).min(self.pending_outgoing_bytes_capacity)
    }

    fn cid_bucket_count(max_conns: usize) -> usize {
        max_conns
            .max(1)
            .saturating_mul(2)
            .checked_next_power_of_two()
            .unwrap_or(1usize << (usize::BITS - 1))
    }

    fn entry_arena(capacity: usize) -> Vec<Entry> {
        (0..capacity)
            .map(|index| Entry {
                slot: None,
                generation: 0,
                used: false,
                free_next: if index + 1 == capacity {
                    NONE
                } else {
                    index as u32 + 1
                },
                flush: QueueLinks::default(),
                reap: QueueLinks::default(),
            })
            .collect()
    }

    pub fn set_gso(&mut self, on: bool) {
        self.gso = on;
    }

    #[must_use]
    pub fn set_max_conns(&mut self, max: usize) -> bool {
        if self.active_conns != 0 || max == 0 || max > MAX_CONNECTIONS {
            return false;
        }
        self.max_conns = max;
        if self.max_conns > self.entries.len() {
            let old_len = self.entries.len();
            let old_free = self.free_head;
            self.deadlines.grow_to(self.max_conns);
            self.entries.reserve(self.max_conns - old_len);
            self.entries
                .extend((old_len..self.max_conns).map(|index| Entry {
                    slot: None,
                    generation: 0,
                    used: false,
                    free_next: if index + 1 == self.max_conns {
                        old_free
                    } else {
                        index as u32 + 1
                    },
                    flush: QueueLinks::default(),
                    reap: QueueLinks::default(),
                }));
            self.free_head = old_len as u32;
        }
        self.cid_buckets = vec![None; Self::cid_bucket_count(self.max_conns)].into_boxed_slice();
        true
    }

    pub fn active_conns(&self) -> usize {
        self.active_conns
    }

    pub fn outgoing_capacity(&self) -> usize {
        self.pending_outgoing.capacity()
    }

    pub fn outgoing_len(&self) -> usize {
        self.pending_outgoing_packets
    }

    pub fn outgoing_bytes(&self) -> usize {
        self.pending_outgoing_bytes
    }

    pub fn outgoing_bytes_capacity(&self) -> usize {
        self.pending_outgoing_bytes_capacity
    }

    pub fn handler(&self) -> &H {
        &self.handler
    }

    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    pub fn replace_ticket_keys(&mut self, keys: Option<TicketKeys>) -> bool {
        let Some(server) = self.server.as_mut() else {
            return false;
        };
        server.shard.replace_ticket_keys(keys);
        true
    }

    pub fn connect(
        &mut self,
        peer_addr: SocketAddr,
        server_pubkey: [u8; 32],
        client_config: conn::Config,
        initial_dcid: Vec<u8>,
        now: Instant,
    ) -> Result<ConnHandle, ConnectError> {
        if self.active_conns >= self.max_conns {
            return Err(ConnectError::Capacity);
        }
        client_config.validate()?;
        let max_packet_bytes = self.connection_packet_ceiling(&client_config);
        if max_packet_bytes < BASE_PMTU as usize {
            return Err(ConnectError::InvalidConfig);
        }
        let local_cid = self.gen_cid(initial_dcid.len(), client_config.cid_prefix);
        let conn = Conn::new_client(
            initial_dcid,
            local_cid.clone(),
            server_pubkey,
            client_config,
        )?;
        let handle = self
            .insert_slot(Slot::new(conn, peer_addr, max_packet_bytes))
            .ok_or(ConnectError::Capacity)?;
        let registered = self.register_cid(handle, local_cid);
        debug_assert!(registered);
        self.schedule_flush(handle);
        self.flush_ready(now);
        self.refresh_deadline(handle, now);
        Ok(handle)
    }

    pub fn recv(&mut self, from: SocketAddr, data: &[u8], now: Instant) -> Result<(), ConnError> {
        let dcid = Self::parse_dcid(data, 8);
        let handle = match dcid.and_then(|value| self.find_cid(value)) {
            Some(h) => h,
            None if Self::is_initial_packet(data) && self.server.is_some() => {
                if self.active_conns >= self.max_conns {
                    return Ok(());
                }
                match self.maybe_handle_retry_gating(from, data)? {
                    RetryGate::Accept(retry_odcid) => self.try_accept(from, data, retry_odcid)?,
                    RetryGate::IssuedRetry | RetryGate::Drop => return Ok(()),
                }
            }
            None => {
                if self.receive_stateless_reset(from, data, now) {
                    return Ok(());
                }
                self.emit_stateless_reset(from, data);
                return Ok(());
            }
        };
        let index = self.handle_index(handle).ok_or(ConnError::HeaderDecode)?;
        let new_cids = {
            let server = &mut self.server;
            let slot = self.entries[index]
                .slot_mut()
                .ok_or(ConnError::HeaderDecode)?;
            if slot.conn.is_client() {
                slot.conn.recv_packet(data, now)?;
            } else {
                let server = server.as_mut().ok_or(ConnError::HeaderDecode)?;
                slot.conn.recv_packet_server(data, now, &mut server.shard)?;
            }
            slot.conn.take_cids_to_register()
        };
        for cid in new_cids {
            if !self.register_cid(handle, cid) {
                self.remove_slot(handle);
                return Err(ConnError::HeaderDecode);
            }
        }
        self.notify(handle);
        self.schedule_flush(handle);
        self.flush_ready(now);
        self.refresh_deadline(handle, now);
        Ok(())
    }

    pub fn drain_outgoing(&mut self) -> impl Iterator<Item = Outgoing> + '_ {
        let now = Instant::now();
        iter::from_fn(move || {
            let outgoing = self.pop_outgoing()?;
            self.flush_ready(now);
            Some(outgoing)
        })
    }

    pub(crate) fn pop_outgoing(&mut self) -> Option<Outgoing> {
        let outgoing = self.pending_outgoing.pop_front()?;
        self.pending_outgoing_packets -= outgoing.packets();
        self.pending_outgoing_bytes -= outgoing.bytes();
        Some(outgoing)
    }

    pub(crate) fn push_outgoing_front(&mut self, outgoing: Outgoing) -> Result<(), Outgoing> {
        let packets = outgoing.packets();
        let bytes = outgoing.bytes();
        self.pending_outgoing.push_front(outgoing)?;
        self.pending_outgoing_packets += packets;
        self.pending_outgoing_bytes += bytes;
        Ok(())
    }

    pub(crate) fn has_buffered_outgoing(&self) -> bool {
        !self.pending_outgoing.is_empty()
    }

    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        if self.reap.len != 0 {
            return Some(now);
        }
        self.deadline_peek().map(|(_, deadline)| deadline)
    }

    pub(crate) fn refill_outgoing(&mut self, now: Instant) {
        self.flush_ready(now);
    }

    pub fn conn_mut(&mut self, handle: ConnHandle) -> Option<&mut Conn> {
        let index = self.handle_index(handle)?;
        self.queue_push_back(QueueKind::Reap, index);
        self.entries[index].slot_mut().map(|slot| &mut slot.conn)
    }

    pub fn conn(&self, handle: ConnHandle) -> Option<&Conn> {
        let index = self.handle_index(handle)?;
        self.entries[index].slot().map(|slot| &slot.conn)
    }

    pub fn flush(&mut self, handle: ConnHandle, now: Instant) {
        self.schedule_flush(handle);
        self.flush_ready(now);
        self.refresh_deadline(handle, now);
    }

    pub fn try_send_datagram(
        &mut self,
        handle: ConnHandle,
        data: Vec<u8>,
        now: Instant,
    ) -> Result<(), crate::TrySendError<Vec<u8>>> {
        let result = match self
            .handle_index(handle)
            .and_then(|index| self.entries.get_mut(index))
            .and_then(Entry::slot_mut)
        {
            Some(slot) => slot.conn.try_send_datagram(data),
            None => Err(TrySendError::Closed(data)),
        };
        self.schedule_flush(handle);
        self.flush_ready(now);
        self.refresh_deadline(handle, now);
        result
    }

    pub fn close(&mut self, handle: ConnHandle) {
        self.remove_slot(handle);
    }

    pub fn reap_closed(&mut self, now: Instant) {
        while let Some((index, deadline)) = self.deadline_peek() {
            if deadline > now {
                break;
            }
            self.deadline_remove(index);
            self.queue_push_back(QueueKind::Reap, index);
        }

        let pass = self.reap.len;
        for _ in 0..pass {
            let Some(index) = self.queue_pop_front(QueueKind::Reap) else {
                break;
            };
            let handle = self.handle_for_index(index);
            let Some(slot) = self.entries[index].slot_mut() else {
                continue;
            };
            slot.conn.check_loss(now);
            if slot.conn.is_closed() {
                self.remove_slot(handle);
            } else {
                self.schedule_flush(handle);
            }
        }
        self.flush_ready(now);
        let pass = self.reap.len;
        for _ in 0..pass {
            let Some(index) = self.queue_pop_front(QueueKind::Reap) else {
                break;
            };
            let handle = self.handle_for_index(index);
            if self.entries[index]
                .slot()
                .is_some_and(|slot| slot.conn.is_closed())
            {
                self.remove_slot(handle);
            } else {
                self.refresh_deadline(handle, now);
            }
        }
    }

    fn try_accept(
        &mut self,
        from: SocketAddr,
        data: &[u8],
        retry_odcid: Option<Vec<u8>>,
    ) -> Result<ConnHandle, ConnError> {
        let server_config = self
            .server
            .as_ref()
            .ok_or(ConnError::HeaderDecode)?
            .config
            .duplicate_connection()
            .map_err(|_| ConnError::Tls)?;
        if !matches!(data.first(), Some(&b) if b & 0xb0 == 0x80) {
            return Err(ConnError::HeaderDecode);
        }
        let cid_prefix = server_config.cid_prefix;
        let prefix = InitialHeader::decode_pre_hp(data).map_err(|_| ConnError::HeaderDecode)?;
        let initial_dcid = prefix.dcid;
        let peer_cid = prefix.scid;
        let local_cid = self.gen_cid(initial_dcid.len(), cid_prefix);
        let client_initial_dcid = initial_dcid.clone();
        let max_packet_bytes = self.connection_packet_ceiling(&server_config);
        if max_packet_bytes < BASE_PMTU as usize {
            return Err(ConnError::PacketCeiling);
        }
        let conn = match retry_odcid {
            Some(odcid) => Conn::new_server_connection_retry(
                initial_dcid.clone(),
                local_cid.clone(),
                peer_cid,
                odcid,
                initial_dcid,
                server_config,
            ),
            None => Conn::new_server_connection(
                initial_dcid,
                local_cid.clone(),
                peer_cid,
                server_config,
            ),
        }
        .map_err(|_| ConnError::Tls)?;
        let handle = self
            .insert_slot(Slot::new(conn, from, max_packet_bytes))
            .ok_or(ConnError::EventCapacity)?;
        if !self.register_cid(handle, local_cid) {
            self.remove_slot(handle);
            return Err(ConnError::HeaderDecode);
        }
        if self.find_cid(&client_initial_dcid).is_none()
            && !self.register_cid(handle, client_initial_dcid)
        {
            self.remove_slot(handle);
            return Err(ConnError::HeaderDecode);
        }
        Ok(handle)
    }

    fn flush_conn_round(&mut self, handle: ConnHandle, now: Instant) -> FlushRound {
        let packet_room = self
            .pending_outgoing
            .capacity()
            .saturating_sub(self.pending_outgoing_packets)
            .min(FLUSH_PACKET_QUANTUM);
        if packet_room == 0 {
            return FlushRound::Backpressure;
        }
        let Some(idx) = self.handle_index(handle) else {
            return FlushRound::Closed;
        };
        let Some(max_packet_bytes) = self.entries.get(idx).and_then(Entry::slot).map(|slot| {
            if slot.first_flush {
                BASE_PMTU as usize
            } else {
                slot.max_packet_bytes
            }
        }) else {
            return FlushRound::Closed;
        };
        if max_packet_bytes > self.pending_outgoing_bytes_capacity {
            self.remove_slot(handle);
            return FlushRound::Closed;
        }
        let global_byte_room = self
            .pending_outgoing_bytes_capacity
            .saturating_sub(self.pending_outgoing_bytes);
        let byte_room = global_byte_room.min(FLUSH_BYTE_QUANTUM.max(max_packet_bytes));
        let packet_limit = packet_room.min(byte_room / max_packet_bytes);
        if packet_limit == 0 {
            return FlushRound::Backpressure;
        }
        if self.gso {
            let mut batch = take(&mut self.out_batch);
            let addr = match self.entries.get_mut(idx).and_then(Entry::slot_mut) {
                Some(s) => {
                    s.conn
                        .send_batch(&mut batch, now, packet_limit, max_packet_bytes);
                    s.peer_addr
                }
                None => {
                    self.out_batch = batch;
                    return FlushRound::Closed;
                }
            };
            let outgoing = Self::coalesce_gso(addr, &mut batch);
            let mut produced = false;
            if let Some(outgoing) = outgoing
                && self.push_outgoing(outgoing).is_ok()
            {
                produced = true;
                if let Some(slot) = self.entries.get_mut(idx).and_then(Entry::slot_mut) {
                    slot.first_flush = false;
                }
            }
            self.out_batch = batch;
            let pending = self
                .entries
                .get(idx)
                .and_then(Entry::slot)
                .is_some_and(|slot| slot.conn.has_pending_output());
            if pending && produced {
                FlushRound::More
            } else if pending {
                FlushRound::Waiting
            } else {
                FlushRound::Idle
            }
        } else {
            let addr = match self.entries.get(idx).and_then(Entry::slot) {
                Some(s) => s.peer_addr,
                None => return FlushRound::Closed,
            };
            let mut packets_left = packet_limit;
            while packets_left != 0 {
                let mut packet = self.recycled_packets.pop().unwrap_or_default();
                packet.clear();
                let emitted = match self.entries.get_mut(idx).and_then(Entry::slot_mut) {
                    Some(s) => s.conn.send_one(&mut packet, now, max_packet_bytes),
                    None => false,
                };
                if !emitted {
                    self.recycle_packet(packet);
                    break;
                }
                if self.push_outgoing(Outgoing::Plain(addr, packet)).is_err() {
                    break;
                }
                if let Some(slot) = self.entries.get_mut(idx).and_then(Entry::slot_mut) {
                    slot.first_flush = false;
                }
                packets_left -= 1;
            }
            let pending = self
                .entries
                .get(idx)
                .and_then(Entry::slot)
                .is_some_and(|slot| slot.conn.has_pending_output());
            if pending && packets_left != packet_limit {
                FlushRound::More
            } else if pending {
                FlushRound::Waiting
            } else {
                FlushRound::Idle
            }
        }
    }

    pub(crate) fn recycle_packet(&mut self, mut packet: Vec<u8>) {
        packet.clear();
        if self.gso && self.out_batch.buf.capacity() == 0 {
            self.out_batch.buf = packet;
            return;
        }
        if self.recycled_packets.len() < self.recycled_packets.capacity() {
            self.recycled_packets.push(packet);
        }
    }

    fn coalesce_gso(addr: SocketAddr, batch: &mut PacketBatch) -> Option<Outgoing> {
        let n = batch.segs.len();
        if n == 0 {
            return None;
        }
        if n == 1 {
            batch.segs.clear();
            return Some(Outgoing::Plain(addr, take(&mut batch.buf)));
        }
        let segments = Segments::from_slice(&batch.segs);
        batch.segs.clear();
        Some(Outgoing::Batch(addr, take(&mut batch.buf), segments))
    }

    fn schedule_flush(&mut self, handle: ConnHandle) {
        let Some(idx) = self.handle_index(handle) else {
            return;
        };
        self.queue_push_back(QueueKind::Flush, idx);
    }

    fn pop_flush(&mut self) -> Option<ConnHandle> {
        let index = self.queue_pop_front(QueueKind::Flush)?;
        Some(self.handle_for_index(index))
    }

    fn unschedule_flush(&mut self, handle: ConnHandle) {
        let Some(idx) = self.handle_index(handle) else {
            return;
        };
        self.queue_remove(QueueKind::Flush, idx);
    }

    fn flush_ready(&mut self, now: Instant) {
        if self.pending_outgoing.capacity() == 0 || self.pending_outgoing_bytes_capacity == 0 {
            while let Some(handle) = self.pop_flush() {
                self.remove_slot(handle);
            }
            return;
        }
        loop {
            let pass = self.flush.len;
            if pass == 0
                || self.pending_outgoing_packets == self.pending_outgoing.capacity()
                || self.pending_outgoing_bytes == self.pending_outgoing_bytes_capacity
            {
                break;
            }
            let mut progressed = false;
            for _ in 0..pass {
                let Some(handle) = self.pop_flush() else {
                    break;
                };
                let packets = self.pending_outgoing_packets;
                match self.flush_conn_round(handle, now) {
                    FlushRound::More | FlushRound::Backpressure => {
                        if self.handle_index(handle).is_some() {
                            self.schedule_flush(handle);
                        }
                    }
                    FlushRound::Idle | FlushRound::Waiting | FlushRound::Closed => {}
                }
                self.refresh_deadline(handle, now);
                progressed |= self.pending_outgoing_packets != packets;
            }
            if !progressed {
                break;
            }
        }
    }

    fn push_outgoing(&mut self, outgoing: Outgoing) -> Result<(), Outgoing> {
        let packets = outgoing.packets();
        let bytes = outgoing.bytes();
        if packets > self.pending_outgoing.capacity() - self.pending_outgoing_packets
            || bytes > self.pending_outgoing_bytes_capacity - self.pending_outgoing_bytes
        {
            return Err(outgoing);
        }
        let packets = outgoing.packets();
        let bytes = outgoing.bytes();
        self.pending_outgoing.push_back(outgoing)?;
        self.pending_outgoing_packets += packets;
        self.pending_outgoing_bytes += bytes;
        Ok(())
    }

    fn push_checked_packet(
        &mut self,
        addr: SocketAddr,
        payload: Vec<u8>,
        packet_ceiling: usize,
    ) -> bool {
        if !self.packet_fits(payload.len(), packet_ceiling) {
            return false;
        }
        self.push_outgoing(Outgoing::Plain(addr, payload)).is_ok()
    }

    fn packet_fits(&self, bytes: usize, packet_ceiling: usize) -> bool {
        bytes != 0
            && bytes <= packet_ceiling
            && self.pending_outgoing_packets < self.pending_outgoing.capacity()
            && bytes
                <= self
                    .pending_outgoing_bytes_capacity
                    .saturating_sub(self.pending_outgoing_bytes)
    }

    fn queue(&self, kind: QueueKind) -> &QueueState {
        match kind {
            QueueKind::Flush => &self.flush,
            QueueKind::Reap => &self.reap,
        }
    }

    fn queue_mut(&mut self, kind: QueueKind) -> &mut QueueState {
        match kind {
            QueueKind::Flush => &mut self.flush,
            QueueKind::Reap => &mut self.reap,
        }
    }

    fn queue_links(&self, kind: QueueKind, index: usize) -> &QueueLinks {
        let entry = &self.entries[index];
        match kind {
            QueueKind::Flush => &entry.flush,
            QueueKind::Reap => &entry.reap,
        }
    }

    fn queue_links_mut(&mut self, kind: QueueKind, index: usize) -> &mut QueueLinks {
        let entry = &mut self.entries[index];
        match kind {
            QueueKind::Flush => &mut entry.flush,
            QueueKind::Reap => &mut entry.reap,
        }
    }

    fn queue_push_back(&mut self, kind: QueueKind, index: usize) -> bool {
        if self.queue_links(kind, index).linked {
            return false;
        }
        let tail = self.queue(kind).tail;
        if tail != NONE {
            self.queue_links_mut(kind, tail as usize).next = index as u32;
        }
        let links = self.queue_links_mut(kind, index);
        links.prev = tail;
        links.next = NONE;
        links.linked = true;
        let queue = self.queue_mut(kind);
        if tail == NONE {
            queue.head = index as u32;
        }
        queue.tail = index as u32;
        queue.len += 1;
        true
    }

    fn queue_pop_front(&mut self, kind: QueueKind) -> Option<usize> {
        let index = self.queue(kind).head;
        (index != NONE).then(|| {
            let index = index as usize;
            self.queue_remove(kind, index);
            index
        })
    }

    fn queue_remove(&mut self, kind: QueueKind, index: usize) -> bool {
        let links = self.queue_links(kind, index);
        if !links.linked {
            return false;
        }
        let prev = links.prev;
        let next = links.next;
        if prev == NONE {
            self.queue_mut(kind).head = next;
        } else {
            self.queue_links_mut(kind, prev as usize).next = next;
        }
        if next == NONE {
            self.queue_mut(kind).tail = prev;
        } else {
            self.queue_links_mut(kind, next as usize).prev = prev;
        }
        *self.queue_links_mut(kind, index) = QueueLinks::default();
        self.queue_mut(kind).len -= 1;
        true
    }

    fn cid_hash(&self, value: &[u8]) -> u64 {
        self.cid_hasher.hash_one(value)
    }

    fn cid_bucket(&self, value: &[u8]) -> usize {
        self.cid_hash(value) as usize & (self.cid_buckets.len() - 1)
    }

    fn cid_record(&self, link: CidLink) -> Option<&CidRecord> {
        let index = self.handle_index(link.handle())?;
        self.entries[index].slot()?.cids.get(link.ordinal())
    }

    fn cid_record_mut(&mut self, link: CidLink) -> Option<&mut CidRecord> {
        let index = self.handle_index(link.handle())?;
        self.entries[index].slot_mut()?.cids.get_mut(link.ordinal())
    }

    fn find_cid(&self, value: &[u8]) -> Option<ConnHandle> {
        let mut current = self.cid_buckets[self.cid_bucket(value)];
        while let Some(link) = current {
            let record = self.cid_record(link)?;
            if record.value.as_deref() == Some(value) {
                return Some(link.handle());
            }
            current = record.next;
        }
        None
    }

    fn register_cid(&mut self, handle: ConnHandle, value: Vec<u8>) -> bool {
        if self.find_cid(&value).is_some() {
            return true;
        }
        let Some(index) = self.handle_index(handle) else {
            return false;
        };
        let Some(ordinal) = self.entries[index]
            .slot()
            .and_then(|slot| slot.cids.iter().position(|record| record.value.is_none()))
        else {
            return false;
        };
        let bucket = self.cid_bucket(&value);
        let next = self.cid_buckets[bucket];
        let Some(link) = CidLink::new(handle, ordinal) else {
            return false;
        };
        let Some(slot) = self.entries[index].slot_mut() else {
            return false;
        };
        let record = &mut slot.cids[ordinal];
        record.value = Some(value);
        record.prev = None;
        record.next = next;
        if let Some(next) = next {
            let Some(record) = self.cid_record_mut(next) else {
                return false;
            };
            record.prev = Some(link);
        }
        self.cid_buckets[bucket] = Some(link);
        true
    }

    fn unregister_cids(&mut self, handle: ConnHandle) {
        let Some(index) = self.handle_index(handle) else {
            return;
        };
        for ordinal in 0..MAX_CIDS_PER_CONN {
            let Some(link) = CidLink::new(handle, ordinal) else {
                continue;
            };
            let Some((bucket, prev, next)) = self.entries[index]
                .slot()
                .and_then(|slot| {
                    slot.cids[ordinal]
                        .value
                        .as_deref()
                        .map(|value| self.cid_bucket(value))
                })
                .and_then(|bucket| {
                    self.entries[index]
                        .slot()
                        .map(|slot| (bucket, slot.cids[ordinal].prev, slot.cids[ordinal].next))
                })
            else {
                continue;
            };
            if let Some(prev) = prev {
                if let Some(record) = self.cid_record_mut(prev) {
                    record.next = next;
                }
            } else {
                debug_assert_eq!(self.cid_buckets[bucket], Some(link));
                self.cid_buckets[bucket] = next;
            }
            if let Some(next) = next
                && let Some(record) = self.cid_record_mut(next)
            {
                record.prev = prev;
            }
            if let Some(slot) = self.entries[index].slot_mut() {
                slot.cids[ordinal] = CidRecord::default();
            }
        }
    }

    fn deadline_peek(&self) -> Option<(usize, Instant)> {
        self.deadlines
            .peek()
            .map(|(index, deadline)| (index, *deadline))
    }

    fn deadline_remove(&mut self, index: usize) -> Option<Instant> {
        self.deadlines.remove(index)
    }

    fn deadline_set(&mut self, index: usize, deadline: Instant) -> bool {
        self.deadline_remove(index);
        self.deadlines.insert(index, deadline).is_ok()
    }

    fn refresh_deadline(&mut self, handle: ConnHandle, now: Instant) {
        let Some(index) = self.handle_index(handle) else {
            return;
        };
        self.queue_remove(QueueKind::Reap, index);
        let Some(slot) = self.entries[index].slot() else {
            self.deadline_remove(index);
            return;
        };
        if slot.conn.is_closed() {
            self.deadline_remove(index);
            self.queue_push_back(QueueKind::Reap, index);
            return;
        }
        let deadline = Self::slot_deadline(slot, self.entries[index].flush.linked, now);
        match deadline {
            Some(deadline) => {
                self.deadline_set(index, deadline);
            }
            None => {
                self.deadline_remove(index);
            }
        }
    }

    fn slot_deadline(slot: &Slot, flush_linked: bool, now: Instant) -> Option<Instant> {
        if slot.conn.is_closed() {
            return Some(now);
        }
        let mut deadline = slot.conn.next_timer();
        if !flush_linked && let Some(send) = slot.conn.send_deadline(now) {
            deadline = Some(deadline.map_or(send, |timer| timer.min(send)));
        }
        deadline
    }

    fn notify(&mut self, handle: ConnHandle) {
        let Some(index) = self.handle_index(handle) else {
            return;
        };
        let slot = match self.entries[index].slot_mut() {
            Some(s) => s,
            None => return,
        };
        if slot.conn.is_established() && !slot.notified_established {
            slot.notified_established = true;
            self.handler.established(&mut slot.conn, handle);
        }
        while let Some(dg) = slot.conn.recv_datagram() {
            self.handler.datagram(&mut slot.conn, handle, dg);
        }
        while let Some(ev) = slot.conn.poll_stream_event() {
            self.handler.stream_event(&mut slot.conn, handle, ev);
        }
    }

    fn insert_slot(&mut self, slot: Slot) -> Option<ConnHandle> {
        let mut slot = Some(slot);
        while self.free_head != NONE {
            let index = self.free_head as usize;
            let entry = &mut self.entries[index];
            self.free_head = entry.free_next;
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
            let value = slot.take()?;
            entry.insert(value);
            self.active_conns = self.active_conns.saturating_add(1);
            return Some(ConnHandle::from_parts(index as u32, generation));
        }
        None
    }

    fn remove_slot(&mut self, handle: ConnHandle) -> bool {
        let Some(idx) = self.handle_index(handle) else {
            return false;
        };
        self.unschedule_flush(handle);
        self.queue_remove(QueueKind::Reap, idx);
        self.deadline_remove(idx);
        self.unregister_cids(handle);
        let Some(slot) = self.entries[idx].take() else {
            return false;
        };
        self.active_conns = self.active_conns.saturating_sub(1);
        self.entries[idx].free_next = self.free_head;
        self.free_head = idx as u32;
        drop(slot);
        self.handler.close(handle);
        true
    }

    fn handle_for_index(&self, index: usize) -> ConnHandle {
        ConnHandle::from_parts(index as u32, self.entries[index].generation)
    }

    fn handle_index(&self, handle: ConnHandle) -> Option<usize> {
        let index = handle.index() as usize;
        self.entries
            .get(index)
            .is_some_and(|entry| entry.generation == handle.generation() && entry.slot.is_some())
            .then_some(index)
    }

    fn maybe_handle_retry_gating(
        &mut self,
        from: SocketAddr,
        data: &[u8],
    ) -> Result<RetryGate, ConnError> {
        let (require_address_validation, retry_token_secret, cid_prefix, configured_ceiling) = {
            let server_config = &self.server.as_ref().ok_or(ConnError::HeaderDecode)?.config;
            (
                server_config.require_address_validation,
                server_config.retry_token_secret,
                server_config.cid_prefix,
                Self::max_packet_bytes(server_config),
            )
        };
        if !require_address_validation {
            return Ok(RetryGate::Accept(None));
        }
        let secret = match retry_token_secret {
            Some(s) => RetryTokenSecret(s),
            None => return Ok(RetryGate::Accept(None)),
        };
        let prefix = InitialHeader::decode_pre_hp(data).map_err(|_| ConnError::HeaderDecode)?;
        if prefix.token.is_empty() {
            let now_secs = WallClock::now().unix_seconds();
            let expiry = now_secs.saturating_add(10);
            let token = secret.issue(&from, &prefix.dcid, expiry);
            let new_scid = self.gen_cid(prefix.dcid.len(), cid_prefix);
            let mut retry = RetryPacket {
                version: QUIC_V1,
                dcid: prefix.scid.clone(),
                scid: new_scid,
                token,
                integrity_tag: [0u8; 16],
            };
            let packet_ceiling = configured_ceiling
                .min(self.pending_outgoing_bytes_capacity)
                .min(data.len().saturating_mul(3));
            let Some(encoded_len) = 7usize
                .checked_add(retry.dcid.len())
                .and_then(|len| len.checked_add(retry.scid.len()))
                .and_then(|len| len.checked_add(retry.token.len()))
                .and_then(|len| len.checked_add(16))
            else {
                return Ok(RetryGate::Drop);
            };
            if !self.packet_fits(encoded_len, packet_ceiling) {
                return Ok(RetryGate::Drop);
            }
            let Ok(integrity_tag) = retry.compute_integrity_tag(&prefix.dcid) else {
                return Ok(RetryGate::Drop);
            };
            retry.integrity_tag = integrity_tag;
            let Ok(encoded) = retry.encode() else {
                return Ok(RetryGate::Drop);
            };
            return Ok(
                if encoded.len() == encoded_len
                    && self.push_checked_packet(from, encoded, packet_ceiling)
                {
                    RetryGate::IssuedRetry
                } else {
                    RetryGate::Drop
                },
            );
        }
        let now_secs = WallClock::now().unix_seconds();
        match secret.validate(&from, &prefix.token, now_secs) {
            None => Ok(RetryGate::Drop),
            Some(odcid) => Ok(RetryGate::Accept(Some(odcid))),
        }
    }

    fn emit_stateless_reset(&mut self, from: SocketAddr, trigger: &[u8]) -> bool {
        let Some(server_config) = self.server.as_ref().map(|server| &server.config) else {
            return false;
        };
        let Some(reset_secret) = server_config.stateless_reset_secret else {
            return false;
        };
        let secret = StatelessResetSecret(reset_secret);
        let Some(dcid) = Self::parse_dcid(trigger, 8) else {
            return false;
        };
        if trigger.len() < 23 {
            return false;
        }
        let packet_ceiling = Self::max_packet_bytes(server_config)
            .min(self.pending_outgoing_bytes_capacity)
            .min(trigger.len().saturating_mul(3));
        if packet_ceiling < 22 {
            return false;
        }
        let len = (trigger.len() - 1).min(packet_ceiling);
        if !self.packet_fits(len, packet_ceiling) {
            return false;
        }
        let reset = Self::build_stateless_reset(secret.token_for(dcid), len);
        self.push_checked_packet(from, reset, packet_ceiling)
    }

    fn receive_stateless_reset(&mut self, from: SocketAddr, datagram: &[u8], now: Instant) -> bool {
        let matched = self
            .entries
            .iter_mut()
            .enumerate()
            .find_map(|(index, entry)| {
                let slot = entry.slot_mut()?;
                (slot.peer_addr == from && slot.conn.try_receive_stateless_reset(datagram))
                    .then_some(index)
            });
        let Some(index) = matched else {
            return false;
        };
        let handle = self.handle_for_index(index);
        self.refresh_deadline(handle, now);
        true
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

impl<'d, const ID: u8, H: Handler, P: ServerPolicy> datagram::Handler<'d, ID> for Mux<H, P> {
    fn packet(
        &mut self,
        addr: SocketAddr,
        packet: datagram::Packet<'d>,
        _socket: Pin<&mut datagram::Socket<'d, ID>>,
        driver: &mut DriverContext<'_, 'd>,
    ) {
        let now = Instant::now();
        let data = packet.as_ref();
        if let Err(error) = self.recv(addr, data, now) {
            self.handler_mut().packet_error(addr, &error, data.len());
        }
        packet.release(driver);
    }
}
