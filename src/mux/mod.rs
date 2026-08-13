pub mod configuration;
pub(crate) mod drive;
pub mod lifecycle;
pub mod output;
pub mod protocol;
mod reset_index;
mod routing;
pub mod setup;

use drive::OutputOps as _;
use routing::{DeadlineOps as _, SlotOps as _};

use std::marker::PhantomData;
use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU32};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::time::Instant;

use dope::{core::driver::schedule, manifold::datagram};
use shin::server::{QuicConnection, Shard};

use crate::conn::config::Validated;
use crate::conn::path::StatelessResetToken;
use crate::conn::session::Connection;
use crate::conn::{self, Error, Handle, MAX_ACTIVE_CONNECTION_IDS};
use crate::stream::ReceiveBuffer;
use std::array::from_fn;

pub trait Handler<const DOMAIN: u8, B: ReceiveBuffer = Vec<u8>> {
    /// Protocol state owned by one connection slot.
    type Connection;

    /// Creates the slot-local state before the first connection event is delivered.
    fn create_connection(
        &mut self,
        conn: &mut Connection<DOMAIN, B>,
        handle: Handle,
    ) -> Self::Connection;
    fn established(
        &mut self,
        _connection: &mut Self::Connection,
        _conn: &mut Connection<DOMAIN, B>,
        _handle: Handle,
    ) {
    }
    fn datagram(
        &mut self,
        _connection: &mut Self::Connection,
        _conn: &mut Connection<DOMAIN, B>,
        _handle: Handle,
        _data: B,
    ) {
    }
    fn stream_event(
        &mut self,
        _connection: &mut Self::Connection,
        _conn: &mut Connection<DOMAIN, B>,
        _handle: Handle,
        _event: conn::stream::Event,
    ) {
    }
    fn early_stream_event(
        &mut self,
        connection: &mut Self::Connection,
        conn: &mut Connection<DOMAIN, B>,
        handle: Handle,
        event: conn::stream::Event,
    ) {
        self.stream_event(connection, conn, handle, event);
    }
    fn close(&mut self, _connection: Self::Connection, _handle: Handle) {}
    fn packet_error(&mut self, _from: SocketAddr, _err: &Error, _len: usize) {}
}

type ServerSession<P, const DOMAIN: u8> = Box<
    QuicConnection<
        fn() -> u64,
        DOMAIN,
        <P as conn::server::Policy>::Guard,
        <P as conn::server::Policy>::Verifier,
    >,
>;

enum TlsSession<'tls, P: conn::server::Policy, const DOMAIN: u8> {
    OwnedServer(ServerSession<P, DOMAIN>),
    Client(conn::handshake::ClientTls<'tls>),
    Server(
        shin::server::QuicPooledConnection<
            'tls,
            conn::handshake::Clock,
            DOMAIN,
            P::Verifier,
            P::Guard,
        >,
    ),
}

struct Slot<'tls, C, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer> {
    conn: Connection<DOMAIN, B>,
    tls: Option<TlsSession<'tls, P, DOMAIN>>,
    connection: C,
    peer_addr: SocketAddr,
    notified_established: bool,
    max_packet_bytes: usize,
    first_flush: bool,
    identifiers: Identifiers,
}

struct Identifiers {
    cids: [CidRecord; MAX_CIDS_PER_CONN],
    reset_tokens: [Option<StatelessResetToken>; MAX_ACTIVE_CONNECTION_IDS],
}

impl<'tls, C, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer>
    Slot<'tls, C, P, DOMAIN, B>
{
    fn new(
        conn: Connection<DOMAIN, B>,
        tls: Option<TlsSession<'tls, P, DOMAIN>>,
        connection: C,
        peer_addr: SocketAddr,
        max_packet_bytes: usize,
    ) -> Self {
        Self {
            conn,
            tls,
            connection,
            peer_addr,
            notified_established: false,
            max_packet_bytes,
            first_flush: true,
            identifiers: Identifiers {
                cids: from_fn(|_| CidRecord::default()),
                reset_tokens: [None; MAX_ACTIVE_CONNECTION_IDS],
            },
        }
    }
}

struct Entry<'tls, C, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer> {
    slot: Option<Slot<'tls, C, P, DOMAIN, B>>,
    generation: u32,
    used: bool,
    free_next: u32,
    notify: QueueLinks,
    flush: QueueLinks,
    reap: QueueLinks,
}

impl<'tls, C, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer>
    Entry<'tls, C, P, DOMAIN, B>
{
    fn slot(&self) -> Option<&Slot<'tls, C, P, DOMAIN, B>> {
        self.slot.as_ref()
    }

    fn slot_mut(&mut self) -> Option<&mut Slot<'tls, C, P, DOMAIN, B>> {
        self.slot.as_mut()
    }

    fn insert(&mut self, slot: Slot<'tls, C, P, DOMAIN, B>) {
        debug_assert!(self.slot.is_none());
        self.notify = QueueLinks::default();
        self.flush = QueueLinks::default();
        self.reap = QueueLinks::default();
        self.slot = Some(slot);
    }

    fn take(&mut self) -> Option<Slot<'tls, C, P, DOMAIN, B>> {
        self.slot.take()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CidLink(NonZeroU32);

impl CidLink {
    fn new(index: usize, ordinal: usize) -> Option<Self> {
        let index = u32::try_from(index).ok()?;
        let ordinal = u32::try_from(ordinal).ok()?;
        if index >= MAX_CONNECTIONS as u32 || ordinal >= 16 {
            return None;
        }
        NonZeroU32::new(((index << 4) | ordinal) + 1).map(Self)
    }

    fn index(self) -> usize {
        ((self.0.get() - 1) >> 4) as usize
    }

    fn ordinal(self) -> usize {
        ((self.0.get() - 1) & 0xf) as usize
    }
}

const _: () = assert!(std::mem::size_of::<CidLink>() == 4);

#[derive(Default)]
struct CidRecord {
    value: Option<crate::packet::ConnectionId>,
    local: Option<crate::conn::path::LocalCidKey>,
    prev: Option<CidLink>,
    next: Option<CidLink>,
}

const _: () = assert!(std::mem::size_of::<CidRecord>() <= 40);

#[derive(Clone, Copy)]
struct RoutedCid {
    handle: Handle,
    local: Option<crate::conn::path::LocalCidKey>,
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
    Notify,
    Flush,
    Reap,
}

#[derive(Clone, Copy)]
enum DrivePhase {
    Notify,
    Deadline,
    Reap,
    Flush,
}

impl DrivePhase {
    const COUNT: usize = 4;

    const fn next(self) -> Self {
        match self {
            Self::Notify => Self::Deadline,
            Self::Deadline => Self::Reap,
            Self::Reap => Self::Flush,
            Self::Flush => Self::Notify,
        }
    }
}

const DEFAULT_MAX_CONNS: usize = 1024;
const DEFAULT_OUTGOING_CAP: usize = 4096;
const DEFAULT_OUTGOING_BYTES_CAP: usize = 16 << 20;
pub(crate) const MAX_CONNECTIONS: usize = 65_536;
pub(crate) const MAX_OUTGOING_CAPACITY: usize = 65_536;
pub(crate) const MAX_OUTGOING_BYTES: usize = 1 << 30;
const FLUSH_PACKET_QUANTUM: usize = 8;
const FLUSH_BYTE_QUANTUM: usize = 64 << 10;
const DIRECT_DRIVE_BUDGET: usize = 256;
const MAX_CIDS_PER_CONN: usize = 10;
const ROUTED_CID_LEN: usize = 8;
const NONE: u32 = u32::MAX;

const _: () = assert!(DIRECT_DRIVE_BUDGET <= schedule::MAX_TURN_WORK_BUDGET);

pub(crate) enum FlushRound {
    Idle,
    More,
    Backpressure,
    Waiting,
    Closed,
}

pub enum Outgoing {
    Plain(SocketAddr, Vec<u8>),
    Suffix(SocketAddr, datagram::OwnedSuffix),
    Batch(SocketAddr, Vec<u8>, NonZeroU16),
}

impl Outgoing {
    pub fn addr(&self) -> SocketAddr {
        match *self {
            Self::Plain(a, _) | Self::Suffix(a, _) | Self::Batch(a, _, _) => a,
        }
    }

    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Plain(_, p) | Self::Batch(_, p, _) => p,
            Self::Suffix(_, p) => p.as_slice(),
        }
    }

    /// Borrows the encoded packet storage for in-place delivery.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Plain(_, payload) | Self::Batch(_, payload, _) => payload,
            Self::Suffix(_, payload) => payload.as_mut_slice(),
        }
    }

    fn packets(&self) -> usize {
        match self {
            Self::Plain(_, _) | Self::Suffix(_, _) => 1,
            Self::Batch(_, payload, segment_size) => {
                payload.len().div_ceil(usize::from(segment_size.get()))
            }
        }
    }

    fn bytes(&self) -> usize {
        self.payload().len()
    }

    fn into_storage(self) -> Vec<u8> {
        match self {
            Self::Plain(_, payload) | Self::Batch(_, payload, _) => payload,
            Self::Suffix(_, payload) => payload.into_storage(),
        }
    }
}

struct ServerRuntime<'tls, P: conn::server::Policy, const DOMAIN: u8> {
    config: Validated,
    shard: ServerShard<'tls, P, DOMAIN>,
    _policy: PhantomData<fn() -> P>,
}

enum ServerShard<'tls, P: conn::server::Policy, const DOMAIN: u8> {
    Owned(Shard<P::Guard, P::Verifier, DOMAIN>),
    Pooled {
        shard: &'tls Shard<P::Guard, P::Verifier, DOMAIN>,
        pool: &'tls shin::server::workspace::QuicPool<
            conn::handshake::Clock,
            P::Verifier,
            DOMAIN,
            P::Guard,
        >,
    },
}

impl<'tls, P: conn::server::Policy, const DOMAIN: u8> ServerRuntime<'tls, P, DOMAIN> {
    fn new(config: Validated, shard: Shard<P::Guard, P::Verifier, DOMAIN>) -> Self {
        Self {
            config,
            shard: ServerShard::Owned(shard),
            _policy: PhantomData,
        }
    }

    fn pooled(
        config: Validated,
        shard: &'tls Shard<P::Guard, P::Verifier, DOMAIN>,
        pool: &'tls shin::server::workspace::QuicPool<
            conn::handshake::Clock,
            P::Verifier,
            DOMAIN,
            P::Guard,
        >,
    ) -> Self {
        Self {
            config,
            shard: ServerShard::Pooled { shard, pool },
            _policy: PhantomData,
        }
    }

    fn shard(&self) -> &Shard<P::Guard, P::Verifier, DOMAIN> {
        match &self.shard {
            ServerShard::Owned(shard) => shard,
            ServerShard::Pooled { shard, .. } => shard,
        }
    }
}

pub struct MuxInner<
    'tls,
    H: Handler<DOMAIN, B>,
    P: conn::server::Policy = conn::server::Standard,
    const DOMAIN: u8 = 0,
    B: ReceiveBuffer = Vec<u8>,
> {
    registry: routing::registry::Registry<'tls, H::Connection, P, DOMAIN, B>,
    outgoing: output::Storage,
    queues: drive::Queues,
    receive_workspace: conn::ReceiveWorkspace,
    handler: H,
    server: Option<ServerRuntime<'tls, P, DOMAIN>>,
    lifecycle: lifecycle::State,
}

pub type Mux<H, P = conn::server::Standard, const DOMAIN: u8 = 0, B = Vec<u8>> =
    MuxInner<'static, H, P, DOMAIN, B>;

pub type PooledMux<'tls, H, P = conn::server::Standard, const DOMAIN: u8 = 0, B = Vec<u8>> =
    MuxInner<'tls, H, P, DOMAIN, B>;

impl<'tls, H: Handler<DOMAIN, B>, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer>
    MuxInner<'tls, H, P, DOMAIN, B>
{
    pub fn configuration(&mut self) -> configuration::Control<'_, 'tls, H, P, DOMAIN, B> {
        configuration::Control::new(self)
    }

    pub fn output(&mut self) -> output::Queue<'_, 'tls, H, P, DOMAIN, B> {
        output::Queue::new(self)
    }

    pub fn active_conns(&self) -> usize {
        self.registry.active_conns
    }

    pub fn handler(&self) -> &H {
        &self.handler
    }

    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    pub fn protocol(&mut self) -> protocol::Io<'_, 'tls, H, P, DOMAIN, B> {
        protocol::Io::new(self)
    }

    pub(crate) fn shutdown_complete(&self) -> bool {
        self.lifecycle.shutting_down
            && self.lifecycle.cursor == self.registry.entries.len()
            && self.outgoing.pending.is_empty()
            && self.outgoing.recycled.is_empty()
            && self.outgoing.batch.is_none()
            && self.registry.indexes.reset.len() == 0
    }

    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        if self.queues.notify.len != 0
            || self.queues.reap.len != 0
            || (self.queues.flush.len != 0 && self.has_outgoing_room())
        {
            return Some(now);
        }
        self.deadline_peek().map(|(_, deadline)| deadline)
    }

    pub fn conn(&self, handle: Handle) -> Option<&Connection<DOMAIN, B>> {
        let index = self.handle_index(handle)?;
        self.registry.entries[index].slot().map(|slot| &slot.conn)
    }

    pub fn lifecycle(&mut self) -> lifecycle::Shutdown<'_, 'tls, H, P, DOMAIN, B> {
        lifecycle::Shutdown::new(self)
    }
}

/// Exclusive connection access that restores Mux routing indexes on drop.
///
/// The guard's borrow prevents the connection from outliving or overlapping
/// its Mux slot. Any peer reset-token changes made through `Connection` APIs
/// are committed before the Mux can receive another datagram.
#[must_use = "connection index synchronization runs when the guard is dropped"]
pub struct ConnectionMut<
    'mux,
    'tls,
    H: Handler<DOMAIN, B>,
    P: conn::server::Policy = conn::server::Standard,
    const DOMAIN: u8 = 0,
    B: ReceiveBuffer = Vec<u8>,
> {
    mux: &'mux mut MuxInner<'tls, H, P, DOMAIN, B>,
    handle: Handle,
}

impl<H: Handler<DOMAIN, B>, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer> Deref
    for ConnectionMut<'_, '_, H, P, DOMAIN, B>
{
    type Target = Connection<DOMAIN, B>;

    fn deref(&self) -> &Self::Target {
        let index = self
            .mux
            .handle_index(self.handle)
            .expect("connection guard owns a live slot");
        &self.mux.registry.entries[index]
            .slot()
            .expect("connection guard owns a live slot")
            .conn
    }
}

impl<H: Handler<DOMAIN, B>, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer> DerefMut
    for ConnectionMut<'_, '_, H, P, DOMAIN, B>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        let index = self
            .mux
            .handle_index(self.handle)
            .expect("connection guard owns a live slot");
        &mut self.mux.registry.entries[index]
            .slot_mut()
            .expect("connection guard owns a live slot")
            .conn
    }
}

impl<H: Handler<DOMAIN, B>, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer> Drop
    for ConnectionMut<'_, '_, H, P, DOMAIN, B>
{
    fn drop(&mut self) {
        self.mux.finish_connection_mut(self.handle);
    }
}

enum RetryGate {
    Accept(Option<crate::packet::ConnectionId>),
    IssuedRetry,
    Drop,
}

impl<'d, 'tls, const ID: u8, H, P, B> datagram::Handler<'d, ID> for MuxInner<'tls, H, P, ID, B>
where
    H: Handler<ID, B>,
    P: conn::server::Policy,
    B: crate::endpoint::EndpointBuffer<'d>,
{
    fn packet<'turn>(
        &mut self,
        addr: SocketAddr,
        packet: datagram::packet::Packet<'turn, 'd>,
        socket: Pin<&'turn mut datagram::Socket<'d, ID>>,
        now: Instant,
    ) {
        let len = packet.as_ref().len();
        let received = B::receive_packet(self, addr, packet, socket, now);
        if let Err(error) = received {
            self.handler.packet_error(addr, &error, len);
        }
    }
}
