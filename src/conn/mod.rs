use o3::{
    alloc,
    depot::{self, index::Initialized},
};
use std::{collections, mem, time};

use o3::buffer::{self, storage::Shared};

use crate::proto::{datagram::Size, param, recovery::numbers};
use crate::runtime::brand;
use crate::stream::{Recv, release};
use crate::wire::varint;
use crate::wire::{frame, packet, stream::Initiator};
use packet::header::widths;

mod error;
pub use error::{Error, timing::Timing};
pub mod id;
pub mod life;
pub(crate) mod machine;
pub mod output;
pub mod scope;
pub mod stream;
pub mod wire;

pub(crate) use stream::state::transmit::queue::{Publication, Reclaim};

use life::{options, status};
use machine::Machine;
use stream::state::transmit;
use wire::{crypto::chunks, scratch};

/// The retained owner and exact key prove initialization in one operation plane.
type Selected<O, K, P> = depot::raw::Proof<(O, K), Initialized<P>>;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Early {
    None,
    Rejected,
}

/// Owned QUIC connection state. Mutable auth is issued by
/// [`Self::with_scope`], while shared inspection is issued by [`Self::view`].
#[repr(transparent)]
pub struct Connection<
    const DOMAIN: u8 = 0,
    B: crate::stream::Recv = Vec<u8>,
    D: buffer::raw::Segment = Shared,
>(pub(crate) Machine<DOMAIN, B, D>);

impl<const DOMAIN: u8, B: crate::stream::Recv, D: buffer::raw::Segment> Connection<DOMAIN, B, D> {
    pub(crate) fn machine(&self) -> &Machine<DOMAIN, B, D> {
        &self.0
    }

    pub(crate) fn machine_mut(&mut self) -> &mut Machine<DOMAIN, B, D> {
        &mut self.0
    }

    pub(crate) fn retire<E: release::Sink>(self, cause: release::Cause, proof: &mut E) {
        let Self(mut machine) = self;
        transmit::Sender::new(&mut machine.streams).release_all(cause, proof);
    }

    pub(crate) fn mark(&mut self, bits: u8) {
        self.0.peer.reconcile.insert(bits);
    }

    /// Runs mutable connection operations under one fresh invariant lifetime.
    pub fn with_scope<R>(
        &mut self,
        f: impl for<'scope> FnOnce(scope::Access<'scope, DOMAIN, B, false, D>) -> R,
    ) -> R {
        brand::Token::with_mut(&mut self.0, |brand, machine| {
            f(scope::Access::new(machine, brand))
        })
    }

    pub(crate) fn scope_in<R>(
        &mut self,
        brand: brand::Token<'_>,
        f: impl for<'scope> FnOnce(scope::Access<'scope, DOMAIN, B, false, D>) -> R,
    ) -> R {
        f(scope::Access::new(&mut self.0, brand.reborrow()))
    }

    /// Borrows responsibility-specific connection state views.
    pub fn view(&self) -> status::View<'_, DOMAIN, B, D> {
        status::View::new(&self.0)
    }

    /// Returns a read-only view which cannot export raw temporal state.
    pub fn inspection(&self) -> status::Inspection<'_, DOMAIN, B, D> {
        status::Inspection::new(&self.0)
    }
}

pub(in crate::conn) struct ReceiveState<B: Recv> {
    pub(in crate::conn) packet_numbers: numbers::Spaces,
    pub(in crate::conn) crypto: chunks::Spaces,
    pub(in crate::conn) datagrams: collections::VecDeque<B>,
    pub(in crate::conn) datagram_capacity: options::Capacity,
    pub(in crate::conn) local_max_datagram_frame_size: Option<u64>,
}

pub(in crate::conn) struct Scratch {
    pub(in crate::conn) frames: Vec<u8>,
    pub(in crate::conn) header: Vec<u8>,
}

pub(in crate::conn) struct PeerState {
    pub(in crate::conn) local: Initiator,
    pub(in crate::conn) application_timeout: bool,
    pub(in crate::conn) reconcile: Effects,
    pub(in crate::conn) transport_params: Option<param::Set>,
    pub(in crate::conn) local_max_idle_ms: u64,
    pub(in crate::conn) application_deadline: Option<time::Instant>,
}

/// Strength of one connection-to-mux deadline projection.
/// `Earlier` is monotonic; `Exact` repairs later or removed timers.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum DeadlineMode {
    Earlier,
    Exact,
}

/// Effect of replacing the one app-owned connection deadline.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    Unchanged,
    Replaced,
    Cleared,
}

/// Connection-local mux invalidation state. It occupies padding beside
/// `PeerState::local`, so tracking exact reconciliation work does not grow
/// a connection.
#[derive(Default)]
#[repr(transparent)]
pub(crate) struct Effects(u8);

impl Effects {
    pub(crate) const ROUTING: u8 = 1 << 0;
    pub(crate) const NOTIFY: u8 = 1 << 1;
    pub(crate) const OUTPUT: u8 = 1 << 2;
    const DEADLINE_EARLIER: u8 = 1 << 3;
    const APPLICATION_DIRTY: u8 = 1 << 4;
    const APPLICATION_READY: u8 = 1 << 5;
    pub(crate) const EARLY_DATA_REJECTED: u8 = 1 << 6;
    pub(in crate::conn) const DEADLINE_EXACT: u8 = 1 << 7;
    const DEADLINE_MASK: u8 = Self::DEADLINE_EARLIER | Self::DEADLINE_EXACT;
    const PLANES: u8 = Self::ROUTING | Self::NOTIFY | Self::OUTPUT | Self::DEADLINE_MASK;
    const SIGNALS: u8 = Self::EARLY_DATA_REJECTED;
    pub(crate) const STREAMS: u8 = Self::NOTIFY | Self::OUTPUT | Self::DEADLINE_EARLIER;
    pub(crate) const TRANSMIT: u8 = Self::OUTPUT | Self::DEADLINE_EARLIER;
    pub(crate) const SCHEDULER: u8 = Self::OUTPUT | Self::DEADLINE_EXACT;
    pub(crate) const RECOVERY: u8 = Self::SCHEDULER;
    pub(crate) const PATH: u8 = Self::ROUTING | Self::OUTPUT | Self::DEADLINE_EXACT;
    pub(crate) const LIFECYCLE: u8 = Self::NOTIFY | Self::OUTPUT | Self::DEADLINE_EXACT;

    pub(crate) const fn none() -> Self {
        Self(0)
    }

    pub(crate) const fn from_bits(bits: u8) -> Self {
        Self(
            bits & (Self::PLANES
                | Self::APPLICATION_DIRTY
                | Self::APPLICATION_READY
                | Self::SIGNALS),
        )
    }

    pub(crate) const fn initial() -> Self {
        Self(Self::PLANES)
    }

    pub(in crate::conn) const fn bits(&self) -> u8 {
        self.0
    }

    pub(crate) const fn contains(&self, bits: u8) -> bool {
        self.0 & bits != 0
    }

    pub(crate) const fn deadline(&self) -> Option<DeadlineMode> {
        if self.0 & Self::DEADLINE_EXACT != 0 {
            Some(DeadlineMode::Exact)
        } else if self.0 & Self::DEADLINE_EARLIER != 0 {
            Some(DeadlineMode::Earlier)
        } else {
            None
        }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    pub(in crate::conn) fn insert(&mut self, bits: u8) {
        self.0 |= bits;
    }

    pub(in crate::conn) fn project(&mut self, update: DeadlineMode) {
        self.0 |= match update {
            DeadlineMode::Earlier => Self::DEADLINE_EARLIER,
            DeadlineMode::Exact => Self::DEADLINE_EXACT,
        };
    }

    pub(crate) fn set_ready(&mut self, ready: bool) {
        self.0 |= Self::APPLICATION_DIRTY;
        if ready {
            self.0 |= Self::APPLICATION_READY;
        } else {
            self.0 &= !Self::APPLICATION_READY;
        }
    }

    pub(crate) const fn ready(&self) -> Option<bool> {
        if self.contains(Self::APPLICATION_DIRTY) {
            Some(self.contains(Self::APPLICATION_READY))
        } else {
            None
        }
    }

    fn take(&mut self) -> Self {
        let bits = self.0;
        if bits != 0 {
            self.0 = 0;
        }
        Self(bits)
    }

    fn remove(&mut self, bits: u8) {
        self.0 &= !bits;
    }

    pub(crate) fn merge(&mut self, later: Self) {
        self.0 |= later.0 & (Self::PLANES | Self::SIGNALS);
        if later.contains(Self::APPLICATION_DIRTY) {
            self.set_ready(later.contains(Self::APPLICATION_READY));
        }
    }
}

/// One ingress value paired with its linear mux reconciliation effects.
#[must_use = "an ingress outcome must be reconciled"]
#[doc(hidden)]
pub struct Ingress<T> {
    value: T,
    effects: Effects,
}

impl<T> Ingress<T> {
    pub(crate) fn new(value: T, effects: Effects) -> Self {
        Self { value, effects }
    }

    pub(crate) fn into_parts(self) -> (T, Effects) {
        (self.value, self.effects)
    }
}

/// Bounded scratch storage for one serialized receive lane.
pub struct Workspace {
    pub(in crate::conn) storage: scratch::Scratch,
}

impl Workspace {
    pub fn try_new() -> Result<Self, alloc::Error> {
        Ok(Self {
            storage: scratch::Scratch::try_new()?,
        })
    }
}

pub(crate) const MIN_INITIAL_LEN: usize = Size::MIN.get() as usize;
pub(crate) const TAG_LEN: usize = packet::TAG_LEN;
pub(crate) const MAX_PACKET_NUMBER_LEN: u8 = widths::MAX_LEN;
const STREAM_FRAME_OVERHEAD: usize = 25;
const PACKET_JOURNAL_CAPACITY: usize = 4096;
const CRYPTO_JOURNAL_CAPACITY: usize = 4096;
const CONTROL_JOURNAL_CAPACITY: usize = 8192;
const STREAM_JOURNAL_CAPACITY: usize = 1024;
const PACKET_CONTROL_CAPACITY: usize = 16;
const PACKET_STREAM_CAPACITY: usize = 16;
const STREAM_SCHEDULE_CAPACITY: usize = 256;
const STREAM_SCHEDULE_WORK_LIMIT: usize = 256;
const MAX_PATH_TOKENS: usize = 64;
pub(crate) const MAX_FRAMES_PER_PACKET: usize = 256;
/// Bound for generated ACK gaps and ranges that each occupy at most two bytes.
const MAX_GENERATED_ACK_FRAME_BYTES: usize =
    1 + 8 + 1 + 2 + 2 + frame::MAX_ADDITIONAL_ACK_RANGES * 4;
pub(crate) const MAX_BATCH_PACKETS: usize = 64;
const MAX_QUEUE_CAPACITY: usize = 65_536;
const MAX_STREAMS: u64 = 65_536;

pub(crate) const MAX_STREAM_COUNT: u64 = 1 << 60;
const MAX_FLOW_CONTROL_CREDIT: u64 = 1 << 30;
pub(crate) const MAX_ACTIVE_CONNECTION_IDS: usize = 8;
pub(crate) const MAX_PACKET_NUMBER: u64 = widths::MAX;
const MAX_PENDING_RETIRE_CONNECTION_IDS: usize = 64;
const INTERNAL_ERROR: varint::VarInt = varint::VarInt::from_u8(0x1);
const APPLICATION_ERROR: varint::VarInt = varint::VarInt::from_u8(0x0c);
const KEY_UPDATE_ERROR: varint::VarInt = varint::VarInt::from_u8(0x0e);
const AEAD_LIMIT_REACHED: varint::VarInt = varint::VarInt::from_u8(0x0f);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Handshaking,
    Established,
    Closed,
}

/// QUIC packet-number space and its matching protection epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Epoch {
    Initial = 0,
    Handshake = 1,
    Application = 2,
}

impl Epoch {
    pub const ALL: [Self; 3] = [Self::Initial, Self::Handshake, Self::Application];

    pub(crate) const fn bind<T>(self, values: &[T; 3]) -> &T {
        match self {
            Self::Initial => &values[0],
            Self::Handshake => &values[1],
            Self::Application => &values[2],
        }
    }

    pub(crate) fn bind_mut<T>(self, values: &mut [T; 3]) -> &mut T {
        match self {
            Self::Initial => &mut values[0],
            Self::Handshake => &mut values[1],
            Self::Application => &mut values[2],
        }
    }
}

const _: () = assert!(MAX_FRAMES_PER_PACKET == 1usize << u8::BITS);
const _: () = {
    type Baseline = (bool, bool, Option<param::Set>, u64, Option<time::Instant>);

    assert!(Effects::STREAMS & Effects::ROUTING == 0);
    assert!(Effects::TRANSMIT & (Effects::ROUTING | Effects::NOTIFY) == 0);
    assert!(Effects::PATH & Effects::ROUTING != 0);
    assert!(mem::size_of::<Epoch>() == 1);
    assert!(mem::size_of::<Effects>() == 1);
    assert!(mem::size_of::<DeadlineMode>() == 1);
    assert!(!mem::needs_drop::<DeadlineMode>());
    assert!(!mem::needs_drop::<Effects>());
    assert!(mem::size_of::<PeerState>() == mem::size_of::<Baseline>());
    assert!(mem::align_of::<PeerState>() == mem::align_of::<Baseline>());
};
const _: () = assert!(mem::size_of::<Workspace>() == mem::size_of::<scratch::Scratch>());
const _: () = {
    assert!(mem::size_of::<Connection<0>>() == mem::size_of::<Machine<0, Vec<u8>>>());
    assert!(mem::align_of::<Connection<0>>() == mem::align_of::<Machine<0, Vec<u8>>>());
    assert!(mem::size_of::<Connection<0, Vec<u8>, Shared>>() == mem::size_of::<Connection<0>>());
    assert!(mem::align_of::<Connection<0, Vec<u8>, Shared>>() == mem::align_of::<Connection<0>>());
};
