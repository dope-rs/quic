use std::{mem, net, num, time};

pub use bridge::Bridge;
pub use dialer::Dialer;
use dope::core::driver::schedule::clock;
use o3::{base::num::bounded, mem::rc};

use crate::{
    conn::life::{options, tls::clients},
    runtime::brand,
};

pub mod auth;
mod bridge;
pub mod build;
pub mod control;
mod dialer;
mod life;
pub mod protocol;
mod raw;

/// Stable identity of one configured remote endpoint.
///
/// The value may cross asynchronous boundaries. Scoped auth may not.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct SlotId(u32);

impl SlotId {
    /// Identifies the endpoint at `index` in the construction-order table.
    pub fn from_index(index: u32) -> Self {
        Self(index)
    }

    pub fn index(self) -> u32 {
        self.0
    }
}

/// Generative auth for one exact client attempt.
/// Packed [`AttemptId`] distinguishes reconnects; the zero-sized brand is lexical.
/// Its private constructor prevents forging auth from a copyable identity.
#[repr(transparent)]
pub struct SlotScope<'scope>(brand::Branded<'scope, AttemptId>);

impl<'scope> SlotScope<'scope> {
    pub(in crate::client) fn new(brand: brand::Token<'scope>, attempt: AttemptId) -> Self {
        Self(brand::Branded::new(brand, attempt))
    }

    pub fn id(&self) -> SlotId {
        self.attempt_id().slot()
    }

    pub fn attempt_id(&self) -> AttemptId {
        *self.0.value()
    }

    pub fn generation(&self) -> u32 {
        self.attempt_id().generation()
    }
}

/// Generation-checked identity of one attempt at a configured remote.
/// Its generation never resets, so stale identities cannot alias later attempts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct AttemptId {
    slot: SlotId,
    generation: num::NonZero<u32>,
}

impl AttemptId {
    pub fn slot(self) -> SlotId {
        self.slot
    }

    pub fn generation(self) -> u32 {
        self.generation.get()
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Start<'d> {
    id: AttemptId,
    ordinal: num::NonZero<u32>,
    started_at: clock::Moment<'d>,
}

/// Exact connection-attempt context issued from one resident attempt state.
/// The generative proof is lexical; [`AttemptId`] is the stable value that
/// preserves causal identity across asynchronous proto boundaries.
#[repr(transparent)]
pub struct AttemptScope<'scope, 'd>(brand::Branded<'scope, Start<'d>>);

impl<'scope, 'd> AttemptScope<'scope, 'd> {
    pub fn id(&self) -> AttemptId {
        self.0.value().id
    }

    pub fn slot(&self) -> SlotId {
        self.id().slot()
    }

    pub fn attempt(&self) -> u32 {
        self.0.value().ordinal.get()
    }

    pub fn started_at(&self) -> clock::Moment<'d> {
        self.0.value().started_at
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RetryCause {
    AttemptFailed,
    ConnectionClosed,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Retry {
    slot: SlotId,
    prior: bounded::NonZeroU32<1, { u32::MAX - 1 }>,
    previous_ordinal: num::NonZero<u32>,
    next_ordinal: num::NonZero<u32>,
    observed_at: time::Instant,
}

/// Causal edge from one completed attempt or connection to its exact next
/// scheduled attempt. Backoff observes the proto event time, not a later
/// client notification-drain time.
#[repr(transparent)]
pub struct RetryScope<'scope>(brand::Branded<'scope, Retry>);

impl<'scope> RetryScope<'scope> {
    pub fn previous_id(&self) -> AttemptId {
        let retry = self.0.value();
        AttemptId {
            slot: retry.slot,
            generation: retry.prior.nonzero(),
        }
    }

    pub fn previous(&self) -> u32 {
        self.0.value().previous_ordinal.get()
    }

    pub fn next_id(&self) -> AttemptId {
        let retry = self.0.value();
        AttemptId {
            slot: retry.slot,
            generation: num::NonZero::<u32>::MIN.saturating_add(retry.prior.get()),
        }
    }

    pub fn next_attempt(&self) -> u32 {
        self.0.value().next_ordinal.get()
    }

    pub fn cause(&self) -> RetryCause {
        if self.next_attempt() == 1 {
            RetryCause::ConnectionClosed
        } else {
            RetryCause::AttemptFailed
        }
    }

    pub fn failures(&self) -> u32 {
        match self.cause() {
            RetryCause::AttemptFailed => self.previous(),
            RetryCause::ConnectionClosed => 1,
        }
    }
}

/// Packed resident attempt generation and retry ordinal. Both retain their
/// complete `u32` domains without adding another allocation or side table.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(C, align(8))]
pub(in crate::client) struct AttemptState {
    generation: num::NonZero<u32>,
    ordinal: num::NonZero<u32>,
}

#[derive(Clone, Copy)]
pub(in crate::client) struct Successor {
    next: AttemptState,
    prior: bounded::NonZeroU32<1, { u32::MAX - 1 }>,
    ordinal: num::NonZero<u32>,
}

impl Successor {
    pub(in crate::client) const fn state(self) -> AttemptState {
        self.next
    }

    pub(in crate::client) fn retry_scope<'scope>(
        self,
        brand: brand::Token<'scope>,
        slot: SlotId,
        seen: time::Instant,
    ) -> RetryScope<'scope> {
        RetryScope(brand::Branded::new(
            brand,
            Retry {
                slot,
                prior: self.prior,
                previous_ordinal: self.ordinal,
                next_ordinal: self.next.ordinal_raw(),
                observed_at: seen,
            },
        ))
    }
}

impl AttemptState {
    pub(in crate::client) fn initial() -> Self {
        Self::from_parts(num::NonZero::<u32>::MIN, num::NonZero::<u32>::MIN)
    }

    fn from_parts(epoch: num::NonZero<u32>, ordinal: num::NonZero<u32>) -> Self {
        Self {
            generation: epoch,
            ordinal,
        }
    }

    fn generation(self) -> num::NonZero<u32> {
        self.generation
    }

    fn ordinal_raw(self) -> num::NonZero<u32> {
        self.ordinal
    }

    pub(in crate::client) fn id(self, slot: SlotId) -> AttemptId {
        AttemptId {
            slot,
            generation: self.generation(),
        }
    }

    pub(in crate::client) fn successor(self, restart: bool) -> Option<Successor> {
        let prior = bounded::NonZeroU32::new(self.generation().get())?;
        let epoch = num::NonZero::<u32>::MIN.saturating_add(prior.get());
        let ordinal = if restart {
            num::NonZero::<u32>::MIN
        } else {
            self.ordinal_raw().checked_add(1)?
        };
        Some(Successor {
            next: Self::from_parts(epoch, ordinal),
            prior,
            ordinal: self.ordinal_raw(),
        })
    }

    pub(in crate::client) fn scope<'scope, 'd>(
        self,
        brand: brand::Token<'scope>,
        slot: SlotId,
        started: clock::Moment<'d>,
    ) -> AttemptScope<'scope, 'd> {
        AttemptScope(brand::Branded::new(
            brand,
            Start {
                id: self.id(slot),
                ordinal: self.ordinal_raw(),
                started_at: started,
            },
        ))
    }
}

/// Retry delay policy owned by a [`Dialer`]; concrete types may borrow lexical state.
///
/// The policy lifetime remains part of the dialer and cannot be widened away:
pub trait Backoff {
    /// Selects only the relative delay. The lifecycle that owns the causal
    /// observation is the sole auth allowed to mint an absolute retry
    /// deadline.
    fn retry_after<'scope>(&'scope self, retry: RetryScope<'scope>) -> time::Duration;
}

/// Per-attempt configuration source owned directly by a [`Dialer`].
///
/// The provider may borrow lexical owner state. Returned options remain owned
/// so no provider borrow or callback proof can cross the connection boundary.
pub trait ConfigSource {
    fn config<'scope, 'd>(
        &'scope mut self,
        attempt: AttemptScope<'scope, 'd>,
    ) -> Option<options::Options>;
}

pub struct StaticConfig(options::Options);

impl ConfigSource for StaticConfig {
    fn config<'scope, 'd>(
        &'scope mut self,
        _: AttemptScope<'scope, 'd>,
    ) -> Option<options::Options> {
        Some(self.0.copy())
    }
}

pub struct EndpointSpec {
    pub addr: net::SocketAddr,
    pub authority: clients::Authority,
}

impl EndpointSpec {
    pub fn try_clone(&self) -> Result<Self, rc::Error> {
        Ok(Self {
            addr: self.addr,
            authority: self.authority.try_clone()?,
        })
    }
}

/// One remote endpoint using borrowed TLS auth and handshake admission.
#[derive(Clone, Copy)]
pub struct PooledSpec<'tls> {
    pub addr: net::SocketAddr,
    pub pool: &'tls clients::Pool,
}

#[derive(Clone, Copy)]
pub struct Config {
    pub event_budget: usize,
    pub retry_budget: usize,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PathStats {
    pub srtt: Option<time::Duration>,
    pub min_rtt: Option<time::Duration>,
    pub cwnd: u64,
    pub bytes_in_flight: u64,
}

const _: () = {
    assert!(mem::size_of::<SlotScope<'static>>() == mem::size_of::<u64>());
    assert!(!mem::needs_drop::<SlotScope<'static>>());
};
const _: () = {
    assert!(std::mem::size_of::<SlotScope<'static>>() == std::mem::size_of::<AttemptId>());
    assert!(std::mem::align_of::<SlotScope<'static>>() == std::mem::align_of::<AttemptId>());
    assert!(!std::mem::needs_drop::<SlotScope<'static>>());
    assert!(std::mem::size_of::<AttemptId>() == 2 * std::mem::size_of::<u32>());
    assert!(std::mem::size_of::<AttemptState>() == std::mem::size_of::<u64>());
    assert!(std::mem::align_of::<AttemptState>() == std::mem::align_of::<u64>());
    assert!(std::mem::size_of::<Option<AttemptState>>() == std::mem::size_of::<u64>());
    assert!(std::mem::size_of::<Successor>() == 2 * std::mem::size_of::<u64>());
    assert!(!std::mem::needs_drop::<Successor>());
    assert!(
        std::mem::size_of::<AttemptScope<'static, 'static>>()
            == std::mem::size_of::<(SlotId, u32, u32, time::Instant)>()
    );
    assert!(
        std::mem::align_of::<AttemptScope<'static, 'static>>()
            == std::mem::align_of::<(SlotId, u32, u32, time::Instant)>()
    );
    assert!(!std::mem::needs_drop::<AttemptScope<'static, 'static>>());
    assert!(
        std::mem::size_of::<RetryScope<'static>>()
            == std::mem::size_of::<AttemptScope<'static, 'static>>()
    );
    assert!(
        std::mem::align_of::<RetryScope<'static>>()
            == std::mem::align_of::<AttemptScope<'static, 'static>>()
    );
    assert!(!std::mem::needs_drop::<RetryScope<'static>>());
};
