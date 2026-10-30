use dope::core::Errno;
use dope::core::driver::{result::SubmitError, route};
use dope::core::io::datagram::ReceiveError;
use o3::buffer;
use o3::buffer::Residency;
use std::{net, num};

use dope::{
    core::{driver::schedule::clock, io::transfer},
    manifold::network::datagram::{RejectCause, send},
};

use crate::{conn::id, errors};

/// Metadata observed at the exact endpoint UDP receive boundary.
///
/// Emitted after the protocol consumes the receive owner, with no payload
/// borrow that instrumentation could extend or counterfeit.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Ingress<'d> {
    source: net::SocketAddr,
    bytes: usize,
    received_at: clock::Moment<'d>,
}

impl<'d> Ingress<'d> {
    pub(crate) const fn new(source: net::SocketAddr, bytes: usize, at: clock::Moment<'d>) -> Self {
        Self {
            source,
            bytes,
            received_at: at,
        }
    }

    pub const fn source(self) -> net::SocketAddr {
        self.source
    }

    pub const fn bytes(self) -> usize {
        self.bytes
    }

    pub const fn received_at(self) -> clock::Moment<'d> {
        self.received_at
    }
}

/// Exact phase of a socket payload owner.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum Phase<I: id::Temporal, const ID: u8> {
    Queued(I::Queued<ID>),
    Flight(I::Flight<ID>),
}

/// Endpoint-scoped identity of one queued or in-flight socket payload.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Owner<I: id::Temporal = id::Static, const DOMAIN: u8 = 0> {
    endpoint: id::Domain<I, DOMAIN>,
    phase: Phase<I, DOMAIN>,
}

impl<I: id::Temporal, const DOMAIN: u8> Owner<I, DOMAIN> {
    pub(crate) const fn queued(endpoint: id::Domain<I, DOMAIN>, owner: I::Queued<DOMAIN>) -> Self {
        Self {
            endpoint,
            phase: Phase::Queued(owner),
        }
    }

    pub(crate) const fn flight(endpoint: id::Domain<I, DOMAIN>, owner: I::Flight<DOMAIN>) -> Self {
        Self {
            endpoint,
            phase: Phase::Flight(owner),
        }
    }

    pub const fn endpoint(self) -> id::Domain<I, DOMAIN> {
        self.endpoint
    }
}

/// Exact queue-to-kernel identity transition for one accepted payload.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Transfer<I: id::Temporal = id::Static, const DOMAIN: u8 = 0> {
    from: Owner<I, DOMAIN>,
    to: Owner<I, DOMAIN>,
}

impl<'d, const DOMAIN: u8> Transfer<id::Driver<'d>, DOMAIN> {
    pub(crate) const fn from_driver(
        endpoint: id::Domain<id::Driver<'d>, DOMAIN>,
        transfer: send::Transfer<'d, route::KeyTag<DOMAIN>>,
    ) -> Self {
        Self {
            from: Owner::queued(endpoint, transfer.queued()),
            to: Owner::flight(endpoint, transfer.flight()),
        }
    }
}

impl<I: id::Temporal, const DOMAIN: u8> Transfer<I, DOMAIN> {
    pub const fn from(self) -> Owner<I, DOMAIN> {
        self.from
    }

    pub const fn to(self) -> Owner<I, DOMAIN> {
        self.to
    }
}

/// Datagram shape accepted by the kernel-facing socket queue.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Shape {
    /// One allocation carries one UDP datagram.
    Plain,
    /// One allocation carries several UDP datagrams through UDP segmentation.
    Segmented {
        segment_size: num::NonZero<u16>,
        datagrams: num::NonZero<usize>,
    },
}

impl Shape {
    pub const fn datagrams(self) -> num::NonZero<usize> {
        match self {
            Self::Plain => num::NonZero::<usize>::MIN,
            Self::Segmented {
                datagrams: count, ..
            } => count,
        }
    }

    pub const fn segment_size(self) -> Option<num::NonZero<u16>> {
        match self {
            Self::Plain => None,
            Self::Segmented {
                segment_size: size, ..
            } => Some(size),
        }
    }

    pub const fn is_segmented(self) -> bool {
        matches!(self, Self::Segmented { .. })
    }
}

/// Payload accepted by the socket queue and paired with one later settlement.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Accepted<I: id::Temporal = id::Static, const DOMAIN: u8 = 0> {
    owner: Owner<I, DOMAIN>,
    destination: net::SocketAddr,
    bytes: usize,
    shape: Shape,
}

impl<I: id::Temporal, const DOMAIN: u8> Accepted<I, DOMAIN> {
    pub(crate) const fn new(
        owner: Owner<I, DOMAIN>,
        peer: net::SocketAddr,
        bytes: usize,
        shape: Shape,
    ) -> Self {
        Self {
            owner,
            destination: peer,
            bytes,
            shape,
        }
    }

    pub const fn owner(self) -> Owner<I, DOMAIN> {
        self.owner
    }

    pub const fn destination(self) -> net::SocketAddr {
        self.destination
    }

    pub const fn bytes(self) -> usize {
        self.bytes
    }

    pub const fn shape(self) -> Shape {
        self.shape
    }
}

/// Terminal result of one accepted socket payload.
pub enum Outcome {
    Sent(transfer::Len),
    Failed(Errno),
    Submit(SubmitError),
    Shutdown,
}

impl From<&send::Outcome> for Outcome {
    fn from(outcome: &send::Outcome) -> Self {
        match outcome {
            send::Outcome::Sent(bytes) => Self::Sent(*bytes),
            send::Outcome::Failed(errno) => Self::Failed(*errno),
            send::Outcome::Submit(error) => Self::Submit(*error),
            send::Outcome::Shutdown => Self::Shutdown,
        }
    }
}

/// CQE-linked borrow of the exact payload owner being retired.
///
/// The borrow cannot escape its callback; recycling follows the return, so
/// instrumentation observes the terminal kernel owner without copying.
pub struct Settlement<'owner, I: id::Temporal = id::Static, const DOMAIN: u8 = 0> {
    owner: Owner<I, DOMAIN>,
    destination: net::SocketAddr,
    outcome: Outcome,
    payload: &'owner [u8],
    settled_at: I::Observation,
}

impl<'owner, 'd, const DOMAIN: u8> Settlement<'owner, id::Driver<'d>, DOMAIN> {
    pub(crate) fn from_driver<'turn, Q: Residency + buffer::raw::Source>(
        endpoint: id::Domain<id::Driver<'d>, DOMAIN>,
        event: &'owner send::Settlement<'turn, 'd, route::KeyTag<DOMAIN>, Q>,
    ) -> Self {
        let payload = match event.payload() {
            send::Payload::Owned(payload) => payload.as_ref(),
            send::Payload::Buffer(payload) => payload.as_ref(),
            send::Payload::Packet(payload) => payload.as_ref(),
        };
        Self {
            owner: match event.owner() {
                send::Owner::Queued(owner) => Owner::queued(endpoint, owner),
                send::Owner::Flight(owner) => Owner::flight(endpoint, owner),
            },
            destination: event.destination(),
            outcome: event.outcome().into(),
            payload,
            settled_at: event.settled_at(),
        }
    }
}

impl<'owner, I: id::Temporal, const DOMAIN: u8> Settlement<'owner, I, DOMAIN> {
    pub const fn owner(&self) -> Owner<I, DOMAIN> {
        self.owner
    }

    pub const fn destination(&self) -> net::SocketAddr {
        self.destination
    }

    pub const fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    pub const fn payload(&self) -> &'owner [u8] {
        self.payload
    }

    pub const fn settled_at(&self) -> I::Observation {
        self.settled_at
    }
}

/// Protocol output failures, queue acceptance and terminal owner retirement.
pub enum Event<'owner, I: id::Temporal = id::Static, const DOMAIN: u8 = 0> {
    /// Exact output failure; timing recovery may already have closed the connection.
    Transmit(errors::Transmit<I, DOMAIN>),
    Receive {
        endpoint: id::Domain<I, DOMAIN>,
        error: ReceiveError,
    },
    /// Permanent queue rejection initiating endpoint shutdown.
    Rejected {
        endpoint: id::Domain<I, DOMAIN>,
        error: RejectCause,
    },
    Accepted(Accepted<I, DOMAIN>),
    Transferred(Transfer<I, DOMAIN>),
    Settled(Settlement<'owner, I, DOMAIN>),
}
