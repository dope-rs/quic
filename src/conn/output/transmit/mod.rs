use o3::{
    alloc,
    buffer::{self, resident},
    depot::capacity::{self, Reason},
};

use std::{collections, net, num::NonZero, time};

use crate::conn::output::{Count, control};
use crate::conn::wire::packet::{Allocation, Batch, Fresh, Gso, Sink, Slot};
use crate::security::crypto;
use crate::stream;
use crate::wire::frame::decode::error;
use crate::wire::packet::{encode, header};
use crate::{
    conn, errors,
    proto::{datagram, recovery::pmtud},
};

mod batch;

pub(in crate::conn) mod builder;
mod effects;
mod failure;
pub use failure::Failure;
mod packet;
pub(crate) mod permit;
mod stage;

pub use effects::Effects;

use builder::pending;

/// One protected packet's still-uncommitted publication authority.
type Built<'a, const DOMAIN: u8, B, D> =
    Result<Option<pending::Packet<'a, DOMAIN, B, D>>, Admission>;

/// Protected output retains publication authority; rejection returns scratch ownership.
type Protected<'a, const DOMAIN: u8, B, D, P, O> = Result<
    (O, pending::Packet<'a, DOMAIN, B, D>),
    pending::Failure<P, &'a mut conn::Scratch, pending::Failed<'a>>,
>;

#[derive(Clone, Debug, PartialEq)]
pub enum Admission<P = crypto::Error> {
    Amplification {
        bytes: NonZero<usize>,
    },
    Crypto {
        needed: usize,
        reason: Reason,
    },
    Encoding {
        epoch: conn::Epoch,
        error: error::Fault,
    },
    Header {
        epoch: conn::Epoch,
        error: encode::Error,
    },
    Protection(P),
    Timing(conn::Timing),
    Datagram(datagram::Error),
    Datagrams(collections::TryReserveError),
    Control {
        records: capacity::Count,
        reason: Reason,
    },
    Packet {
        space: conn::Epoch,

        number: header::Number,

        controls: Count,

        streams: Count,
        reason: Reason,
    },
    Stream {
        records: usize,
        reason: Reason,
    },
    StreamCredit {
        sent: u64,
        additional: u64,
    },
    Segments {
        error: alloc::Error,
        requested: usize,
    },
    Packets {
        error: alloc::Error,
        requested: usize,
    },
    Payload {
        error: alloc::Error,
        requested: usize,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    Admission(Admission),
    Timing(conn::Timing),
    Path(capacity::Reason),
    Finalize {
        admission: Admission,
        timing: conn::Timing,
    },
}

impl From<Admission> for Error {
    fn from(error: Admission) -> Self {
        Self::Admission(error)
    }
}

impl<P> From<conn::Timing> for Admission<P> {
    fn from(error: conn::Timing) -> Self {
        Self::Timing(error)
    }
}

impl<P> From<control::Admission> for Admission<P> {
    fn from(error: control::Admission) -> Self {
        let control::Admission { records, reason } = error;
        Self::Control { records, reason }
    }
}

impl<P> From<Allocation> for Admission<P> {
    fn from(error: Allocation) -> Self {
        match error {
            Allocation::Segments {
                error,
                requested: need,
            } => Self::Segments {
                error,
                requested: need,
            },
            Allocation::Packets {
                error,
                requested: need,
            } => Self::Packets {
                error,
                requested: need,
            },
            Allocation::Payload {
                error,
                requested: need,
            } => Self::Payload {
                error,
                requested: need,
            },
        }
    }
}

impl Admission<crypto::Dimensions> {
    pub fn into_error(self) -> Admission {
        match self {
            Self::Amplification { bytes } => Admission::Amplification { bytes },
            Self::Crypto { needed, reason } => Admission::Crypto { needed, reason },
            Self::Encoding { epoch, error } => Admission::Encoding { epoch, error },
            Self::Header { epoch, error } => Admission::Header { epoch, error },
            Self::Protection(error) => Admission::Protection(error.into()),
            Self::Timing(error) => Admission::Timing(error),
            Self::Datagram(error) => Admission::Datagram(error),
            Self::Datagrams(error) => Admission::Datagrams(error),
            Self::Control { records, reason } => Admission::Control { records, reason },
            Self::Packet {
                space,
                number,
                controls,
                streams,
                reason,
            } => Admission::Packet {
                space,
                number,
                controls,
                streams,
                reason,
            },
            Self::Stream { records, reason } => Admission::Stream { records, reason },
            Self::StreamCredit { sent, additional } => Admission::StreamCredit { sent, additional },
            Self::Segments { error, requested } => Admission::Segments { error, requested },
            Self::Packets { error, requested } => Admission::Packets { error, requested },
            Self::Payload { error, requested } => Admission::Payload { error, requested },
        }
    }
}

#[repr(transparent)]
pub struct Emission<
    'a,
    const DOMAIN: u8,
    B: stream::Recv = Vec<u8>,
    D: buffer::raw::Segment = resident::Shared<'a>,
    const RECONCILE: bool = false,
> {
    connection: &'a mut conn::Machine<DOMAIN, B, D>,
}

#[derive(Clone, Copy)]
pub(crate) enum Destination {
    Direct,
    Network(net::SocketAddr),
}

#[derive(Clone, Copy)]
pub(super) enum Policy {
    Direct,
    Fallback(net::SocketAddr),
    Exact(net::SocketAddr),
}

impl Destination {
    pub(crate) fn network(self) -> Option<net::SocketAddr> {
        match self {
            Self::Direct => None,
            Self::Network(address) => Some(address),
        }
    }
}

impl Policy {
    fn resolve(self, routed: Option<net::SocketAddr>) -> Option<Destination> {
        match self {
            Self::Direct => Some(match routed {
                Some(address) => Destination::Network(address),
                None => Destination::Direct,
            }),
            Self::Fallback(fallback) => Some(Destination::Network(match routed {
                Some(routed) => routed,
                None => fallback,
            })),
            Self::Exact(expected) => match routed {
                Some(actual) if actual != expected => None,
                Some(_) | None => Some(Destination::Network(expected)),
            },
        }
    }
}

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, const RECONCILE: bool>
    Emission<'a, DOMAIN, B, D, RECONCILE>
{
    pub(in crate::conn) fn new(conn: &'a mut conn::Machine<DOMAIN, B, D>) -> Self {
        Self { connection: conn }
    }

    /// Protects and commits one arena-owned DATAGRAM, retaining its arena loan.
    pub fn try_packet<'pool>(
        &mut self,
        packet: datagram::Packet<'pool>,
        now: time::Instant,
        max: usize,
    ) -> Result<datagram::Sealed<'pool>, errors::SendFailure<datagram::Packet<'pool>>> {
        use crate::conn::life::datagram::Datagrams;
        use builder::app::datagram::{Outcome, Pooled};
        use errors::SendFailure;

        let Some(limit) = Datagrams::<DOMAIN, B, false, D>::new(self.connection).max_payload()
        else {
            return Err(SendFailure::Unsupported(packet));
        };
        if packet.len() > limit {
            return Err(SendFailure::TooLarge(packet));
        }
        let pto = match stage::Stage::new(self.connection).try_one_rtt(now) {
            Ok(stage::Outcome::Ready(pto)) => pto,
            Ok(stage::Outcome::Closed) => return Err(SendFailure::Closed(packet)),
            Err(error) => {
                return Err(SendFailure::Admission(packet, error));
            }
        };
        let Some(max) = NonZero::new(max) else {
            return Err(SendFailure::Full(packet));
        };
        let pooled = match Pooled::try_new(self.connection, now, max) {
            Ok(pooled) => pooled,
            Err(conn) => {
                if RECONCILE {
                    conn.streams.events.arm_retry();
                }
                return Err(SendFailure::Full(packet));
            }
        };
        let mut records = builder::Records::new();
        let target = Policy::Direct;
        match pooled.build(now, packet, &target, &mut records, pto) {
            Outcome::Admission(packet, error) => {
                if let Admission::Timing(timing) = error {
                    self.connection.fail_timing(timing);
                }
                Err(SendFailure::Admission(packet, error))
            }
            Outcome::Rejected(packet) => Err(SendFailure::Full(packet)),
            Outcome::Sealed(packet, prepared, timer) => {
                prepared.commit(now);
                self.connection.egress.recovery.timer = timer;
                Ok(packet)
            }
            Outcome::Crypto(error) => Err(SendFailure::Crypto(error)),
        }
    }

    /// Returns every committed packet, including those emitted before an error.
    pub fn send(&mut self, now: time::Instant) -> (Vec<Vec<u8>>, Result<(), Error>) {
        let limit = if self
            .connection
            .path
            .output()
            .has_output(&self.connection.control)
        {
            1
        } else {
            conn::MAX_BATCH_PACKETS
        };
        let capacity = self
            .connection
            .egress
            .datagrams
            .pending_datagrams
            .len()
            .min(limit);
        let mut out = match alloc::VecExt::try_new(capacity) {
            Ok(out) => out,
            Err(error) => {
                return (
                    Vec::new(),
                    Err(Admission::Packets {
                        error,
                        requested: capacity,
                    }
                    .into()),
                );
            }
        };
        let result = batch::Batch::new(&mut *self.connection, Policy::Direct).fill(
            &mut out,
            now,
            limit,
            pmtud::MAX_PMTU as usize,
        );
        match result {
            Ok(()) => (out, Ok(())),
            Err(error) => (out, Err(error)),
        }
    }

    pub fn send_batch(
        &mut self,
        batch: &mut Batch,
        now: time::Instant,
        packets: usize,
        bytes: usize,
    ) -> Result<(), Error> {
        let (slots, ceiling) = self.prepare(batch, packets, bytes);
        batch::Batch::new(&mut *self.connection, Policy::Direct).fill(batch, now, slots, ceiling)
    }

    /// Fills `batch` and reports the effects successfully committed.
    /// Observation is compiled out of [`Self::send_batch`].
    pub fn send_effects(
        &mut self,
        batch: &mut Batch,
        now: time::Instant,
        packets: usize,
        bytes: usize,
    ) -> Result<Effects, Failure> {
        let (outcome, result) = self.report::<true>(batch, now, packets, bytes, Policy::Direct);
        match result {
            Ok(()) => Ok(outcome.effects),
            Err(error) => Err(Failure {
                effects: outcome.effects,
                error,
            }),
        }
    }

    pub(crate) fn send_gso(
        &mut self,
        batch: &mut Gso,
        now: time::Instant,
        packets: usize,
        bytes: usize,
        active: net::SocketAddr,
    ) -> (Option<Destination>, Result<(), Error>) {
        let (outcome, result) =
            self.report::<false>(batch, now, packets, bytes, Policy::Fallback(active));
        match result {
            Ok(()) => (outcome.destination, Ok(())),
            Err(error) => (outcome.destination, Err(error)),
        }
    }

    /// Appends exactly one packet to a mux-owned cross-connection GSO flight.
    /// The caller prepares the resident sink once and retains it across a
    /// sequence of short, non-overlapping connection borrows.
    pub(crate) fn append_gso(
        &mut self,
        batch: &mut Gso,
        now: time::Instant,
        bytes: usize,
        active: net::SocketAddr,
    ) -> Result<(), Error> {
        let mut append = batch.append();
        batch::Batch::new(&mut *self.connection, Policy::Exact(active)).fill(
            &mut append,
            now,
            1,
            bytes,
        )
    }

    fn report<const OBSERVE: bool>(
        &mut self,
        batch: &mut (impl Fresh + Sink),
        now: time::Instant,
        packets: usize,
        bytes: usize,
        target: Policy,
    ) -> (batch::Outcome, Result<(), Error>) {
        let (slots, ceiling) = self.prepare(batch, packets, bytes);
        batch::Batch::new(&mut *self.connection, target)
            .report::<OBSERVE, _>(batch, now, slots, ceiling)
    }

    fn prepare(&mut self, batch: &mut impl Fresh, packets: usize, bytes: usize) -> (usize, usize) {
        let packet = bytes.min(self.connection.egress.cc.metrics().current_mtu() as usize);
        let slots = packets.min(conn::MAX_BATCH_PACKETS).min(
            if self
                .connection
                .path
                .output()
                .has_output(&self.connection.control)
            {
                1
            } else {
                conn::MAX_BATCH_PACKETS
            },
        );
        batch.prepare();
        (slots, packet)
    }

    pub(crate) fn send_one(
        &mut self,
        packet: &mut Vec<u8>,
        now: time::Instant,
        bytes: usize,
        active: net::SocketAddr,
    ) -> (Option<Destination>, Result<(), Error>) {
        let mut sink = Slot {
            packet,
            emitted: false,
        };
        let (outcome, result) = batch::Batch::new(&mut *self.connection, Policy::Fallback(active))
            .report::<false, _>(&mut sink, now, 1, bytes);
        match result {
            Ok(()) => (
                sink.emitted.then_some(outcome.destination).flatten(),
                Ok(()),
            ),
            Err(error) => (outcome.destination, Err(error)),
        }
    }
}
