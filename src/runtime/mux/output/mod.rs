use o3::buffer::storage;
use std::{net, num::NonZero};

mod flight;
pub(in crate::runtime) mod gate;
pub(in crate::runtime) mod quantum;
mod queue;
mod segments;

use crate::runtime::Transit;
pub use flight::Flight;
pub(in crate::runtime) use flight::Kind;
pub use queue::Queue;
pub use segments::Segments;

use o3::{
    alloc::{self, VecExt as _},
    depot::{capacity, queue::ring},
};

use crate::conn::{self, wire::packet};
use packet::Fresh as _;

pub(super) struct Storage {
    pub(super) pending: Pending,
    pub(super) bytes_capacity: usize,
    pub(super) cache: Cache,
}

/// Owns each queued flight and the exact sum of its immutable packet and byte extents.
pub(super) struct Pending {
    flights: ring::Fifo<Flight>,
    packets: usize,
    bytes: usize,
}

pub(super) struct Cache {
    pub(super) batch: Option<packet::Gso>,
    pub(super) recycled: Vec<Vec<u8>>,
}

/// Vacant queue entry coupled to its packet and byte credits until commit.
struct Reservation<'storage> {
    vacant: ring::Vacant<'storage, ring::Fifo<Flight>>,
    packets: &'storage mut usize,
    bytes: &'storage mut usize,
    packet: NonZero<usize>,
    byte: NonZero<usize>,
}

/// One segmentation flight whose queue credit and builder share this exact
/// borrow. Consequently packet state cannot be committed into a flight whose
/// output owner could disappear or lose admission before publication.
struct GsoFlight<'storage> {
    slot: Reservation<'storage>,
    batch: &'storage mut packet::Gso,
}

pub(in crate::runtime) enum Submit<'quota, R, E> {
    Empty,
    Deferred,
    Accepted(R, quantum::Reservation<'quota>),
    Rejected(E),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::runtime::mux) enum Emission {
    Sent,
    Skipped,
    Allocation {
        error: alloc::Error,
        requested: usize,
    },
}

impl Pending {
    pub(super) fn capacity(&self) -> usize {
        self.flights.capacity()
    }

    pub(super) fn len(&self) -> usize {
        self.packets
    }

    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(super) fn is_empty(&self) -> bool {
        self.flights.is_empty()
    }

    fn reserve(&mut self, limit: usize, packet: usize, byte: usize) -> Option<Reservation<'_>> {
        let packet = NonZero::new(packet)?;
        let byte = NonZero::new(byte)?;
        if packet.get() > self.capacity() - self.packets
            || byte.get() > limit.saturating_sub(self.bytes)
        {
            return None;
        }
        let vacant = self.flights.vacant()?;
        Some(Reservation {
            vacant,
            packets: &mut self.packets,
            bytes: &mut self.bytes,
            packet,
            byte,
        })
    }

    fn pop_front(&mut self) -> Option<Flight> {
        let front = self.flights.front_entry()?;
        let packets = front.get().packet_count();
        let bytes = front.get().byte_len();
        let outgoing = front.remove();
        self.packets -= packets.get();
        self.bytes -= bytes;
        Some(outgoing)
    }

    fn submit<'quota, R, E>(
        &mut self,
        credit: quantum::Credit<'quota>,
        submit: impl for<'op> FnOnce(Transit<'op>) -> Result<R, (Transit<'op>, E)>,
    ) -> Submit<'quota, R, E> {
        let Some(front) = self.flights.front_entry() else {
            return Submit::Empty;
        };
        let count = front.get().packet_count();
        let Some(grant) = credit.try_reserve(count) else {
            return Submit::Deferred;
        };
        let len = front.get().byte_len();
        let packets = self.packets - count.get();
        let bytes = self.bytes - len;
        let (outgoing, vacant) = front.take();
        match Transit::scope(outgoing, submit) {
            Ok(value) => {
                self.packets = packets;
                self.bytes = bytes;
                Submit::Accepted(value, grant)
            }
            Err((outgoing, error)) => {
                vacant.push_front(outgoing);
                Submit::Rejected(error)
            }
        }
    }
}

impl Reservation<'_> {
    fn commit(self, outgoing: Flight) -> Result<NonZero<usize>, Flight> {
        let count = outgoing.packet_count();
        let len = outgoing.byte_len();
        if count > self.packet || len > self.byte.get() {
            return Err(outgoing);
        }
        let packets = *self.packets + count.get();
        let bytes = *self.bytes + len;
        self.vacant.push_back(outgoing);
        *self.packets = packets;
        *self.bytes = bytes;
        Ok(count)
    }
}

impl GsoFlight<'_> {
    fn commit(self, addr: net::SocketAddr) -> usize {
        let Self { slot, batch } = self;
        let Some(ready) = batch.take() else {
            return 0;
        };
        let outgoing = if ready.packets.get() == 1 {
            Flight::plain(addr, ready.payload)
        } else {
            Flight::batch(addr, ready.payload, ready.segment_size, ready.packets)
        };
        slot.commit(outgoing).map_or(0, NonZero::get)
    }
}

impl Cache {
    fn recycle(&mut self, mut packet: Vec<u8>) {
        packet.clear();
        if let Some(batch) = self.batch.as_mut() {
            packet = match batch.recycle(packet) {
                Ok(()) => return,
                Err(packet) => packet,
            };
        }
        if self.recycled.len() < self.recycled.capacity() {
            self.recycled.push(packet);
        }
    }
}

impl Storage {
    pub(super) fn try_new(capacity: capacity::Count, limit: usize) -> Result<Self, alloc::Error> {
        Ok(Self {
            pending: Pending {
                flights: ring::Fifo::try_new(capacity)?,
                packets: 0,
                bytes: 0,
            },
            bytes_capacity: limit,
            cache: Cache {
                batch: None,
                recycled: Vec::try_new(capacity.get())?,
            },
        })
    }

    /// Removes one flight and returns its packet and byte credits atomically.
    pub(super) fn pop_front(&mut self) -> Option<Flight> {
        self.pending.pop_front()
    }

    pub(super) fn gso_room(&self, max: NonZero<usize>) -> usize {
        let Some(batch) = self.cache.batch.as_ref() else {
            return 0;
        };
        batch
            .limits()
            .capacity()
            .count()
            .min(conn::MAX_BATCH_PACKETS)
            .min(self.pending.capacity() - self.pending.len())
            .min(self.bytes_capacity.saturating_sub(self.pending.bytes()) / max)
    }

    fn gso_flight(&mut self, packet: usize, byte: usize) -> Option<GsoFlight<'_>> {
        let Self {
            pending,
            bytes_capacity: limit,
            cache,
        } = self;
        let slot = pending.reserve(*limit, packet, byte)?;
        let batch = cache.batch.as_mut()?;
        Some(GsoFlight { slot, batch })
    }

    pub(super) fn emit_gso<E>(
        &mut self,
        packet: usize,
        byte: usize,
        fallback: net::SocketAddr,
        emit: impl for<'batch> FnOnce(
            &'batch mut packet::Gso,
        ) -> (Option<net::SocketAddr>, Result<(), E>),
    ) -> (usize, Result<(), E>) {
        let Some(flight) = self.gso_flight(packet, byte) else {
            return (0, Ok(()));
        };
        let (addr, result) = emit(flight.batch);
        (flight.commit(addr.unwrap_or(fallback)), result)
    }

    /// Builds and publishes one mux-owned cross-connection GSO flight.
    /// The HRTB prevents the resident builder from escaping, and normal
    /// closure return always consumes the exact admission in `commit`.
    pub(super) fn build_gso<E>(
        &mut self,
        packet: usize,
        byte: usize,
        addr: net::SocketAddr,
        emit: impl for<'batch> FnOnce(&'batch mut packet::Gso) -> Result<(), E>,
    ) -> (usize, Result<(), E>) {
        self.emit_gso(packet, byte, addr, |batch| {
            batch.prepare();
            (None, emit(batch))
        })
    }

    pub(super) fn emit_owned(
        &mut self,
        byte: usize,
        required: usize,
        build: impl FnOnce(Vec<u8>) -> Result<Flight, (Vec<u8>, Option<alloc::Error>)>,
    ) -> Emission {
        let Self {
            pending,
            bytes_capacity: limit,
            cache,
        } = self;
        let Some(slot) = pending.reserve(*limit, 1, byte) else {
            return Emission::Skipped;
        };
        let mut packet = cache.recycled.pop().unwrap_or_default();
        if let Err(error) = packet.try_grow(required) {
            cache.recycle(packet);
            return Emission::Allocation {
                error,
                requested: required,
            };
        }
        match build(packet) {
            Ok(outgoing) => match slot.commit(outgoing) {
                Ok(_) => Emission::Sent,
                Err(outgoing) => {
                    cache.recycle(outgoing.into_storage());
                    Emission::Skipped
                }
            },
            Err((packet, error)) => {
                cache.recycle(packet);
                match error {
                    Some(error) => Emission::Allocation {
                        error,
                        requested: required,
                    },
                    None => Emission::Skipped,
                }
            }
        }
    }

    pub(super) fn emit_round<E>(
        &mut self,
        limit: usize,
        max: usize,
        fallback: net::SocketAddr,
        mut emit: impl for<'packet> FnMut(
            &'packet mut Vec<u8>,
        ) -> (Option<net::SocketAddr>, Result<(), E>),
    ) -> (usize, Result<(), E>) {
        let Self {
            pending,
            bytes_capacity: cap,
            cache,
        } = self;
        let mut emitted = 0;
        while emitted != limit {
            let Some(slot) = pending.reserve(*cap, 1, max) else {
                break;
            };
            let mut packet = cache.recycled.pop().unwrap_or_default();
            let (addr, result) = emit(&mut packet);
            let addr = addr.unwrap_or(fallback);
            let count = match storage::NonEmpty::try_new(packet) {
                Ok(packet) => slot
                    .commit(Flight::plain(addr, packet))
                    .map_or(0, NonZero::get),
                Err(empty) => {
                    cache.recycle(empty.into_parts().0);
                    0
                }
            };
            emitted += count;
            if let Err(error) = result {
                return (emitted, Err(error));
            }
            if count == 0 {
                break;
            }
        }
        (emitted, Ok(()))
    }
}
