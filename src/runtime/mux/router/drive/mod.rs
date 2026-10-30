use o3::buffer;
use std::{num::NonZero, pin, time};

use dope::core::io::datagram;

use crate::{
    conn, errors,
    proto::datagram::Size,
    runtime::{brand, mux, routing::registry},
    stream,
};
use conn::output::transmit;
use conn::{id, wire};
use issuer::Source as _;
use mux::{auth, handler, output, router};
use registry::Scope;
use router::routing;
use routing::issuer;
use routing::state::timers;
use wire::packet;

mod groups;

const MIN_GSO_PACKETS: usize = 4;

type Observation<I> = <I as id::Temporal>::Observation;

fn slot_max_packet_bytes(first: bool, max: Size) -> NonZero<usize> {
    let size = if first { Size::MIN } else { max };
    NonZero::<u16>::from(size).into()
}

/// Fair packet work for one connection while preserving large kernel batches
/// when only a few connections are runnable.
fn flush_packet_quantum(gso: Option<datagram::GsoLimits>, peers: usize) -> usize {
    let Some(limits) = gso else {
        return mux::FLUSH_PACKET_QUANTUM;
    };
    let flows = peers.saturating_add(1);
    let max = limits.capacity().count();
    max.div_ceil(flows)
        .max(mux::FLUSH_PACKET_QUANTUM.min(max))
        .min(max)
}

fn flush_slot_round<C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>(
    mut slot: registry::Access<'_, C, DOMAIN, B, D, T, false>,
    output: &mut output::Storage,
    peers: usize,
    now: time::Instant,
) -> Result<router::Flush, transmit::Error> {
    let max = slot_max_packet_bytes(*slot.first_flush, *slot.max_packet_bytes);
    let size = max.get();
    if size > output.bytes_capacity {
        return Ok(router::Flush::Closed);
    }
    let gso = if slot
        .conn
        .view()
        .permit()
        .is_gso_ready(size, MIN_GSO_PACKETS)
    {
        output.cache.batch.as_ref().map(packet::Gso::limits)
    } else {
        None
    };
    let quota = flush_packet_quantum(gso, peers);
    let room = output
        .pending
        .capacity()
        .saturating_sub(output.pending.len())
        .min(quota);
    if room == 0 {
        return Ok(router::Flush::Backpressure);
    }
    let space = output.bytes_capacity.saturating_sub(output.pending.bytes());
    let chunk = match gso {
        Some(limits) => mux::FLUSH_BYTE_QUANTUM.min(limits.max_bytes().into_raw()),
        None => mux::FLUSH_BYTE_QUANTUM,
    };
    let bytes = space.min(chunk.max(size));
    let mut count = room.min(bytes / max);
    if let Some(limits) = gso {
        count = count.min(limits.capacity().count());
    }
    if count == 0 {
        return Ok(router::Flush::Backpressure);
    }

    let (sent, result) = if gso.is_some() {
        let count = if slot.conn.view().path().has_output() {
            1
        } else {
            count
        };
        output.emit_gso(count, bytes, *slot.peer_addr, |batch| {
            let (target, result) =
                slot.conn
                    .output()
                    .send_gso(batch, now, count, size, *slot.peer_addr);
            (target.and_then(transmit::Destination::network), result)
        })
    } else {
        output.emit_round(count, size, *slot.peer_addr, |packet| {
            let (target, result) = slot
                .conn
                .output()
                .send_one(packet, now, size, *slot.peer_addr);
            (target.and_then(transmit::Destination::network), result)
        })
    };
    if sent != 0 {
        *slot.first_flush = false;
    }
    result?;
    let more = slot.conn.view().permit().has_pending();
    if more && sent != 0 {
        Ok(router::Flush::More)
    } else if more {
        Ok(router::Flush::Waiting)
    } else {
        Ok(router::Flush::Idle)
    }
}

#[derive(dope::WorkGraph)]
pub(super) enum Phase {
    Notify,
    Deadline,
    Reap,
    Flush,
}

#[derive(Default)]
pub(super) struct State {
    pub(super) phase: PhaseGraph,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::runtime) enum Step {
    Driven,
    Idle,
}

impl Step {
    pub(in crate::runtime::mux) const fn is_driven(self) -> bool {
        matches!(self, Self::Driven)
    }
}

fn flush_slot<
    'storage,
    'id,
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
>(
    sink: pin::Pin<&mut H>,
    scope: brand::Token<'_>,
    mut slots: registry::Scope<'storage, 'id, H::Connection, DOMAIN, B, A::Send, A::Session>,
    key: registry::Key<'id>,
    binding: &mut router::Binding<A, DOMAIN>,
    outgoing: &mut output::Storage,
    now: time::Instant,
) -> Result<router::Flush, errors::Transmit<A::Identity, DOMAIN>> {
    let peers = slots.len_in::<{ mux::FLUSH_QUEUE }>();
    let handle = slots.handle(binding.domain, key);
    let round = router::State::<A, H::Connection, DOMAIN, B>::output_in(
        scope.reborrow(),
        &mut slots,
        key,
        binding,
        outgoing,
        now,
        |slot, output| {
            let round = flush_slot_round(slot, output, peers, now);
            let ready = match &round {
                Ok(router::Flush::More | router::Flush::Backpressure) | Err(_) => true,
                Ok(router::Flush::Idle | router::Flush::Waiting | router::Flush::Closed) => false,
            };
            (round, ready)
        },
    );
    let round = round.map_err(|cause| errors::Transmit::new(handle, cause))?;
    match round {
        router::Flush::Closed => {
            let taken = slots.into_taken(key, binding.domain);
            router::Turn::<A, H, DOMAIN, B>::retire(sink, taken, scope, now);
            Ok(router::Flush::Closed)
        }
        round => Ok(round),
    }
}

fn flush_one<
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
>(
    turn: &mut router::Turn<'_, A, H, DOMAIN, B>,
    now: time::Instant,
) -> Result<Step, errors::Transmit<A::Identity, DOMAIN>> {
    if turn.registry.promote(now).is_driven() || reap_one(turn, now)?.is_driven() {
        return Ok(Step::Driven);
    }
    if turn.outgoing.pending.len() >= turn.outgoing.pending.capacity()
        || turn.outgoing.pending.bytes() >= turn.outgoing.bytes_capacity
    {
        return Ok(Step::Idle);
    }
    turn.run(|scope, turn| {
        let state = &mut *turn.state;
        let binding = &mut state.binding;
        let outgoing = &mut state.outgoing;
        let sink = turn.handler.as_mut();
        Scope::with(&mut state.registry, |mut slots| {
            let Some(key) = slots.pop_front::<{ mux::FLUSH_QUEUE }>() else {
                return Ok(Step::Idle);
            };
            if groups::flush_group(scope.reborrow(), &mut slots, key, binding, outgoing, now)?
                .is_driven()
            {
                return Ok(Step::Driven);
            }
            flush_slot::<A, H, DOMAIN, B>(sink, scope, slots, key, binding, outgoing, now)?;
            Ok(Step::Driven)
        })
    })
}

pub(in crate::runtime::mux) fn drive_one<
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
>(
    turn: &mut router::Turn<'_, A, H, DOMAIN, B>,
    at: Observation<A::Identity>,
) -> Result<Step, errors::Transmit<A::Identity, DOMAIN>> {
    let now = Into::<time::Instant>::into(at);
    let mut seen = 0;
    while seen != PhaseGraph::SLOTS {
        seen += 1;
        let phase = turn.drive.phase.take();
        let driven = match phase {
            Phase::Notify => timers::notify(turn, at),
            Phase::Deadline => turn.registry.promote(now),
            Phase::Reap => reap_one(turn, now)?,
            Phase::Flush => flush_one(turn, now)?,
        };
        if driven.is_driven() {
            return Ok(Step::Driven);
        }
    }
    Ok(Step::Idle)
}

fn reap_one<
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
>(
    turn: &mut router::Turn<'_, A, H, DOMAIN, B>,
    now: time::Instant,
) -> Result<Step, errors::Transmit<A::Identity, DOMAIN>> {
    turn.run(|scope, turn| {
        let state = &mut *turn.state;
        let binding = &mut state.binding;
        let sink = turn.handler.as_mut();
        Scope::with(&mut state.registry, |mut slots| {
            let Some(key) = slots.pop_front::<{ mux::REAP_QUEUE }>() else {
                return Ok(Step::Idle);
            };
            let handle = slots.handle(binding.domain, key);
            let retry = slots.get(key).conn.view().path().is_retry_due(now);
            let token = if retry {
                binding.issuer.challenge()
            } else {
                None
            };
            let (closed, result) =
                router::State::<A, H::Connection, DOMAIN, B>::trusted_in::<_, true>(
                    scope.reborrow(),
                    &mut slots,
                    key,
                    binding,
                    now,
                    |mut slot| {
                        slot.conn.events().mark(conn::Effects::SCHEDULER);
                        slot.conn.lifecycle().expire(now);
                        let result = slot.conn.routing().try_validate(now, token).and_then(|()| {
                            slot.conn
                                .recovery()
                                .try_loss(now)
                                .map_err(transmit::Error::Timing)
                        });
                        (slot.conn.view().lifecycle().is_closed(), result)
                    },
                );
            if closed {
                let taken = slots.into_taken(key, binding.domain);
                router::Turn::<A, H, DOMAIN, B>::retire(sink, taken, scope, now);
            }
            result.map_err(|cause| errors::Transmit::new(handle, cause))?;
            Ok(Step::Driven)
        })
    })
}
