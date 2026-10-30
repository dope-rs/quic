use crate::conn::output::control::revision;
use crate::conn::output::delivery;
use crate::conn::output::journals::stack;
use std::{num::NonZero, time};

use o3::depot::capacity::Reason;

use crate::conn;
use crate::conn::machine::storage::capacity;
use crate::conn::output::journals::{self, controls, streams};
use crate::proto::recovery::rtt;
use crate::wire::frame::ack::ranges;
use crate::wire::packet::header;

pub(in crate::conn) struct Table {
    rings: [journals::Window; 3],
    pools: journals::Pools,
    len: usize,
    /// Live packets own these bytes until their single journal removal.
    /// The admitted u16 packet count bounds their usize sum within u128.
    flight: u128,
}

impl Default for Table {
    fn default() -> Self {
        Self {
            rings: [const { journals::Window::EMPTY }; 3],
            pools: journals::Pools::new(0, 0),
            len: 0,
            flight: 0,
        }
    }
}

/// Read-only journal state for one QUIC packet-number space.
pub(in crate::conn) struct Space<'a> {
    table: &'a Table,
    epoch: conn::Epoch,
}

/// Mutable journal state for one QUIC packet-number space.
pub(in crate::conn::output) struct SpaceMut<'a> {
    table: &'a mut Table,
    epoch: conn::Epoch,
}

impl Table {
    pub(in crate::conn::output) fn new(
        limit: capacity::Capacity<capacity::Packet>,
        ctrl: capacity::Capacity<capacity::Control>,
        stream: capacity::Capacity<capacity::Stream>,
    ) -> Self {
        let crypto = limit.crypto_epoch();
        Self {
            rings: [
                journals::Window::with_limit(crypto),
                journals::Window::with_limit(crypto),
                journals::Window::with_limit(limit),
            ],
            pools: journals::Pools::new(ctrl.get(), stream.get()),
            len: 0,
            flight: 0,
        }
    }

    pub(in crate::conn) fn resident(&self) -> usize {
        self.rings
            .iter()
            .map(journals::Window::resident)
            .fold(self.pools.resident(), usize::saturating_add)
    }

    pub(in crate::conn::output) const fn flight(&self) -> u128 {
        self.flight
    }

    pub(in crate::conn) const fn space(&self, epoch: conn::Epoch) -> Space<'_> {
        Space { table: self, epoch }
    }

    pub(in crate::conn::output) fn space_mut(&mut self, epoch: conn::Epoch) -> SpaceMut<'_> {
        SpaceMut { table: self, epoch }
    }

    pub(in crate::conn::output::journals) fn try_reserve(
        &mut self,
        epoch: conn::Epoch,
        pn: header::Number,
        demand: journals::Demand,
    ) -> Result<NonZero<usize>, Reason> {
        let next = NonZero::<usize>::MIN
            .checked_add(self.len)
            .ok_or(Reason::Full)?;
        if next.get() > self.limit() || !self.pools.can_admit(demand) {
            return Err(Reason::Full);
        }
        let Self { rings, pools, .. } = self;
        let ring = epoch.bind_mut(rings).try_grow(pn)?;
        let pools = pools.try_grow(demand)?;
        ring.commit();
        pools.commit();
        Ok(next)
    }

    pub(in crate::conn::output::journals) fn parts(
        &mut self,
        epoch: conn::Epoch,
    ) -> (
        &mut journals::Window,
        &mut journals::Pools,
        &mut usize,
        &mut u128,
    ) {
        let Self {
            rings,
            pools,
            len,
            flight,
        } = self;
        (epoch.bind_mut(rings), pools, len, flight)
    }

    pub(in crate::conn::output) fn has_carriers(&self, controls: usize, streams: usize) -> bool {
        self.pools.has_room(controls, streams)
    }

    fn recount(&mut self) {
        self.len = self.rings.iter().map(journals::Window::len).sum();
    }

    fn limit(&self) -> usize {
        conn::Epoch::Application.bind(&self.rings).limit()
    }
}

impl SpaceMut<'_> {
    pub(in crate::conn::output) fn drain_where(
        &mut self,
        pred: impl FnMut(&journals::Packet) -> bool,
        mut emit: impl FnMut(
            journals::Packet,
            stack::raw::Drain<'_, revision::Key, controls::Tag>,
            stack::raw::Drain<'_, delivery::Handle<delivery::Stream>, streams::Tag>,
        ),
    ) {
        let Table {
            rings,
            pools,
            flight,
            ..
        } = self.table;
        self.epoch
            .bind_mut(rings)
            .drain_where(pools, flight, pred, &mut emit);
        self.table.recount();
    }

    pub(in crate::conn::output) fn discard(&mut self) {
        self.drain_where(
            |_| true,
            |packet, controls, streams| drop((packet, controls, streams)),
        );
    }

    pub(in crate::conn::output) fn try_ack<E>(
        &mut self,
        ranges: ranges::Validated<'_>,
        mut emit: impl FnMut(
            journals::Packet,
            stack::raw::Drain<'_, revision::Key, controls::Tag>,
            stack::raw::Drain<'_, delivery::Handle<delivery::Stream>, streams::Tag>,
        ) -> Result<(), E>,
    ) -> Result<(), E> {
        let Table {
            rings,
            pools,
            flight,
            ..
        } = self.table;
        let result = self
            .epoch
            .bind_mut(rings)
            .try_ack(pools, flight, ranges, &mut emit);
        self.table.recount();
        result
    }

    pub(in crate::conn::output) fn drain_lost(
        &mut self,
        largest: u64,
        cutoff: Option<time::Instant>,
        emit: impl FnMut(
            journals::Packet,
            stack::raw::Drain<'_, revision::Key, controls::Tag>,
            stack::raw::Drain<'_, delivery::Handle<delivery::Stream>, streams::Tag>,
        ),
    ) {
        let ring = self.epoch.bind(&self.table.rings);
        if ring.first().is_none_or(|packet| packet.pn.get() > largest) {
            return;
        }
        if let Some(cutoff) = cutoff {
            self.drain_where(
                |journal| {
                    let pn = journal.pn.get();
                    if pn > largest {
                        return false;
                    }
                    largest.saturating_sub(pn) >= rtt::PACKET_THRESHOLD
                        || (!journal.transmission.is_pto() && journal.sent_time <= cutoff)
                },
                emit,
            );
        } else if let Some(last) = largest.checked_sub(rtt::PACKET_THRESHOLD) {
            self.drain_where(|journal| journal.pn.get() <= last, emit);
        }
    }

    pub(in crate::conn::output) fn protect_pto(&mut self) {
        self.epoch.bind_mut(&mut self.table.rings).protect_pto();
    }
}

impl Space<'_> {
    pub(in crate::conn::output) fn loss_sent(&self, largest: u64) -> Option<time::Instant> {
        let lowest = largest.saturating_sub(rtt::PACKET_THRESHOLD - 1);
        (lowest..=largest)
            .filter_map(|pn| self.epoch.bind(&self.table.rings).get(pn))
            .filter(|journal| !journal.transmission.is_pto())
            .map(|journal| journal.sent_time)
            .min()
    }

    pub(in crate::conn::output) fn has_room_for(&self, pn: u64, needed: usize) -> bool {
        self.table.len.saturating_add(needed) <= self.table.limit()
            && self.epoch.bind(&self.table.rings).has_room_for(pn, needed)
    }

    pub(in crate::conn) fn count(&self) -> usize {
        self.epoch.bind(&self.table.rings).len()
    }

    pub(in crate::conn::output) fn has_elicit(&self) -> bool {
        self.epoch
            .bind(&self.table.rings)
            .values()
            .any(|packet| packet.transmission.is_eliciting() && packet.transmission.is_flight())
    }
}

const _: () = {
    assert!(usize::BITS <= 64);
    assert!(std::mem::size_of::<Table>() == 16 * std::mem::size_of::<usize>());
};
