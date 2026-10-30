//! Demand-backed packet recovery journals.

pub(in crate::conn::output) use pools::Pools;
pub(in crate::conn) use table::Table;
pub(in crate::conn::output) use window::Window;

pub(super) mod controls;
pub(in crate::conn::output) mod raw;
pub(in crate::conn::output) mod stack;
pub(in crate::conn) mod streams;
mod table;

mod pools;
mod window;

use crate::conn;
use crate::conn::output::control::revision;
use crate::conn::output::{Count, delivery};
use crate::wire::packet::header;
use o3::depot::{
    array::{self, init},
    capacity,
};
use std::{marker, mem, num::NonZero, time};

/// Carrier upper bounds derived from one bounded packet plan.
#[derive(Clone, Copy)]
pub(in crate::conn::output) struct Demand {
    controls: Count,
    streams: Count,
}

/// One non-duplicable carrier insertion admitted by a reservation.
pub(in crate::conn) struct Slot<'a, Tag>(marker::PhantomData<fn(&'a Tag) -> &'a Tag>);

impl<'a, Tag> Slot<'a, Tag> {
    /// # Safety
    /// The head belongs to the original pool of this admitted insertion.
    pub(in crate::conn::output::journals) unsafe fn push<T: Copy>(
        self,
        slab: &mut &'a mut stack::raw::Slab<T, Tag>,
        head: &mut stack::Head<Tag>,
        value: T,
    ) {
        let Self(marker::PhantomData) = self;
        let state = slab.block.state_mut();
        let index = if state.free == u16::MAX {
            state.live
        } else {
            state.free
        };
        let pointer = unsafe { slab.block.as_mut_ptr().add(usize::from(index)) };
        let state = slab.block.state_mut();
        if state.free != u16::MAX {
            state.free = unsafe { (*pointer).assume_init_ref().next };
        }
        unsafe {
            pointer.write(mem::MaybeUninit::new(stack::raw::Node {
                value,
                next: head.index,
            }))
        };
        head.index = index;
        state.live += 1;
    }
}

pub(in crate::conn) struct Supply<Tag> {
    count: Count,
    tag: marker::PhantomData<fn(Tag) -> Tag>,
}

pub(in crate::conn) struct Slots<'a, T, Tag> {
    values: init::IntoIter<'a, T>,
    remaining: usize,
    tag: marker::PhantomData<fn(&'a Tag) -> &'a Tag>,
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub(in crate::conn::output) struct Transmission(u8);

pub(in crate::conn::output) struct Packet {
    pub(in crate::conn::output) transmission: Transmission,
    pub(in crate::conn::output::journals) carriers: Carriers,
    pub(in crate::conn::output) pn: header::Number,
    pub(in crate::conn::output) sent_time: time::Instant,
    pub(in crate::conn::output) bytes_sent: usize,
    pub(in crate::conn::output) crypto: Option<delivery::Handle<delivery::Crypto>>,
}

pub(in crate::conn::output::journals) struct Carriers {
    controls: stack::Head<controls::Tag>,
    streams: stack::Head<streams::Tag>,
}

impl Packet {
    fn flight(&self) -> u128 {
        if self.transmission.is_flight() {
            self.bytes_sent as u128
        } else {
            0
        }
    }

    pub(in crate::conn::output) fn new(
        tx: Transmission,
        pn: header::Number,
        sent: time::Instant,
        bytes: usize,
    ) -> Self {
        Self {
            transmission: tx,
            carriers: Carriers {
                controls: stack::Head::new(),
                streams: stack::Head::new(),
            },
            pn,
            sent_time: sent,
            bytes_sent: bytes,
            crypto: None,
        }
    }
}

impl Demand {
    pub(in crate::conn::output) fn new<C, S>(
        controls: &array::Vec<C, { conn::PACKET_CONTROL_CAPACITY }>,
        streams: &array::Vec<S, { conn::PACKET_STREAM_CAPACITY }>,
    ) -> Self {
        Self {
            controls: Count::new(controls.extent()),
            streams: Count::new(streams.extent()),
        }
    }

    pub(in crate::conn::output) const fn counts(self) -> (Count, Count) {
        (self.controls, self.streams)
    }

    pub(in crate::conn::output::journals) fn supplies(
        self,
    ) -> (Supply<controls::Tag>, Supply<streams::Tag>) {
        (Supply::new(self.controls), Supply::new(self.streams))
    }
}

impl<Tag> Supply<Tag> {
    fn new(count: Count) -> Self {
        Self {
            count,
            tag: marker::PhantomData,
        }
    }

    pub(in crate::conn) fn consume<'a, T>(
        self,
        values: init::IntoIter<'a, T>,
    ) -> Slots<'a, T, Tag> {
        Slots {
            values,
            remaining: usize::from(self.count.get()),
            tag: marker::PhantomData,
        }
    }
}

impl<'a, T, Tag> Iterator for Slots<'a, T, Tag> {
    type Item = (T, Slot<'a, Tag>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        self.values
            .next()
            .map(|value| (value, Slot(marker::PhantomData)))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.values.len().min(self.remaining);
        (len, Some(len))
    }
}

impl<T, Tag> Slots<'_, T, Tag> {
    pub(in crate::conn) fn as_mut_slice(&mut self) -> &mut [T] {
        self.values.as_mut_slice()
    }
}

impl Transmission {
    const EARLY_DATA: u8 = 1 << 0;
    const ACK_ELICITING: u8 = 1 << 1;
    const IN_FLIGHT: u8 = 1 << 2;
    const PTO_PROTECTED: u8 = 1 << 3;

    pub(in crate::conn::output) fn new(early: bool, elicits: bool, flight: bool) -> Self {
        Self(
            (u8::from(early) * Self::EARLY_DATA)
                | (u8::from(elicits) * Self::ACK_ELICITING)
                | (u8::from(flight) * Self::IN_FLIGHT),
        )
    }

    pub(in crate::conn::output) fn is_early(self) -> bool {
        self.0 & Self::EARLY_DATA != 0
    }

    pub(in crate::conn::output) fn is_eliciting(self) -> bool {
        self.0 & Self::ACK_ELICITING != 0
    }

    pub(in crate::conn::output) fn is_flight(self) -> bool {
        self.0 & Self::IN_FLIGHT != 0
    }

    pub(in crate::conn::output) fn is_pto(self) -> bool {
        self.0 & Self::PTO_PROTECTED != 0
    }

    pub(in crate::conn::output) fn protect_pto(&mut self) {
        self.0 |= Self::PTO_PROTECTED;
    }
}

const _: () = {
    assert!(mem::size_of::<Demand>() == 2);
    assert!(mem::size_of::<Slot<'static, controls::Tag>>() == 0);
    assert!(mem::size_of::<Supply<controls::Tag>>() == 1);
    assert!(mem::size_of::<Transmission>() == 1);
    assert!(mem::size_of::<Packet>() == 48);
};

pub(in crate::conn::output) struct Entry<'a> {
    packet: &'a mut Packet,
    controls: &'a mut stack::raw::Slab<revision::Key, controls::Tag>,
    streams: &'a mut stack::raw::Slab<delivery::Handle<delivery::Stream>, streams::Tag>,
    scope: marker::PhantomData<fn(&'a ()) -> &'a ()>,
}

impl<'a> Entry<'a> {
    fn new(
        packet: &'a mut Packet,
        controls: &'a mut stack::raw::Slab<revision::Key, controls::Tag>,
        streams: &'a mut stack::raw::Slab<delivery::Handle<delivery::Stream>, streams::Tag>,
    ) -> Self {
        Self {
            packet,
            controls,
            streams,
            scope: marker::PhantomData,
        }
    }

    pub(in crate::conn::output) fn push_control(
        &mut self,
        slot: Slot<'a, controls::Tag>,
        handle: revision::Key,
    ) {
        // SAFETY: the consumed slot is one element of this packet's bounded
        // control supply. Its invariant scope binds it to this exact pool.
        unsafe {
            slot.push(
                &mut self.controls,
                &mut self.packet.carriers.controls,
                handle,
            )
        };
    }

    pub(in crate::conn::output) fn push_stream(
        &mut self,
        slot: Slot<'a, streams::Tag>,
        handle: delivery::Handle<delivery::Stream>,
    ) {
        // SAFETY: the consumed slot is one element of this packet's bounded
        // stream supply. Its invariant scope binds it to this exact pool.
        unsafe { slot.push(&mut self.streams, &mut self.packet.carriers.streams, handle) };
    }
}

const _: () = assert!(std::mem::size_of::<Entry<'static>>() == 3 * std::mem::size_of::<usize>());

#[must_use]
pub(in crate::conn::output) struct Reserve<O: raw::Owner> {
    owner: O,
    epoch: conn::Epoch,
    pn: header::Number,
    demand: Demand,
    next: NonZero<usize>,
}

impl<O: raw::Owner> Reserve<O> {
    pub(in crate::conn::output) fn try_new(
        mut owner: O,
        epoch: conn::Epoch,
        pn: header::Number,
    ) -> Result<Self, (O, capacity::Reason, Demand)> {
        let demand = owner.demand();
        let result = owner.parts().0.try_reserve(epoch, pn, demand);
        let next = match result {
            Ok(next) => next,
            Err(reason) => return Err((owner, reason, demand)),
        };
        Ok(Self {
            owner,
            epoch,
            pn,
            demand,
            next,
        })
    }

    pub(in crate::conn::output) fn owner(&self) -> &O {
        &self.owner
    }

    pub(in crate::conn::output) fn context(&mut self) -> O::Context<'_> {
        self.owner.parts().2
    }

    pub(in crate::conn::output) fn cancel(self) -> O {
        self.owner
    }

    pub(in crate::conn::output) fn commit(
        mut self,
        tx: Transmission,
        now: time::Instant,
        bytes: usize,
        crypto: Option<delivery::Handle<delivery::Crypto>>,
    ) -> O {
        let mut packet = Packet::new(tx, self.pn, now, bytes);
        packet.crypto = crypto;
        let charged = packet.flight();
        let (control, stream) = self.demand.supplies();
        let (table, controls, context) = self.owner.parts();
        let (window, pools, len, flight) = table.parts(self.epoch);
        O::write(
            pools.entry(&mut packet),
            control.consume(controls.drain()),
            stream,
            context,
        );
        *len = self.next.get();
        *flight += charged;
        let capacity = window.block.extent().get();
        let state = window.block.state_mut();
        let physical = state.physical(capacity, state.len.get());
        state.len = capacity::Count::new(state.len.raw() + 1);
        unsafe {
            window
                .block
                .as_mut_ptr()
                .add(physical)
                .write(mem::MaybeUninit::new(packet))
        };
        self.owner
    }
}
