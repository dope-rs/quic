use o3::alloc;
use std::{convert::Infallible, mem, slice};

use o3::alloc::array;
use o3::depot::capacity::{Count, Reason};

use crate::conn::output::journals::{controls, stack, streams};
use crate::conn::output::{control::revision, delivery};
use crate::conn::{machine::storage, output::journals};
use crate::wire::{frame::ack::ranges, packet::header};
use storage::capacity;

mod growth;
mod state;

pub(in crate::conn::output::journals) use growth::Growth;

#[repr(transparent)]
pub(in crate::conn::output) struct Window {
    pub(in crate::conn::output::journals) block:
        array::Block<mem::MaybeUninit<journals::Packet>, Count, state::State>,
}

impl Window {
    pub(in crate::conn::output::journals) const EMPTY: Self = Self::new(Count::EMPTY);

    pub(in crate::conn::output::journals) const fn with_limit(
        limit: capacity::Capacity<capacity::Packet>,
    ) -> Self {
        Self::new(Count::new(limit.as_u32()))
    }

    const fn new(limit: Count) -> Self {
        Self {
            block: array::Block::empty(
                alloc::raw::Empty::EMPTY,
                state::State {
                    head: Count::EMPTY,
                    len: Count::EMPTY,
                    limit,
                },
            ),
        }
    }

    pub(in crate::conn::output::journals) const fn limit(&self) -> usize {
        self.block.state().limit.get()
    }

    pub(in crate::conn::output::journals) const fn len(&self) -> usize {
        self.block.state().len.get()
    }

    pub(in crate::conn::output::journals) const fn resident(&self) -> usize {
        self.block.extent().get() * mem::size_of::<journals::Packet>()
    }

    pub(in crate::conn::output::journals) fn try_grow(
        &mut self,
        pn: header::Number,
    ) -> Result<Growth<'_>, Reason> {
        if !self.has_room_for(pn.get(), 1) {
            return Err(Reason::Full);
        }
        let required = self.len() + 1;
        let resident = self.block.extent().get();
        let spare = if required <= resident {
            None
        } else {
            let plan =
                storage::Plan::geometric(resident, required, self.limit()).ok_or(Reason::Full)?;
            Some(
                array::Block::try_new(Count::new(plan.capacity().get()), ())
                    .map_err(Reason::Allocation)?,
            )
        };
        Ok(Growth {
            window: self,
            spare,
        })
    }

    pub(in crate::conn::output::journals) fn get(&self, pn: u64) -> Option<&journals::Packet> {
        let len = self.len();
        if len == 0 {
            return None;
        }
        let mut left = 0;
        let mut right = len;
        while left < right {
            let middle = left + (right - left) / 2;
            let physical = self
                .block
                .state()
                .physical(self.block.extent().get(), middle);
            let packet = unsafe { &*self.block.as_ptr().add(physical).cast::<journals::Packet>() };
            if packet.pn.get() < pn {
                left = middle + 1;
            } else {
                right = middle;
            }
        }
        if left == len {
            return None;
        }
        let physical = self.block.state().physical(self.block.extent().get(), left);
        let packet = unsafe { &*self.block.as_ptr().add(physical).cast::<journals::Packet>() };
        if packet.pn.get() == pn {
            Some(packet)
        } else {
            None
        }
    }

    pub(in crate::conn::output::journals) fn first(&self) -> Option<&journals::Packet> {
        if self.len() == 0 {
            return None;
        }
        let head = self.block.state().head.get();
        // SAFETY: this nonempty window retains its initialized head, and the
        // returned borrow prevents its removal or backing relocation.
        Some(unsafe { &*self.block.as_ptr().add(head).cast::<journals::Packet>() })
    }

    pub(in crate::conn::output::journals) fn has_room_for(&self, pn: u64, needed: usize) -> bool {
        if needed == 0 {
            return true;
        }
        if needed > self.limit() - self.len() || pn.checked_add((needed - 1) as u64).is_none() {
            return false;
        }
        let Some(last) = self.len().checked_sub(1) else {
            return true;
        };
        let physical = self.block.state().physical(self.block.extent().get(), last);
        unsafe {
            (*self.block.as_ptr().add(physical))
                .assume_init_ref()
                .pn
                .get()
                < pn
        }
    }

    pub(in crate::conn::output::journals) fn drain<const REVERSE: bool>(
        &mut self,
        accept: impl FnMut(&journals::Packet) -> bool,
        mut emit: impl FnMut(journals::Packet),
    ) {
        match self.try_drain::<REVERSE, Infallible>(accept, |packet| {
            emit(packet);
            Ok(())
        }) {
            Ok(()) => {}
            Err(never) => match never {},
        }
    }

    fn try_drain<const REVERSE: bool, E>(
        &mut self,
        mut accept: impl FnMut(&journals::Packet) -> bool,
        mut emit: impl FnMut(journals::Packet) -> Result<(), E>,
    ) -> Result<(), E> {
        let capacity = self.block.extent().get();
        let len = self.len();
        let pointer = self.block.as_mut_ptr();
        let at = |step| {
            let offset = if REVERSE { len - step - 1 } else { step };
            let source = self.block.state().physical(capacity, offset);
            // SAFETY: both traversals visit only original offsets below len.
            (offset, unsafe { pointer.add(source) })
        };
        let retain = |offset, source, removed| {
            if removed != 0 {
                let target = if REVERSE {
                    offset + removed
                } else {
                    offset - removed
                };
                let target = self.block.state().physical(capacity, target);
                // SAFETY: distinct logical offsets below len <= capacity
                // identify disjoint slots. This retained value moves once.
                unsafe { pointer.add(target).copy_from_nonoverlapping(source, 1) };
            }
        };
        let mut removed = 0;
        let mut steps = 0..len;
        let result = loop {
            let Some(step) = steps.next() else {
                break Ok(());
            };
            let (offset, source) = at(step);
            // SAFETY: each original initialized slot is visited once. Moves
            // only fill already visited slots, including across the wrap.
            if accept(unsafe { (*source).assume_init_ref() }) {
                removed += 1;
                if let Err(error) = emit(unsafe { source.read().assume_init() }) {
                    break Err(error);
                }
            } else {
                retain(offset, source, removed);
            }
        };
        for step in steps {
            let (offset, source) = at(step);
            retain(offset, source, removed);
        }
        if removed == 0 {
            return result;
        }
        let state = self.block.state_mut();
        state.len = Count::new((len - removed) as u32);
        if len == removed {
            state.head = Count::EMPTY;
        } else if REVERSE {
            state.head = Count::new(state.physical(capacity, removed) as u32);
        }
        result
    }

    pub(in crate::conn::output::journals) fn values(
        &self,
    ) -> impl Iterator<Item = &journals::Packet> {
        let (head, first, second) = self.block.state().split(self.block.extent().get());
        let pointer = self.block.as_ptr().cast::<journals::Packet>();
        let first = unsafe { slice::from_raw_parts(pointer.add(head), first) };
        let second = unsafe { slice::from_raw_parts(pointer, second) };
        first.iter().chain(second)
    }

    fn emit<R>(
        pools: &mut journals::Pools,
        flight: &mut u128,
        mut journal: journals::Packet,
        emit: &mut impl FnMut(
            journals::Packet,
            stack::raw::Drain<'_, revision::Key, controls::Tag>,
            stack::raw::Drain<'_, delivery::Handle<delivery::Stream>, streams::Tag>,
        ) -> R,
    ) -> R {
        *flight -= journal.flight();
        let (controls, streams) = pools.drain(&mut journal);
        emit(journal, controls, streams)
    }

    pub(in crate::conn::output::journals) fn try_ack<E>(
        &mut self,
        pools: &mut journals::Pools,
        flight: &mut u128,
        ranges: ranges::Validated<'_>,
        emit: &mut impl FnMut(
            journals::Packet,
            stack::raw::Drain<'_, revision::Key, controls::Tag>,
            stack::raw::Drain<'_, delivery::Handle<delivery::Stream>, streams::Tag>,
        ) -> Result<(), E>,
    ) -> Result<(), E> {
        if self
            .first()
            .is_none_or(|packet| packet.pn.get() > ranges.largest())
        {
            return Ok(());
        }
        let (first, mut rest) = ranges.spans();
        let mut current = Some(first);
        self.try_drain::<true, E>(
            |journal| loop {
                let Some(span) = current else {
                    return false;
                };
                if journal.pn.get() > span.largest() {
                    return false;
                }
                if journal.pn.get() >= span.smallest() {
                    return true;
                }
                current = rest.next();
            },
            |journal| Self::emit(pools, flight, journal, emit),
        )
    }

    pub(in crate::conn::output::journals) fn drain_where(
        &mut self,
        pools: &mut journals::Pools,
        flight: &mut u128,
        accept: impl FnMut(&journals::Packet) -> bool,
        emit: &mut impl FnMut(
            journals::Packet,
            stack::raw::Drain<'_, revision::Key, controls::Tag>,
            stack::raw::Drain<'_, delivery::Handle<delivery::Stream>, streams::Tag>,
        ),
    ) {
        self.drain::<false>(accept, |journal| Self::emit(pools, flight, journal, emit));
    }

    pub(in crate::conn::output::journals) fn protect_pto(&mut self) {
        let (head, first, second) = self.block.state().split(self.block.extent().get());
        let pointer = self.block.as_mut_ptr().cast::<journals::Packet>();
        let first = unsafe { slice::from_raw_parts_mut(pointer.add(head), first) };
        let second = unsafe { slice::from_raw_parts_mut(pointer, second) };
        for packet in first.iter_mut().chain(second) {
            if packet.transmission.is_flight() {
                packet.transmission.protect_pto();
            }
        }
    }
}

const _: () = {
    assert!(size_of::<Window>() == 3 * size_of::<usize>());
    assert!(!mem::needs_drop::<journals::Packet>());
};
