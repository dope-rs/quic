use crate::conn::output::control;
use crate::conn::stream::event::queue::{self, readable};
use crate::conn::stream::resident::{
    self,
    slot::{self, plane, store},
};
use crate::conn::stream::state::receive::recv::map::{
    Handle, Held, Node, Side, Tag, recycle, views,
};
use crate::conn::stream::state::receive::{Consumed, recv};
use crate::conn::stream::state::resident::{Table, sides};
use crate::conn::wire::ingress::frames::CommitPermit;
use crate::errors::detail;
use crate::stream::Recv;
use crate::wire::ranges::{inserts, plan};
use crate::wire::{frame, stream, varint};
use control::journal::{self, records};
use o3::depot;
use std::ops;
use views::Read;

pub(in crate::conn) struct Resolved<'map, B: Recv> {
    pub(super) entry: slot::Resolved<'map, Side, recv::Entry<B>, Option<readable::Handle>>,
    pub(super) arena: &'map depot::raw::Arena<Node<B>, Tag>,
}

impl<B: Recv> Resolved<'_, B> {
    pub(in crate::conn) fn state(&self) -> &recv::State {
        &self.entry.value().state
    }

    pub(in crate::conn) fn try_plan<'a>(
        &self,
        segs: &'a mut Vec<ops::Range<u64>>,
        parts: &'a mut Vec<inserts::Part>,
    ) -> Result<plan::Plan<'a>, detail::Ranges> {
        Read::new(&self.entry.value().buffer, self.arena).try_plan(segs, parts, |_| {})
    }

    pub(in crate::conn) fn has_event(&self) -> bool {
        self.entry.auxiliary().is_some()
    }
}

pub(in crate::conn) enum Slot<'map, B: Recv> {
    Occupied(Occupied<'map, B>),
    Vacant(Vacant<'map, B>),
    Unavailable,
}

impl<'map, B: Recv> Slot<'map, B> {
    pub(in crate::conn) fn insert(self, registry: &mut Table) -> Option<Occupied<'map, B>> {
        match self {
            Self::Occupied(occupied) => {
                let slot = occupied.entry.handle().index();
                match registry.side::<false>().claim(occupied.id()) {
                    sides::Entry::Occupied(resident) if resident.slot() == slot => Some(occupied),
                    sides::Entry::Occupied(_) | sides::Entry::Unavailable => None,
                    sides::Entry::Vacant(vacant) => {
                        vacant.release();
                        None
                    }
                }
            }
            Self::Vacant(vacant) => {
                let id = vacant.entry.id();
                let sides::Entry::Vacant(resident) = registry.side::<false>().claim(id) else {
                    return None;
                };
                let occupied = vacant.insert()?;
                resident.bind(occupied.entry.handle());
                Some(occupied)
            }
            Self::Unavailable => None,
        }
    }
}

pub(in crate::conn) struct Occupied<'map, B: Recv> {
    pub(super) entry:
        store::Occupied<'map, Side, recv::Entry<B>, Option<readable::Handle>, plane::HeadOnly>,
    pub(super) arena: &'map depot::raw::Arena<Node<B>, Tag>,
}

impl<'map, B: Recv> Occupied<'map, B> {
    pub(in crate::conn) fn id(&self) -> stream::Id {
        self.entry.id()
    }

    fn key(&self, registry: &Table) -> Option<resident::Key> {
        registry.read().key(self.entry.id())
    }

    fn borrow(&mut self) -> views::Write<'map, '_, B> {
        views::Write {
            entry: self.entry.get_mut(),
            arena: self.arena,
        }
    }

    pub(in crate::conn) fn hold(&mut self) -> (Option<Held<B>>, bool) {
        let held = self.borrow().read_buffer().map(|(buffer, bytes)| Held {
            buffer,
            handle: Handle::from_storage(self.entry.handle()),
            bytes,
        });
        (held, self.entry.get().state.is_eof())
    }

    pub(in crate::conn::stream::state::receive) fn read(
        mut self,
        dst: &mut Vec<u8>,
    ) -> DeliveryRead<'map, B, Result<usize, crate::stream::Capacity>> {
        let value = self.borrow().read(dst);
        let free = value.as_ref().map_or(0, |count| *count as u64);
        DeliveryRead {
            slot: self,
            value,
            free,
        }
    }

    pub(in crate::conn::stream::state::receive) fn read_owned(
        mut self,
    ) -> DeliveryRead<'map, B, Result<Option<Vec<u8>>, crate::stream::Capacity>> {
        let value = self.borrow().read_owned();
        let free = value
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
            .map_or(0, |bytes| bytes.len() as u64);
        DeliveryRead {
            slot: self,
            value,
            free,
        }
    }

    pub(in crate::conn::stream::state::receive) fn read_buffer(
        mut self,
    ) -> DeliveryRead<'map, B, Option<B>> {
        let (value, free) = self
            .borrow()
            .read_buffer()
            .map_or((None, 0), |(buffer, count)| (Some(buffer), count as u64));
        DeliveryRead {
            slot: self,
            value,
            free,
        }
    }

    pub(in crate::conn::stream::state::receive) fn observe(
        &mut self,
        permit: CommitPermit<'_>,
        offset: varint::VarInt,
        record: plan::Record,
        boundary: frame::Boundary,
    ) {
        self.entry
            .get_mut()
            .state
            .observe(permit, offset, record, boundary);
    }

    pub(in crate::conn::stream::state::receive) fn reset(
        &mut self,
        code: crate::errors::Code,
        end: u64,
    ) {
        self.entry.get_mut().state.reset(code, end);
    }

    pub(in crate::conn) fn stop(
        &mut self,
        ctrl: &mut control::Pending,
        code: crate::errors::Code,
        base: varint::VarInt,
    ) {
        let state = &mut self.entry.get_mut().state;
        state.credit.stop(base);
        ctrl.stop(&mut state.stop_sending, code);
        self.activate();
    }

    pub(in crate::conn) fn push_read(
        &mut self,
        events: &mut queue::Permit<'_>,
        registry: &mut Table,
    ) {
        let id = self.entry.id();
        let Some(key) = self.key(registry) else {
            return;
        };
        let position = self.entry.position_mut();
        let Some((hold, event)) = registry.event::<false>().hold(key, id) else {
            return;
        };
        if matches!(
            events.push_read(hold, key, position, id),
            queue::Push::Rollback
        ) {
            event.release();
        }
    }

    pub(in crate::conn) fn push_reset(
        &mut self,
        events: &mut queue::Permit<'_>,
        registry: &mut Table,
        code: crate::errors::Code,
    ) {
        let id = self.entry.id();
        let Some(key) = self.key(registry) else {
            return;
        };
        let position = self.entry.position_mut();
        let Some((hold, event)) = registry.event::<false>().hold(key, id) else {
            return;
        };
        if matches!(
            events.push_reset(hold, key, position, id, code),
            queue::Push::Rollback
        ) {
            event.release();
        }
    }

    pub(in crate::conn) fn cancel_read(
        &mut self,
        events: &mut queue::Pending,
        registry: &mut Table,
    ) {
        let id = self.entry.id();
        let Some(key) = self.key(registry) else {
            return;
        };
        let position = self.entry.position_mut();
        let pending = position.is_some();
        events.cancel_read(key, position, id);
        if pending && let Some(event) = registry.event::<false>().held(key, id) {
            event.release();
        }
    }

    pub(in crate::conn) fn activate(&mut self) {
        self.entry.set_active(true);
    }

    /// Retains the exact occupied epoch while admitting its retirement.
    pub(in crate::conn) fn try_reclaim(mut self) -> Result<Reclaim<'map, B>, Self> {
        let stream = &self.entry.get_mut().state;
        if stream.credit.has_held(stream.delivered_to()) {
            Err(self)
        } else {
            Ok(Reclaim { slot: self })
        }
    }

    /// Keeps the generation occupied while removing it from control topology.
    /// Outstanding receive capabilities use this terminal tombstone until the
    /// final capability returns its credit.
    pub(in crate::conn::stream::state::receive) fn retain(mut self, ctrl: &mut control::Pending) {
        self.entry.get_mut().state.retire(ctrl);
        self.borrow().clear();
        self.entry.set_active(false);
    }
}

/// The exact delivered amount remains paired with its exclusively borrowed epoch.
pub(in crate::conn::stream::state::receive) struct DeliveryRead<'map, B: Recv, R> {
    pub(in crate::conn::stream::state::receive) slot: Occupied<'map, B>,
    pub(in crate::conn::stream::state::receive) value: R,
    pub(in crate::conn::stream::state::receive) free: u64,
}

impl<B: Recv, R> DeliveryRead<'_, B, R> {
    pub(in crate::conn::stream::state::receive) fn finish(
        self,
        base: varint::VarInt,
        ctrl: &mut control::Pending,
        table: &mut Table,
        events: &mut queue::Pending,
    ) -> Consumed<R> {
        let Self {
            mut slot,
            value,
            free,
        } = self;
        let id = slot.id();
        let stream = &mut slot.entry.get_mut().state;
        let limit = (free != 0)
            .then(|| stream.credit.release(base, free))
            .flatten();
        let reset = stream.reset_error().is_some();
        let done = reset || stream.is_eof();
        let credit = match limit {
            None => false,
            Some(_) if done => false,
            Some(limit) => match records::Records::new(&mut *ctrl).set_stream(
                &mut stream.max_stream_data,
                id,
                limit,
            ) {
                Ok(()) => false,
                Err(journal::Error::Vacant | journal::Error::Revision(_)) => {
                    stream.mark_credit();
                    true
                }
            },
        };
        let retire = if done {
            match slot.try_reclaim() {
                Ok(mut reclaim) => {
                    if !reset {
                        reclaim.cancel_read(events, table);
                    }
                    reclaim.remove(table, ctrl);
                    true
                }
                Err(_) => false,
            }
        } else {
            if credit {
                slot.activate();
            }
            false
        };
        Consumed {
            value,
            id,
            free,
            retire,
        }
    }
}

pub(in crate::conn) struct Reclaim<'map, B: Recv> {
    slot: Occupied<'map, B>,
}

impl<B: Recv> Reclaim<'_, B> {
    pub(in crate::conn) fn cancel_read(
        &mut self,
        events: &mut queue::Pending,
        registry: &mut Table,
    ) {
        self.slot.cancel_read(events, registry);
    }

    /// Only an epoch with no outstanding receive credit can be recycled.
    pub(in crate::conn) fn remove(self, registry: &mut Table, ctrl: &mut control::Pending) {
        let Occupied { entry, arena } = self.slot;
        let id = entry.id();
        let Some(key) = registry.read().key(id) else {
            return;
        };
        let slot = entry.handle().index();
        if registry.side::<false>().remove(key, id, slot).is_none() {
            return;
        }
        entry.retire(recycle::Recycle::new(ctrl, arena));
    }
}

pub(in crate::conn) struct Vacant<'map, B: Recv> {
    pub(super) entry:
        store::Vacant<'map, Side, recv::Entry<B>, Option<readable::Handle>, plane::HeadOnly>,
    pub(super) arena: &'map depot::raw::Arena<Node<B>, Tag>,
}

impl<'map, B: Recv> Vacant<'map, B> {
    pub(in crate::conn) fn insert(self) -> Option<Occupied<'map, B>> {
        self.entry.insert(()).map(|entry| Occupied {
            entry,
            arena: self.arena,
        })
    }
}
