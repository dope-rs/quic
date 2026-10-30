//! Bounded stream event admission and delivery.
use o3::{alloc, base::num::bounded};

use o3::depot::queue::{indexed::slab, links};
use slab::phase;
use std::mem;

use crate::conn::stream::state::resident::events;
use crate::conn::stream::{Event, resident};
use crate::wire::stream::Id;

pub(in crate::conn) enum Domain {}

mod plan;
pub(in crate::conn) mod readable;
pub(in crate::conn) use plan::Plan;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::conn) enum Record {
    Writable,
    Readable {
        id: Id,
        index: readable::Handle,
    },
    Reset {
        id: Id,
        error_code: crate::errors::Code,
    },
    Stopped {
        id: Id,
        error_code: crate::errors::Code,
    },
}

impl Record {
    pub(in crate::conn) fn bind(self) -> Event {
        match self {
            Self::Writable => Event::Writable,
            Self::Readable { id, .. } => Event::Readable { id },
            Self::Reset {
                id,
                error_code: code,
            } => Event::Reset {
                id,
                error_code: code,
            },
            Self::Stopped {
                id,
                error_code: code,
            } => Event::Stopped {
                id,
                error_code: code,
            },
        }
    }
}

/// Bounded FIFO whose stream owner retains typed pending state.
/// Delivery validates generation, owner, and physical queue position.
pub(in crate::conn) struct Pending {
    pending: slab::Slab<Popped, Domain, { u32::MAX }, links::Hook, 0, Plan>,
    leased: Option<readable::Handle>,
    writable: bounded::U32<0, 1>,
    leased_writable: bool,
    canceled: bool,
    /// Only selecting a real event advances this connection's fair turn.
    writable_first: bool,
    datagram_retry: bool,
}

/// Proof that a commit may append at most `remaining` event nodes.
pub(in crate::conn) struct Permit<'events> {
    events: &'events mut Pending,
    remaining: usize,
}

pub(in crate::conn) enum Push {
    Applied,
    Rollback,
}

impl Permit<'_> {
    pub(in crate::conn) fn events(&mut self) -> &mut Pending {
        self.events
    }

    fn take(
        &mut self,
    ) -> Option<slab::Vacant<'_, Popped, Domain, { u32::MAX }, links::Hook, 0, Plan, phase::Vacant>>
    {
        let left = self.remaining.checked_sub(1)?;
        let slot = self.events.pending.vacant()?;
        self.remaining = left;
        Some(slot)
    }

    pub(in crate::conn) fn push_read(
        &mut self,
        hold: events::Hold,
        key: resident::Key,
        position: &mut Option<readable::Handle>,
        id: Id,
    ) -> Push {
        match hold {
            events::Hold::Pending if position.is_some() => return Push::Applied,
            events::Hold::Pending | events::Hold::Added if position.is_some() => {
                return Push::Rollback;
            }
            events::Hold::Pending => return Push::Rollback,
            events::Hold::Added => {}
        }
        let Some(vacant) = self.take() else {
            return Push::Rollback;
        };
        let occupied = vacant.insert_with(|index| Popped::Readable {
            key,
            id,
            index: readable::Handle(index),
        });
        *position = Some(readable::Handle(occupied.key()));
        Push::Applied
    }

    pub(in crate::conn) fn push_stopped(
        &mut self,
        hold: events::Hold,
        key: resident::Key,
        id: Id,
        code: crate::errors::Code,
    ) -> Push {
        match hold {
            events::Hold::Pending => return Push::Applied,
            events::Hold::Added => {}
        };
        let Some(vacant) = self.take() else {
            return Push::Rollback;
        };
        vacant.fill(Popped::Stopped {
            key,
            id,
            error_code: code,
        });
        Push::Applied
    }

    pub(in crate::conn) fn push_reset(
        &mut self,
        hold: events::Hold,
        key: resident::Key,
        readable: &mut Option<readable::Handle>,
        id: Id,
        code: crate::errors::Code,
    ) -> Push {
        let event = Popped::Reset {
            key: Some(key),
            id,
            error_code: code,
        };
        if let Some(index) = *readable {
            if self.events.leased == Some(index) {
                return Push::Applied;
            }
            let Some(mut queued) = self.events.pending.entry(index.0) else {
                return Push::Applied;
            };
            if !Pending::is_readable(queued.as_ref(), key, id) {
                return Push::Applied;
            }
            *queued.as_mut() = event;
            queued.push_back();
            *readable = None;
            return Push::Applied;
        }
        if !matches!(hold, events::Hold::Added) {
            return Push::Rollback;
        }
        let Some(vacant) = self.take() else {
            return Push::Rollback;
        };
        vacant.fill(event);
        Push::Applied
    }

    pub(in crate::conn) fn reset_orphan(&mut self, id: Id, code: crate::errors::Code) {
        let Some(vacant) = self.take() else {
            return;
        };
        vacant.fill(Popped::Reset {
            key: None,
            id,
            error_code: code,
        });
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::conn) enum Popped {
    Writable,
    Readable {
        key: resident::Key,
        id: Id,
        index: readable::Handle,
    },
    Reset {
        key: Option<resident::Key>,
        id: Id,
        error_code: crate::errors::Code,
    },
    Stopped {
        key: resident::Key,
        id: Id,
        error_code: crate::errors::Code,
    },
}

pub(in crate::conn) struct Lease {
    popped: Popped,
    index: Option<readable::Handle>,
}

impl Lease {
    pub(in crate::conn) const fn event(&self) -> Record {
        self.popped.event()
    }

    pub(in crate::conn) fn stream_key(&self) -> Option<resident::Key> {
        self.popped.stream_key()
    }
}

impl Popped {
    pub(in crate::conn) const fn event(self) -> Record {
        match self {
            Self::Writable => Record::Writable,
            Self::Readable { id, index, .. } => Record::Readable { id, index },
            Self::Reset {
                id,
                error_code: code,
                ..
            } => Record::Reset {
                id,
                error_code: code,
            },
            Self::Stopped {
                id,
                error_code: code,
                ..
            } => Record::Stopped {
                id,
                error_code: code,
            },
        }
    }

    pub(in crate::conn) const fn stream_key(self) -> Option<resident::Key> {
        match self {
            Self::Writable | Self::Reset { key: None, .. } => None,
            Self::Readable { key, .. }
            | Self::Reset { key: Some(key), .. }
            | Self::Stopped { key, .. } => Some(key),
        }
    }
}

impl Pending {
    pub(in crate::conn) fn try_new(capacity: Plan) -> Result<Self, alloc::Error> {
        Ok(Self {
            pending: slab::Slab::try_from(capacity)?,
            leased: None,
            writable: bounded::U32::exact::<0>(),
            leased_writable: false,
            canceled: false,
            writable_first: false,
            datagram_retry: false,
        })
    }

    pub(in crate::conn) fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.writable.get() == 0
    }

    pub(in crate::conn) fn set_writable(&mut self) {
        self.writable = bounded::U32::exact::<1>();
    }

    pub(in crate::conn) fn has_retry(&self) -> bool {
        self.datagram_retry
    }

    pub(in crate::conn) fn arm_retry(&mut self) {
        self.datagram_retry = true;
    }

    pub(in crate::conn) fn clear_retry(&mut self) {
        self.datagram_retry = false;
    }

    pub(in crate::conn) fn available(&self) -> usize {
        self.pending.available()
    }

    pub(in crate::conn) fn reserve(&mut self, count: usize) -> Option<Permit<'_>> {
        (count <= self.available()).then_some(Permit {
            events: self,
            remaining: count,
        })
    }

    pub(in crate::conn) fn cancel_read(
        &mut self,
        key: resident::Key,
        position: &mut Option<readable::Handle>,
        id: Id,
    ) {
        let Some(index) = position.take() else {
            return;
        };
        let Some(queued) = self.pending.entry(index.0) else {
            return;
        };
        if !Self::is_readable(queued.as_ref(), key, id) {
            return;
        }
        if self.leased == Some(index) {
            self.canceled = true;
        } else {
            queued.remove();
        }
    }

    pub(in crate::conn) fn pop(&mut self) -> Option<Popped> {
        if self.leased.is_some() || self.leased_writable {
            return None;
        }
        if let Some(popped) = self.pending.pop_front() {
            return Some(popped);
        }
        if mem::replace(&mut self.writable, bounded::U32::exact::<0>()).get() != 0 {
            return Some(Popped::Writable);
        }
        None
    }

    pub(in crate::conn) fn poll_mux(&mut self) -> Option<Lease> {
        if self.leased.is_some() || self.leased_writable {
            return None;
        }
        if !(self.writable_first && self.writable.get() != 0)
            && let Some((index, queued)) = self.pending.front_pair()
        {
            let handle = readable::Handle(index);
            let lease = Lease {
                popped: *queued,
                index: Some(handle),
            };
            self.leased = Some(handle);
            self.writable_first = true;
            return Some(lease);
        }
        let lease = (self.writable.get() != 0).then_some(Lease {
            popped: Popped::Writable,
            index: None,
        });
        self.leased_writable = lease.is_some();
        if self.leased_writable {
            self.writable_first = false;
        }
        lease
    }

    fn is_readable(queued: &Popped, key: resident::Key, id: Id) -> bool {
        matches!(*queued, Popped::Readable { key: owner, id: queued, .. } if owner == key && queued == id)
    }

    pub(in crate::conn) fn finish(&mut self, lease: Lease, accept: bool) -> Option<Popped> {
        let Some(index) = lease.index else {
            if !self.leased_writable
                || self.leased.is_some()
                || self.canceled
                || lease.popped != Popped::Writable
                || self.writable.get() == 0
            {
                return None;
            }
            self.leased_writable = false;
            if accept {
                self.writable = bounded::U32::exact::<0>();
                return Some(lease.popped);
            }
            return None;
        };
        if self.leased != Some(index) || self.leased_writable {
            return None;
        }
        let entry = self.pending.entry(index.0)?;
        let queued = entry.as_ref();
        if *queued != lease.popped {
            return None;
        }
        self.leased = None;
        let canceled = mem::take(&mut self.canceled);
        if !accept && !canceled {
            return None;
        }
        entry.remove();
        if canceled {
            return None;
        }
        Some(lease.popped)
    }
}

const _: () = {
    assert!(
        mem::size_of::<Option<resident::Key>>() == mem::size_of::<u64>()
            && mem::size_of::<Plan>() == mem::size_of::<u32>()
            && mem::size_of::<Option<Plan>>() == mem::size_of::<Plan>()
            && mem::size_of::<slab::Slab<Popped, Domain, { u32::MAX }, links::Hook, 0, Plan>>()
                == mem::size_of::<slab::Slab<Popped, Domain>>()
            && mem::size_of::<Record>() == 24
            && mem::size_of::<Popped>() == 32
            && mem::size_of::<Lease>() == 40
            && mem::size_of::<readable::Handle>() == 8
            && mem::size_of::<Option<readable::Handle>>() == 8
            && mem::size_of::<Pending>() == 48
            && mem::size_of::<Permit<'static>>() == 16
    );
};
