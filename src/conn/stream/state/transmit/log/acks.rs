use o3::buffer;

use crate::conn::machine::storage;
use crate::conn::output::{control, delivery};
use crate::conn::stream::state::transmit::{self, log, queue};
use crate::conn::stream::{event::queue::Pending, state::resident::Table};
use crate::stream::{outbound, release, send};
use crate::wire::stream::Id;
use crate::wire::varint::VarInt;
use links::storage::Account;
use links::topology::{Active, Record};
use log::links;
use queue::{Occupied, recycle::Recycle};

/// An acknowledged stream head retaining its journal and byte owner together.
/// Out-of-order ACKs do not produce this capability and remain charged to
/// journal capacity until their preceding records are acknowledged.
#[must_use]
pub(in crate::conn::stream) struct Ack<'a, 'map, D: buffer::raw::Segment> {
    record: Record<'a, (), (), Active>,
    sender: queue::Occupied<'map, D>,
}

pub(crate) struct Acknowledged {
    bytes: usize,
    last: outbound::Range,
}

pub(in crate::conn::stream::state::transmit) struct Retired<'map, D: buffer::raw::Segment> {
    sender: queue::Occupied<'map, D>,
}

impl<'map, D: buffer::raw::Segment> Retired<'map, D> {
    pub(in crate::conn::stream::state::transmit) fn into_inner(self) -> queue::Occupied<'map, D> {
        self.sender
    }
}

impl Acknowledged {
    pub(crate) fn len(&self) -> usize {
        self.bytes
    }

    pub(crate) fn end(&self) -> VarInt {
        self.last.end_offset()
    }

    pub(crate) fn boundary(&self) -> send::Boundary {
        self.last.boundary()
    }
}

impl<D: buffer::raw::Segment> Ack<'_, '_, D> {
    pub(in crate::conn::stream) fn acknowledge<E: release::Sink, C>(
        state: &mut transmit::State<D>,
        handle: delivery::Handle<delivery::Stream>,
        registry: &mut Table,
        control: &mut control::Pending,
        events: &mut Pending,
        evidence: &mut E,
        prepare: impl FnOnce(Id) -> Option<C>,
    ) -> Option<(Id, C)> {
        let record = Record::bind(&mut state.deliveries, handle)?.acknowledge()?;
        let Some(sender) = state.map.occupied(record.group.get().owner) else {
            record.cancel();
            return None;
        };
        let (id, acked, sender) =
            queue::Occupied::ack::<E>(Ack { record, sender }, events, evidence);
        let done = match acked {
            outbound::Acked::Live(()) => None,
            outbound::Acked::Closed(()) => Some(Retired { sender }),
        };
        let retired = done?;
        let close = prepare(id)?;
        let (key, _) = registry.read().find::<true>(id)?;
        let recycle = Recycle::new(control, &mut state.deliveries);
        match Occupied::retire(retired, key, registry, recycle) {
            queue::Removal::Absent => None,
            queue::Removal::Removed => Some((id, close)),
        }
    }

    pub(in crate::conn::stream) fn retire_reset<C>(
        state: &mut transmit::State<D>,
        id: Id,
        registry: &mut Table,
        control: &mut control::Pending,
        prepare: impl FnOnce(Id) -> Option<C>,
    ) -> Result<Option<(Id, C)>, crate::conn::Error> {
        let Some(close) = prepare(id) else {
            return Ok(None);
        };
        let Some((key, sender)) = state.map.bind(id, registry) else {
            return Ok(None);
        };
        if !sender.state().is_reset() {
            return Err(crate::conn::Error::Internal);
        }
        let retired = Retired { sender };
        let recycle = Recycle::new(control, &mut state.deliveries);
        Ok(match Occupied::retire(retired, key, registry, recycle) {
            queue::Removal::Absent => None,
            queue::Removal::Removed => Some((id, close)),
        })
    }
}

impl<'a, 'map, D: buffer::raw::Segment> Ack<'a, 'map, D> {
    /// Retains the original byte owner while detaching its ordered acknowledged prefix.
    pub(in crate::conn::stream::state::transmit) fn into_parts(
        self,
    ) -> (queue::Occupied<'map, D>, Acknowledged) {
        let Self { record, sender } = self;
        let first = record.node.get().record;
        let mut bytes = first.range.len_usize();
        let mut last = first.range;
        let mut next = record.next(Account::Active);
        while let Some(record) = next {
            let key = storage::Key::new(record.node.key());
            let node = record.node.get();
            if !node.is_acked(key) {
                break;
            }
            let value = node.record;
            bytes += value.range.len_usize();
            last = value.range;
            next = record.next(Account::Active);
        }
        (sender, Acknowledged { bytes, last })
    }
}
