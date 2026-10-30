use crate::conn::machine::storage::capacity;
use crate::conn::output::delivery;
use crate::conn::stream::{Local, state::transmit::queue};
use crate::conn::wire::path::probe;
use crate::errors;
use crate::wire::stream;
use o3::depot::capacity::{Count, Reason};

mod blocked;
pub(in crate::conn) use blocked::Blocked;

pub(in crate::conn) mod encode;
pub(in crate::conn) mod journal;
pub(in crate::conn) mod kind;
pub(in crate::conn) mod owner;
pub(in crate::conn) mod revision;

pub(in crate::conn::output::control) enum Tag {}

use crate::conn::output::control::journal::{cursor, records, storage};

const HANDSHAKE_DONE: u16 = 1 << 0;
const NEW_CONNECTION_ID: u16 = 1 << 1;
const RETIRE_CONNECTION_ID: u16 = 1 << 2;
const STOP_SENDING: u16 = 1 << 3;
const RESET_STREAM: u16 = 1 << 4;
const MAX_DATA: u16 = 1 << 5;
const MAX_STREAM_DATA: u16 = 1 << 6;
const MAX_STREAMS_BIDI: u16 = 1 << 7;
const MAX_STREAMS_UNI: u16 = 1 << 8;
const PATH_RESPONSE: u16 = 1 << 9;
const PATH_CHALLENGE: u16 = 1 << 10;
const LANE_COUNT: usize = 11;

pub(in crate::conn) const PREFIX: u16 = HANDSHAKE_DONE | NEW_CONNECTION_ID | RETIRE_CONNECTION_ID;
pub(in crate::conn) const SUFFIX: u16 = STOP_SENDING
    | RESET_STREAM
    | MAX_DATA
    | MAX_STREAM_DATA
    | MAX_STREAMS_BIDI
    | MAX_STREAMS_UNI
    | PATH_RESPONSE
    | PATH_CHALLENGE;

pub(in crate::conn) enum Effect {
    None,
    RetireStream(stream::Id),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::conn) struct Admission {
    pub(in crate::conn::output) records: Count,
    pub(in crate::conn::output) reason: Reason,
}

/// Bounded owner for control values, delivery generations, and queue links.
/// Typed owner keys resolve in one slot access; a borrowing cursor prevents
/// selected records from outliving or racing generation mutation.
pub(in crate::conn) struct Pending {
    storage: storage::Set,
    handshake_done: Option<owner::Key<kind::Handshake>>,
    probe: probe::State,
}

/// Read-only send capability tied to the pending-control owner.
/// It adds no storage or allocation: cursors retain the original owner borrow.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(in crate::conn) struct Ready<'pending> {
    pending: &'pending Pending,
}

impl Pending {
    pub(in crate::conn) fn new(limit: capacity::Capacity<capacity::Control>) -> Self {
        Self {
            storage: storage::Set::new(limit),
            handshake_done: None,
            probe: probe::State::new(),
        }
    }

    pub(in crate::conn) fn available(&self) -> Count {
        self.storage.available()
    }

    pub(in crate::conn) fn probe(&self) -> probe::View<'_> {
        self.probe.view()
    }

    pub(in crate::conn) fn queue(&mut self) -> probe::Queue<'_> {
        self.probe.queue(&mut self.storage)
    }

    pub(in crate::conn) fn challenges(&mut self) -> probe::Challenges<'_> {
        self.probe.challenges(&mut self.storage)
    }

    pub(in crate::conn) fn replies(&mut self) -> probe::Replies<'_> {
        self.probe.replies(&mut self.storage)
    }

    pub(in crate::conn) fn done_slots(&self) -> Count {
        Count::new(u32::from(
            !records::Records::new(self).contains(self.handshake_done),
        ))
    }

    pub(in crate::conn) fn try_done(&mut self) -> Result<(), Admission> {
        if let Some(owner) = self.handshake_done
            && self.storage.owner(owner).is_some()
        {
            return Ok(());
        }
        let slot = self.storage.try_insert(delivery::Control::HandshakeDone)?;
        self.handshake_done = Some(slot.owner());
        Ok(())
    }

    pub(in crate::conn) fn ready(&self) -> Ready<'_> {
        Ready { pending: self }
    }

    pub(in crate::conn) fn remove<Kind>(&mut self, owner: &mut Option<owner::Key<Kind>>) {
        self.storage.remove(owner);
    }

    pub(in crate::conn) fn clear<Kind>(&mut self, signal: &mut owner::Signal<Kind>) {
        let mut owner = signal.owner();
        self.remove(&mut owner);
        signal.clear();
    }

    pub(in crate::conn) fn reset(
        &mut self,
        signal: &mut owner::Signal<kind::ResetStream>,
        error: errors::Code,
    ) {
        let mut owner = signal.owner();
        self.remove(&mut owner);
        signal.defer(error);
    }

    pub(in crate::conn) fn stop(
        &mut self,
        signal: &mut owner::Signal<kind::StopSending>,
        error: errors::Code,
    ) {
        let mut owner = signal.owner();
        self.remove(&mut owner);
        signal.defer(error);
    }

    pub(in crate::conn) fn ack(&mut self, handle: revision::Key) -> Effect {
        let Some(record) = records::Records::new(&mut *self).complete(handle) else {
            return Effect::None;
        };
        match record {
            delivery::Control::DataBlocked(_) | delivery::Control::StreamDataBlocked(_, _) => {
                Effect::None
            }
            delivery::Control::ResetStream(stream, _, _) => Effect::RetireStream(stream),
            delivery::Control::RetireConnectionId(serial) => {
                self.probe.ack_retire(serial);
                Effect::None
            }
            _ => Effect::None,
        }
    }

    pub(in crate::conn) fn lose(&mut self, handle: revision::Key) {
        if let Some(slot) = self.storage.revision(handle) {
            slot.lose();
        }
    }
}

impl<'pending> Ready<'pending> {
    pub(in crate::conn) fn can_probe(self) -> bool {
        self.pending.probe().has_work() && self.pending.available().raw() != 0
    }

    pub(in crate::conn) fn bytes(self) -> usize {
        self.pending.storage.bytes()
    }

    pub(in crate::conn) fn is_queued<K>(self, owner: Option<owner::Key<K>>) -> bool {
        records::Records::new(self.pending)
            .entry(owner)
            .is_some_and(|entry| matches!(entry.status, storage::Status::Queued))
    }

    pub(in crate::conn) fn has_blocked<K>(self, credit: &queue::Credit<K>) -> bool {
        match credit.blocked {
            None => self.pending.available().raw() != 0,
            Some(owner) => self.is_queued(Some(owner)),
        }
    }

    pub(in crate::conn) fn is_empty(self) -> bool {
        self.pending.storage.topology().lanes.bits() == 0
    }

    pub(in crate::conn) fn responses(self) -> Option<cursor::Cursor<'pending, PATH_RESPONSE>> {
        cursor::Cursor::<PATH_RESPONSE>::new(self.pending)
    }

    pub(in crate::conn) fn challenges(self) -> Option<cursor::Cursor<'pending, PATH_CHALLENGE>> {
        cursor::Cursor::<PATH_CHALLENGE>::new(self.pending)
    }

    pub(in crate::conn) fn response(self) -> Option<cursor::Cursor<'pending, PATH_RESPONSE>> {
        if self.pending.storage.topology().lanes.bits() != PATH_RESPONSE {
            return None;
        }
        cursor::Cursor::<PATH_RESPONSE>::new(self.pending)
    }

    pub(in crate::conn) fn challenge(self) -> Option<cursor::Cursor<'pending, PATH_CHALLENGE>> {
        if self.pending.storage.topology().lanes.bits() != PATH_CHALLENGE {
            return None;
        }
        cursor::Cursor::<PATH_CHALLENGE>::new(self.pending)
    }

    pub(in crate::conn) fn prefix(self) -> Option<cursor::Cursor<'pending, PREFIX>> {
        cursor::Cursor::<PREFIX>::new(self.pending)
    }

    pub(in crate::conn) fn suffix(self) -> Option<cursor::Cursor<'pending, SUFFIX>> {
        cursor::Cursor::<SUFFIX>::new(self.pending)
    }

    pub(in crate::conn) fn has_sendable(self, local: &Local, role: stream::Initiator) -> bool {
        let bits = self.pending.storage.topology().lanes.ready_bits() & (PREFIX | SUFFIX);
        if bits == 0 {
            return false;
        }
        if local.all_allowed() || bits & !(STOP_SENDING | RESET_STREAM | MAX_STREAM_DATA) != 0 {
            return true;
        }
        self.suffix()
            .is_some_and(|mut records| records.any(|selected| selected.allows(local, role)))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Lane {
    Done,
    NewCid,
    RetireCid,
    Stop,
    Reset,
    MaxData,
    MaxStreamData,
    MaxBidi,
    MaxUni,
    Response,
    Challenge,
}

impl Lane {
    const fn bind<T>(self, values: &[T; LANE_COUNT]) -> &T {
        match self {
            Self::Done => &values[0],
            Self::NewCid => &values[1],
            Self::RetireCid => &values[2],
            Self::Stop => &values[3],
            Self::Reset => &values[4],
            Self::MaxData => &values[5],
            Self::MaxStreamData => &values[6],
            Self::MaxBidi => &values[7],
            Self::MaxUni => &values[8],
            Self::Response => &values[9],
            Self::Challenge => &values[10],
        }
    }

    fn bind_mut<T>(self, values: &mut [T; LANE_COUNT]) -> &mut T {
        match self {
            Self::Done => &mut values[0],
            Self::NewCid => &mut values[1],
            Self::RetireCid => &mut values[2],
            Self::Stop => &mut values[3],
            Self::Reset => &mut values[4],
            Self::MaxData => &mut values[5],
            Self::MaxStreamData => &mut values[6],
            Self::MaxBidi => &mut values[7],
            Self::MaxUni => &mut values[8],
            Self::Response => &mut values[9],
            Self::Challenge => &mut values[10],
        }
    }

    const fn bit(self) -> u16 {
        1 << self as u8
    }

    fn from_bit(bit: u16) -> Option<Self> {
        Some(match bit {
            1 => Self::Done,
            2 => Self::NewCid,
            4 => Self::RetireCid,
            8 => Self::Stop,
            16 => Self::Reset,
            32 => Self::MaxData,
            64 => Self::MaxStreamData,
            128 => Self::MaxBidi,
            256 => Self::MaxUni,
            512 => Self::Response,
            1024 => Self::Challenge,
            _ => return None,
        })
    }
}

fn kind(record: delivery::Control) -> Option<Lane> {
    Some(match record {
        delivery::Control::HandshakeDone => Lane::Done,
        delivery::Control::NewConnectionId(_) => Lane::NewCid,
        delivery::Control::RetireConnectionId(_) => Lane::RetireCid,
        delivery::Control::StopSending(_, _) => Lane::Stop,
        delivery::Control::ResetStream(_, _, _) => Lane::Reset,
        delivery::Control::MaxData(_) => Lane::MaxData,
        delivery::Control::MaxStreamData(_, _) => Lane::MaxStreamData,
        delivery::Control::MaxStreams(stream::Direction::Bidi, _) => Lane::MaxBidi,
        delivery::Control::MaxStreams(stream::Direction::Uni, _) => Lane::MaxUni,
        delivery::Control::PathResponse(_) => Lane::Response,
        delivery::Control::PathChallenge(_) | delivery::Control::PathValidation(_) => {
            Lane::Challenge
        }
        delivery::Control::DataBlocked(_) | delivery::Control::StreamDataBlocked(_, _) => {
            return None;
        }
    })
}

const _: () = assert!(std::mem::size_of::<Pending>() == 512);
const _: () = assert!(std::mem::size_of::<Option<owner::Key<kind::MaxData>>>() == 8);
const _: () = assert!(std::mem::size_of::<owner::Signal<kind::ResetStream>>() == 8);
const _: () = assert!(std::mem::size_of::<Ready<'static>>() == std::mem::size_of::<&Pending>());
