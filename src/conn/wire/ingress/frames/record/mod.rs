use crate::errors::{self, detail};
use std::ops;

use crate::conn::stream::resident;
use crate::conn::stream::state::receive::input;
use crate::conn::wire::crypto::chunks;
use crate::wire::ranges::plan;
use crate::{
    conn,
    proto::recovery::pmtud,
    wire::{frame, packet::cid, stream, varint},
};
use conn::wire::ingress::frames;
use frame::{Repr, ack::ranges};
use plan::Record;

mod storage;

pub(super) use storage::{Control, Records, Vacant};
pub(in crate::conn) use storage::{Group, RecvIndex, Storage};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::conn) enum Admission {
    Drop,
    Datagram,
    Stream,
    StreamTransient,
    Reset,
    Stop,
}

#[derive(Clone, Copy, Default)]
#[repr(transparent)]
struct PayloadPlan(u64);

impl PayloadPlan {
    const fn record(self) -> Record {
        Record::from_bits(self.0 as u32)
    }

    const fn start(self) -> usize {
        (self.0 >> u32::BITS) as u16 as usize
    }

    fn set_record(&mut self, record: Record) {
        self.0 = u64::from(record.bits());
    }

    fn set_start(&mut self, start: usize) {
        self.0 = u64::from(self.0 as u32) | u64::from(start as u16) << u32::BITS;
    }
}

type Parsed<'id> = Repr<ops::Range<usize>, ranges::Proof<'id>, cid::Id>;
type View<'a, 'id> = frame::View<'a, ops::Range<usize>, ranges::Proof<'id>, cid::Id>;

/// A row's kind, immutable identity, and kind-specific admission remain together.
pub(in crate::conn) struct FrameRecord<'id> {
    id: stream::Id,
    kind: Kind<'id>,
}

enum Kind<'id> {
    Other(Parsed<'id>),
    Datagram(Datagram),
    Stream(StreamRecord),
    Reset(ResetRecord),
    Stop(StopRecord),
    Crypto(CryptoRecord<'id>),
}

pub(super) struct Datagram {
    data: ops::Range<usize>,
    length: frame::Length,
    payload: Option<PayloadPlan>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Drop,
    Stream,
    Transient,
}

struct StreamRecord {
    offset: varint::VarInt,
    data: ops::Range<usize>,
    boundary: frame::Boundary,
    length: frame::Length,
    key: Option<resident::Key>,
    payload: PayloadPlan,
    admission: Status,
}

struct ResetRecord {
    code: errors::Code,
    end: varint::VarInt,
    key: Option<resident::Key>,
    free: Option<u64>,
}

struct StopRecord {
    code: errors::Code,
    key: Option<resident::Key>,
    admitted: bool,
}

struct CryptoRecord<'id> {
    offset: varint::VarInt,
    data: ops::Range<usize>,
    step: chunks::Step<'id>,
}

/// A typed loan can change only metadata belonging to its actual wire variant.
pub(in crate::conn) enum Receive<'a> {
    Stream(Stream<'a>),
    Reset(Reset<'a>),
}

pub(in crate::conn) struct Stream<'a>(&'a mut StreamRecord);
pub(in crate::conn) struct Reset<'a>(&'a mut ResetRecord);

pub(in crate::conn) struct Stored<'a> {
    offset: varint::VarInt,
    data: &'a ops::Range<usize>,
    payload: &'a mut PayloadPlan,
}

impl Stored<'_> {
    pub(in crate::conn) fn offset(&self) -> varint::VarInt {
        self.offset
    }
    pub(in crate::conn) fn data(&self) -> &ops::Range<usize> {
        self.data
    }
    pub(in crate::conn) fn record(&self) -> Record {
        self.payload.record()
    }
    pub(in crate::conn) fn set_start(&mut self, _: frames::CommitPermit<'_>, start: usize) {
        self.payload.set_start(start);
    }
}

impl Stream<'_> {
    pub(in crate::conn) fn offset(&self) -> varint::VarInt {
        self.0.offset
    }
    pub(in crate::conn) fn len(&self) -> usize {
        self.0.data.len()
    }
    pub(in crate::conn) fn boundary(&self) -> frame::Boundary {
        self.0.boundary
    }
    pub(in crate::conn) fn admit(&mut self, key: Option<resident::Key>, added: &plan::Added) {
        self.0.key = key;
        self.0.payload.set_record(added.record());
        self.0.admission = Status::Stream;
    }
    pub(in crate::conn) fn seen(&mut self, key: Option<resident::Key>, record: Record) {
        self.0.key = key;
        self.0.payload.set_record(record);
        self.0.admission = Status::Transient;
    }
    pub(in crate::conn) fn stored_mut(&mut self) -> Option<Stored<'_>> {
        if self.0.admission != Status::Stream {
            return None;
        }
        Some(Stored {
            offset: self.0.offset,
            data: &self.0.data,
            payload: &mut self.0.payload,
        })
    }
}

impl Reset<'_> {
    pub(in crate::conn) fn final_size(&self) -> varint::VarInt {
        self.0.end
    }
    pub(in crate::conn) fn admit(&mut self, key: Option<resident::Key>, free: u64) {
        self.0.key = key;
        self.0.free = Some(free);
    }
}

impl Datagram {
    pub(super) fn len(&self) -> usize {
        self.data.len()
    }
    pub(super) fn length(&self) -> frame::Length {
        self.length
    }
    pub(super) fn admit(&mut self) -> Result<(), detail::Payload> {
        let len = self.data.len();
        let record = Record::full(len).ok_or_else(|| detail::Payload::new(len))?;
        let mut payload = PayloadPlan::default();
        payload.set_record(record);
        self.payload = Some(payload);
        Ok(())
    }
    fn stored_mut(&mut self) -> Option<Stored<'_>> {
        Some(Stored {
            offset: varint::VarInt::ZERO,
            data: &self.data,
            payload: self.payload.as_mut()?,
        })
    }
}

/// Construction consumes a decoder frame only after packet and role admission.
#[repr(transparent)]
pub(super) struct Admitted<'id>(frame::Frame<ops::Range<usize>, ranges::Proof<'id>>);

impl<'id> Admitted<'id> {
    pub(super) fn new(
        kind: frames::PacketKind,
        local: stream::Initiator,
        frame: frame::Frame<ops::Range<usize>, ranges::Proof<'id>>,
    ) -> Result<Self, conn::Error> {
        if !kind.allows(&frame, local) {
            return Err(conn::Error::ProtocolViolation);
        }
        Ok(Self(frame))
    }
    pub(super) fn frame(&self) -> &frame::Frame<ops::Range<usize>, ranges::Proof<'id>> {
        &self.0
    }
}

pub(in crate::conn) enum Operation<'record, 'id> {
    Drop(View<'record, 'id>),
    Datagram,
    Stream {
        key: Option<resident::Key>,
        id: stream::Id,
        offset: varint::VarInt,
        data: &'record ops::Range<usize>,
        plan: Record,
        boundary: frame::Boundary,
    },
    StreamTransient {
        key: Option<resident::Key>,
        id: stream::Id,
        offset: varint::VarInt,
        plan: Record,
        boundary: frame::Boundary,
    },
    Reset(input::Reset),
    Stop {
        key: Option<resident::Key>,
        id: stream::Id,
        error_code: errors::Code,
    },
}

impl<'id> FrameRecord<'id> {
    pub(super) fn new(frame: Admitted<'id>, body: &frame::Body<'_, 'id>) -> Self {
        let (id, kind) = match frame.0.into_repr() {
            Repr::Stream {
                stream_id: id,
                offset,
                boundary,
                length,
                data,
                ..
            } => (
                id,
                Kind::Stream(StreamRecord {
                    offset,
                    data,
                    boundary,
                    length,
                    key: None,
                    payload: PayloadPlan::default(),
                    admission: Status::Drop,
                }),
            ),
            Repr::ResetStream {
                stream_id: id,
                error_code: code,
                final_size: end,
            } => (
                id,
                Kind::Reset(ResetRecord {
                    code,
                    end,
                    key: None,
                    free: None,
                }),
            ),
            Repr::StopSending {
                stream_id: id,
                error_code: code,
            } => (
                id,
                Kind::Stop(StopRecord {
                    code,
                    key: None,
                    admitted: false,
                }),
            ),
            Repr::Datagram { data } => (
                stream::Id::from_varint(varint::VarInt::ZERO),
                Kind::Datagram(Datagram {
                    data,
                    length: frame::Length::Implicit,
                    payload: None,
                }),
            ),
            Repr::DatagramLen { data, .. } => (
                stream::Id::from_varint(varint::VarInt::ZERO),
                Kind::Datagram(Datagram {
                    data,
                    length: frame::Length::Explicit,
                    payload: None,
                }),
            ),
            Repr::Crypto { offset, data, .. } => (
                stream::Id::from_varint(varint::VarInt::ZERO),
                Kind::Crypto(CryptoRecord {
                    offset,
                    data,
                    step: chunks::Step::new(body),
                }),
            ),
            wire => {
                let id = match &wire {
                    Repr::MaxStreamData { stream_id: id, .. } => *id,
                    _ => stream::Id::from_varint(varint::VarInt::ZERO),
                };
                (id, Kind::Other(wire))
            }
        };
        Self { id, kind }
    }

    pub(in crate::conn) fn view(&self) -> View<'_, 'id> {
        match &self.kind {
            Kind::Other(wire) => wire.view(),
            Kind::Datagram(record) => frame::View::Datagram {
                length: record.length,
                data: &record.data,
            },
            Kind::Stream(record) => frame::View::Stream {
                stream_id: self.id,
                offset: record.offset,
                boundary: record.boundary,
                length: record.length,
                data: &record.data,
            },
            Kind::Reset(record) => frame::View::ResetStream {
                stream_id: self.id,
                error_code: record.code,
                final_size: record.end,
            },
            Kind::Stop(record) => frame::View::StopSending {
                stream_id: self.id,
                error_code: record.code,
            },
            Kind::Crypto(record) => frame::View::Crypto {
                offset: record.offset,
                data: &record.data,
            },
        }
    }

    pub(super) fn is_probing(&self) -> bool {
        let kind = match &self.kind {
            Kind::Other(wire) => wire.kind(),
            Kind::Datagram(_) => frame::Kind::Datagram,
            Kind::Stream(_) => frame::Kind::Stream,
            Kind::Reset(_) => frame::Kind::ResetStream,
            Kind::Stop(_) => frame::Kind::StopSending,
            Kind::Crypto(_) => frame::Kind::Crypto,
        };
        kind.is_probing()
    }

    pub(in crate::conn) fn admission(&self) -> Admission {
        match &self.kind {
            Kind::Datagram(record) if record.payload.is_some() => Admission::Datagram,
            Kind::Stream(record) => match record.admission {
                Status::Drop => Admission::Drop,
                Status::Stream => Admission::Stream,
                Status::Transient => Admission::StreamTransient,
            },
            Kind::Reset(record) if record.free.is_some() => Admission::Reset,
            Kind::Stop(record) if record.admitted => Admission::Stop,
            _ => Admission::Drop,
        }
    }

    pub(super) fn datagram_mut(&mut self) -> Option<&mut Datagram> {
        match &mut self.kind {
            Kind::Datagram(record) => Some(record),
            _ => None,
        }
    }

    pub(super) fn stored_dgram(&mut self) -> Option<Stored<'_>> {
        self.datagram_mut()?.stored_mut()
    }

    pub(in crate::conn) fn range(&self) -> ops::Range<usize> {
        let payload = match &self.kind {
            Kind::Datagram(record) => record.payload.unwrap_or_default(),
            Kind::Stream(record) => record.payload,
            _ => PayloadPlan::default(),
        };
        let start = payload.start();
        start..start + payload.record().bytes()
    }

    pub(in crate::conn) fn operation(&self) -> Operation<'_, 'id> {
        let id = self.id;
        match &self.kind {
            Kind::Datagram(record) if record.payload.is_some() => Operation::Datagram,
            Kind::Stream(record) => match record.admission {
                Status::Drop => Operation::Drop(self.view()),
                Status::Stream => Operation::Stream {
                    key: record.key,
                    id,
                    offset: record.offset,
                    data: &record.data,
                    plan: record.payload.record(),
                    boundary: record.boundary,
                },
                Status::Transient => Operation::StreamTransient {
                    key: record.key,
                    id,
                    offset: record.offset,
                    plan: record.payload.record(),
                    boundary: record.boundary,
                },
            },
            Kind::Reset(record) => match record.free {
                Some(free) => Operation::Reset(input::Reset {
                    key: record.key,
                    id,
                    code: record.code,
                    end: record.end.get(),
                    free,
                }),
                None => Operation::Drop(self.view()),
            },
            Kind::Stop(record) if record.admitted => Operation::Stop {
                key: record.key,
                id,
                error_code: record.code,
            },
            Kind::Datagram(_) | Kind::Stop(_) | Kind::Other(_) | Kind::Crypto(_) => {
                Operation::Drop(self.view())
            }
        }
    }

    fn receive(&mut self) -> Option<Receive<'_>> {
        match &mut self.kind {
            Kind::Stream(record) => Some(Receive::Stream(Stream(record))),
            Kind::Reset(record) => Some(Receive::Reset(Reset(record))),
            _ => None,
        }
    }
}

const _: () = assert!(pmtud::MAX_PMTU <= u16::MAX as u64);
