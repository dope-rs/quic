use o3::{
    alloc,
    base::num::bounded,
    buffer::write::{self, Sink},
};
use std::num::NonZero;

use crate::conn::output::delivery;
use crate::conn::stream::{Local, state::streams};
use crate::conn::wire::path;
use crate::errors;
use crate::wire::stream;
use crate::wire::{frame, packet::cid, varint};

use crate::conn::output::control;
use control::{
    journal::{State, storage},
    revision,
};
use path::{local, probe};

pub(in crate::conn) mod raw;

pub(in crate::conn) struct Encoder<'a> {
    path: &'a path::State,
}

#[derive(Clone, Copy)]
pub(in crate::conn) struct Selected<'a> {
    handle: revision::Key,
    probe: probe::View<'a>,
    encodable: Encodable<'a>,
    state: State,
}

#[derive(Clone, Copy)]
enum Encodable<'a> {
    HandshakeDone,
    NewConnectionId(&'a local::Announcement),
    RetireConnectionId(varint::VarInt),
    StopSending(stream::Id, errors::Code),
    ResetStream(stream::Id, errors::Code, varint::VarInt),
    MaxData(varint::VarInt),
    MaxStreamData(stream::Id, varint::VarInt),
    MaxStreams(stream::Direction, varint::VarInt),
    PathResponse(path::ControlKey),
    PathChallenge(path::ControlKey),
    DataBlocked(varint::VarInt),
    StreamDataBlocked(stream::Id, varint::VarInt),
}

enum Prepared<'a, 'e> {
    HandshakeDone(Option<(&'a [u8], varint::VarInt)>),
    NewConnectionId {
        record: &'e local::Announcement,
        cid: cid::Ref<'a>,
        token: [u8; 16],
    },
    RetireConnectionId(varint::VarInt),
    StopSending(stream::Id, errors::Code),
    ResetStream(stream::Id, errors::Code, varint::VarInt),
    MaxData(varint::VarInt),
    MaxStreamData(stream::Id, varint::VarInt),
    MaxStreams(stream::Direction, varint::VarInt),
    PathResponse([u8; 8]),
    PathChallenge([u8; 8]),
    DataBlocked(varint::VarInt),
    StreamDataBlocked(stream::Id, varint::VarInt),
}

struct Length(bounded::Usize<{ usize::MAX }>);

impl Sink for Length {
    type Error = bounded::Error;

    fn write_slice(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0 = self.0.try_add(bytes.len())?;
        Ok(())
    }

    fn write_slices<const N: usize>(&mut self, slices: [&[u8]; N]) -> Result<(), Self::Error> {
        let mut end = self.0;
        for source in slices {
            end = end.try_add(source.len())?;
        }
        self.0 = end;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(in crate::conn::output::control) enum Blocked {
    Data(varint::VarInt),
    Stream(stream::Id, varint::VarInt),
}

impl Blocked {
    pub(in crate::conn::output::control) const fn record(self) -> delivery::Control {
        match self {
            Self::Data(limit) => delivery::Control::DataBlocked(limit),
            Self::Stream(id, limit) => delivery::Control::StreamDataBlocked(id, limit),
        }
    }
}

impl<'a> Selected<'a> {
    pub(in crate::conn::output::control) fn blocked(
        handle: revision::Key,
        blocked: Blocked,
        probe: probe::View<'a>,
    ) -> Self {
        let kind = match blocked {
            Blocked::Data(limit) => Encodable::DataBlocked(limit),
            Blocked::Stream(id, limit) => Encodable::StreamDataBlocked(id, limit),
        };
        Self {
            handle,
            probe,
            encodable: kind,
            state: State::Ready,
        }
    }

    pub(in crate::conn::output::control) fn new(
        handle: revision::Key,
        entry: &'a storage::Entry,
        state: State,
        probe: probe::View<'a>,
    ) -> Self {
        let record = entry.record();
        let kind = match *record {
            delivery::Control::HandshakeDone => Encodable::HandshakeDone,
            delivery::Control::NewConnectionId(ref record) => Encodable::NewConnectionId(record),
            delivery::Control::RetireConnectionId(value) => Encodable::RetireConnectionId(value),
            delivery::Control::StopSending(id, code) => Encodable::StopSending(id, code),
            delivery::Control::ResetStream(id, code, final_) => {
                Encodable::ResetStream(id, code, final_)
            }
            delivery::Control::MaxData(value) => Encodable::MaxData(value),
            delivery::Control::MaxStreamData(id, value) => Encodable::MaxStreamData(id, value),
            delivery::Control::MaxStreams(dir, value) => {
                Encodable::MaxStreams(dir, varint::VarInt::from(value))
            }
            delivery::Control::PathResponse(key) => Encodable::PathResponse(key),
            delivery::Control::PathChallenge(key) | delivery::Control::PathValidation(key) => {
                Encodable::PathChallenge(key)
            }
            delivery::Control::DataBlocked(value) => Encodable::DataBlocked(value),
            delivery::Control::StreamDataBlocked(id, value) => {
                Encodable::StreamDataBlocked(id, value)
            }
        };
        Self {
            handle,
            probe,
            encodable: kind,
            state,
        }
    }

    pub(in crate::conn) fn path(self) -> Option<path::Key> {
        let record = match self.encodable {
            Encodable::PathResponse(key) => delivery::Control::PathResponse(key),
            Encodable::PathChallenge(key) => delivery::Control::PathChallenge(key),
            _ => return None,
        };
        self.probe.control_path(record)
    }

    pub(in crate::conn) fn allows(self, local: &Local, role: stream::Initiator) -> bool {
        match self.encodable {
            Encodable::StopSending(id, _)
            | Encodable::ResetStream(id, _, _)
            | Encodable::MaxStreamData(id, _)
            | Encodable::StreamDataBlocked(id, _) => local.allows(streams::Relative::new(id, role)),
            _ => true,
        }
    }

    pub(in crate::conn) const fn kind(self) -> frame::Kind {
        match self.encodable {
            Encodable::HandshakeDone => frame::Kind::HandshakeDone,
            Encodable::NewConnectionId(_) => frame::Kind::NewConnectionId,
            Encodable::RetireConnectionId(_) => frame::Kind::RetireConnectionId,
            Encodable::StopSending(..) => frame::Kind::StopSending,
            Encodable::ResetStream(..) => frame::Kind::ResetStream,
            Encodable::MaxData(_) => frame::Kind::MaxData,
            Encodable::MaxStreamData(..) => frame::Kind::MaxStreamData,
            Encodable::MaxStreams(..) => frame::Kind::MaxStreams,
            Encodable::PathResponse(_) => frame::Kind::PathResponse,
            Encodable::PathChallenge(_) => frame::Kind::PathChallenge,
            Encodable::DataBlocked(_) => frame::Kind::DataBlocked,
            Encodable::StreamDataBlocked(..) => frame::Kind::StreamDataBlocked,
        }
    }

    pub(in crate::conn) const fn state(self) -> State {
        self.state
    }

    pub(in crate::conn) const fn handle(self) -> revision::Key {
        self.handle
    }
}

/// One control whose path selection and complete encoding have been admitted.
/// Only the retaining packet builder may publish this affine selection.
pub(in crate::conn) struct Written {
    kind: frame::Kind,
    handle: revision::Key,
    state: State,
    sent: raw::Sent,
}

impl Written {
    pub(in crate::conn) const fn sent(&self) -> raw::Sent {
        self.sent
    }

    pub(in crate::conn) const fn kind(&self) -> frame::Kind {
        self.kind
    }

    pub(in crate::conn) const fn handle(&self) -> revision::Key {
        self.handle
    }

    pub(in crate::conn) const fn state(&self) -> State {
        self.state
    }
}

pub(in crate::conn) enum Write {
    Done(Written),
    Full,
}

impl<'a> Encoder<'a> {
    pub(in crate::conn) fn new(path: &'a path::State) -> Self {
        Self { path }
    }

    /// Counts the shared encoding; the fixed token, CID and varints bound it to 54 bytes.
    pub(in crate::conn) fn minimum(&self, selected: Selected<'_>) -> Option<NonZero<usize>> {
        let mut length = Length(bounded::Usize::ZERO);
        self.prepare(selected)?.0.encode(&mut length).ok()?;
        NonZero::new(length.0.get())
    }

    pub(in crate::conn) fn encode(
        &self,
        out: &mut write::Append<'_>,
        limit: usize,
        selected: Selected<'_>,
    ) -> Result<Option<Write>, alloc::Error> {
        let Some((prepared, sent)) = self.prepare(selected) else {
            return Ok(None);
        };
        let room = limit.saturating_sub(out.len());
        let mut out = out.append();
        prepared.encode(&mut out)?;
        Ok(Some(if out.len() <= room {
            Write::Done(Written {
                kind: selected.kind(),
                handle: selected.handle(),
                state: selected.state(),
                sent,
            })
        } else {
            out.rollback();
            Write::Full
        }))
    }

    fn prepare<'e>(&self, selected: Selected<'e>) -> Option<(Prepared<'a, 'e>, raw::Sent)> {
        let mut sent = raw::Sent::None;
        let prepared = match selected.encodable {
            Encodable::HandshakeDone => {
                let token = self.path.origin.issued();
                let token = match token {
                    Some(data) => Some((data, varint::VarInt::from_usize(data.len())?)),
                    None => None,
                };
                Prepared::HandshakeDone(token)
            }
            Encodable::NewConnectionId(record) => {
                let (found, cid, token) = self.path.local.identity(record.key())?;
                sent = raw::Sent::Local(record.key().slot_index());
                (record.sequence() == found && !cid.is_empty())
                    .then_some(Prepared::NewConnectionId { record, cid, token })?
            }
            Encodable::RetireConnectionId(value) => Prepared::RetireConnectionId(value),
            Encodable::StopSending(id, code) => Prepared::StopSending(id, code),
            Encodable::ResetStream(id, code, value) => Prepared::ResetStream(id, code, value),
            Encodable::MaxData(value) => Prepared::MaxData(value),
            Encodable::MaxStreamData(id, value) => Prepared::MaxStreamData(id, value),
            Encodable::MaxStreams(dir, value) => Prepared::MaxStreams(dir, value),
            Encodable::PathResponse(key) => {
                let probe = selected.probe.response(key)?;
                sent = raw::Sent::Response(probe.position);
                Prepared::PathResponse(probe.data)
            }
            Encodable::PathChallenge(key) => {
                let probe = selected.probe.challenge(key)?;
                sent = raw::Sent::Challenge(probe.position);
                Prepared::PathChallenge(probe.data)
            }
            Encodable::DataBlocked(value) => Prepared::DataBlocked(value),
            Encodable::StreamDataBlocked(id, value) => Prepared::StreamDataBlocked(id, value),
        };
        Some((prepared, sent))
    }
}

impl Prepared<'_, '_> {
    fn encode<S: Sink>(self, out: &mut S) -> Result<(), S::Error> {
        match self {
            Prepared::HandshakeDone(None) => out.write_byte(frame::TYPE_HANDSHAKE_DONE),
            Prepared::HandshakeDone(Some((token, len))) => out.write_slices([
                &[frame::TYPE_HANDSHAKE_DONE, frame::TYPE_NEW_TOKEN],
                len.pack().as_ref(),
                token,
            ]),
            Prepared::NewConnectionId { record, cid, token } => out.write_slices([
                &[frame::TYPE_NEW_CONNECTION_ID],
                record.sequence().pack().as_ref(),
                record.retire().pack().as_ref(),
                &[cid.length().get()],
                cid.into_slice(),
                &token,
            ]),
            Prepared::RetireConnectionId(seq) => {
                out.write_slices([&[frame::TYPE_RETIRE_CONNECTION_ID], seq.pack().as_ref()])
            }
            Prepared::StopSending(id, code) => out.write_slices([
                &[frame::TYPE_STOP_SENDING],
                id.varint().pack().as_ref(),
                code.as_varint().pack().as_ref(),
            ]),
            Prepared::ResetStream(id, code, final_) => out.write_slices([
                &[frame::TYPE_RESET_STREAM],
                id.varint().pack().as_ref(),
                code.as_varint().pack().as_ref(),
                final_.pack().as_ref(),
            ]),
            Prepared::MaxData(max) => {
                out.write_slices([&[frame::TYPE_MAX_DATA], max.pack().as_ref()])
            }
            Prepared::MaxStreamData(id, max) => out.write_slices([
                &[frame::TYPE_MAX_STREAM_DATA],
                id.varint().pack().as_ref(),
                max.pack().as_ref(),
            ]),
            Prepared::MaxStreams(dir, max) => out.write_slices([
                &[match dir {
                    stream::Direction::Bidi => frame::TYPE_MAX_STREAMS_BIDI,
                    stream::Direction::Uni => frame::TYPE_MAX_STREAMS_UNI,
                }],
                max.pack().as_ref(),
            ]),
            Prepared::PathResponse(data) => out.write_slices([&[frame::TYPE_PATH_RESPONSE], &data]),
            Prepared::PathChallenge(data) => {
                out.write_slices([&[frame::TYPE_PATH_CHALLENGE], &data])
            }
            Prepared::DataBlocked(value) => {
                out.write_slices([&[frame::TYPE_DATA_BLOCKED], value.pack().as_ref()])
            }
            Prepared::StreamDataBlocked(id, value) => out.write_slices([
                &[frame::TYPE_STREAM_DATA_BLOCKED],
                id.varint().pack().as_ref(),
                value.pack().as_ref(),
            ]),
        }
    }
}

const _: () = {
    assert!(std::mem::size_of::<Selected<'static>>() == 56);
    assert!(std::mem::size_of::<Option<Selected<'static>>>() == 56);
    assert!(std::mem::size_of::<Encoder<'static>>() == std::mem::size_of::<usize>());
};

const _: () = assert!(std::mem::size_of::<Written>() == 24);
