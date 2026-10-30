use crate::conn::stream::state::transmit::{
    State,
    log::journal::{self, Entry},
};
use pending::{Input, Preparation};

use self::app::{early, rtt};
use crate::conn::output::transmit::permit::{self, fit};
use crate::stream::outbound;
use crate::wire::stream::{Id, Initiator};
use outbound::chunk;

use o3::depot::{array, queue::pool};
use o3::{
    alloc,
    buffer::{self, write},
};
use write::Sink as _;

use std::{mem, num, time};

pub(in crate::conn) mod ack;
pub(super) mod app;
pub(in crate::conn) mod crypto;
pub(in crate::conn::output::transmit) mod pending;

use crate::{
    conn::{
        self,
        output::{
            control::{
                self, encode,
                journal::{cursor, probes},
            },
            transmit::{
                self,
                packet::{plan::Plan, seals},
            },
        },
        wire::{crypto::tx, path},
    },
    proto::recovery::numbers,
    stream,
    wire::{
        frame,
        packet::{self, header, header::widths, kind},
        varint,
    },
};

/// Bounded packet records retained once for the enclosing emission scope.
pub(in crate::conn::output::transmit) struct Records {
    controls: array::Vec<encode::Written, { conn::PACKET_CONTROL_CAPACITY }>,
    streams: array::Vec<Entry, { conn::PACKET_STREAM_CAPACITY }>,
    crypto: Option<tx::Commit>,
}

impl Records {
    pub(in crate::conn::output::transmit) const fn new() -> Self {
        Self {
            controls: array::Vec::new(),
            streams: array::Vec::new(),
            crypto: None,
        }
    }
}

pub(in crate::conn) struct Builder<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    connection: &'a mut conn::Machine<DOMAIN, B, D>,
    destination: &'a transmit::Policy,
    controls: &'a mut array::Vec<encode::Written, { conn::PACKET_CONTROL_CAPACITY }>,
    streams: &'a mut array::Vec<Entry, { conn::PACKET_STREAM_CAPACITY }>,
    crypto: &'a mut Option<tx::Commit>,
}

enum Selection {
    Empty,
    Ready,
}

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Builder<'a, DOMAIN, B, D> {
    pub(in crate::conn::output::transmit) fn new(
        conn: &'a mut conn::Machine<DOMAIN, B, D>,
        target: &'a transmit::Policy,
        records: &'a mut Records,
    ) -> Self {
        records.controls = array::Vec::new();
        records.streams = array::Vec::new();
        records.crypto = None;
        Self {
            connection: conn,
            destination: target,
            controls: &mut records.controls,
            streams: &mut records.streams,
            crypto: &mut records.crypto,
        }
    }

    fn target(&self, route: path::OutputRoute) -> Option<transmit::Destination> {
        Self::target_for(self.connection, self.destination, route)
    }

    fn target_for(
        conn: &conn::Machine<DOMAIN, B, D>,
        policy: &transmit::Policy,
        route: path::OutputRoute,
    ) -> Option<transmit::Destination> {
        conn.path
            .output()
            .target(route)
            .and_then(|routed| policy.resolve(routed))
    }

    fn limit<K: kind::Long + numbers::AckSpace>(&self, max: usize, pn_len: u8) -> usize {
        Self::limit_for::<K>(&self.connection.path, max, pn_len)
    }

    pub(in crate::conn::output::transmit) fn limit_for<K: kind::Long + numbers::AckSpace>(
        path: &path::State,
        max: usize,
        pn_len: u8,
    ) -> usize {
        let peer = path.peer.id().len();
        let local = path.local.cid().len();
        if K::TYPE == packet::LONG_INITIAL {
            Self::initial_for(peer, local, path.origin.initial().len(), max, pn_len)
        } else {
            let fixed = 1 + 4 + 1 + peer + 1 + local + usize::from(pn_len);
            Self::long_limit::<K>(fixed, max, pn_len)
        }
    }

    fn long_limit<K: kind::Long>(fixed: usize, max: usize, pn_len: u8) -> usize {
        let minimum = K::MIN_LENGTH_WIDTH.into_usize();
        let mut payload = max.saturating_sub(fixed + conn::TAG_LEN + minimum);
        loop {
            let length = usize::from(pn_len) + payload + conn::TAG_LEN;
            let width = varint::VarInt::width(length).max(minimum);
            let next = max.saturating_sub(fixed + conn::TAG_LEN + width);
            if next >= payload {
                return payload;
            }
            payload = next;
        }
    }

    pub(in crate::conn) fn initial_for(
        peer: usize,
        local: usize,
        token: usize,
        max: usize,
        pn_len: u8,
    ) -> usize {
        let fixed = 1
            + 4
            + 1
            + peer
            + 1
            + local
            + varint::VarInt::width(token)
            + token
            + usize::from(pn_len);
        Self::long_limit::<kind::Initial>(fixed, max, pn_len)
    }

    fn short_limit(
        &self,
        max: usize,
        encoding: widths::Encoding,
        route: path::OutputRoute,
    ) -> usize {
        Self::short_for(&self.connection.path, max, encoding, route)
    }

    pub(in crate::conn::output::transmit) fn short_for(
        path: &path::State,
        max: usize,
        encoding: widths::Encoding,
        route: path::OutputRoute,
    ) -> usize {
        let width = widths::Width::from_pn(encoding);
        let limit =
            max.saturating_sub(1 + path.output().cid(route).len() + width.get() + conn::TAG_LEN);
        if limit < header::Payload::new(1, width).get() {
            0
        } else {
            limit
        }
    }

    pub(in crate::conn::output::transmit) fn select<'pending, const MASK: u16>(
        conn: &conn::Machine<DOMAIN, B, D>,
        records: &mut cursor::Cursor<'pending, MASK>,
        route: path::OutputRoute,
    ) -> Option<encode::Selected<'pending>> {
        records.find(|selected| {
            selected.allows(&conn.streams.local_initiated, conn.streams.local())
                && selected.path() == route.path()
        })
    }

    fn put_stream(
        out: &mut write::Append<'_>,
        limit: usize,
        id: Id,
        stream: &outbound::Sender,
        chunks: pool::View<'_, chunk::Node<D>>,
        range: outbound::Range,
    ) -> Result<Option<num::NonZero<u16>>, alloc::Error> {
        stream
            .write(out, limit, id, chunks, range)
            .map(|written| written.map(|written| written.wire_len()))
    }

    fn can_track(&self) -> bool {
        permit::Permit::new(self.connection).can_track()
    }

    fn put<N, const MASK: u16>(
        &mut self,
        select: impl for<'b> FnOnce(control::Ready<'b>) -> Option<cursor::Cursor<'b, MASK>>,
        out: &mut write::Append<'_>,
        limit: usize,
        commit: &mut Plan<N>,
    ) -> Result<Selection, transmit::Admission> {
        let Some(mut records) = select(self.connection.control.ready()) else {
            return Ok(Selection::Empty);
        };
        let mut result = Selection::Empty;
        while let Some(vacant) = self.controls.vacancy() {
            let Some(selected) = Self::select(self.connection, &mut records, commit.path.route)
            else {
                break;
            };
            result = Selection::Ready;
            let Some(encode::Write::Done(written)) = encode::Encoder::new(&self.connection.path)
                .encode(out, limit, selected)
                .map_err(|error| transmit::Admission::Payload {
                    error,
                    requested: limit,
                })?
            else {
                break;
            };
            vacant.insert(written);
            commit.flags.set_elicit(true);
        }
        Ok(result)
    }

    fn probe<N>(
        &mut self,
        frames: &mut write::Append<'_>,
        limit: usize,
        commit: &mut Plan<N>,
    ) -> Result<(), transmit::Admission> {
        while let Some(vacant) = self.controls.vacancy() {
            let next = probes::Probes::new(&self.connection.control).next(
                conn::Epoch::Application,
                |selected| {
                    !selected.allows(
                        &self.connection.streams.local_initiated,
                        self.connection.streams.local(),
                    ) || vacant
                        .as_slice()
                        .iter()
                        .any(|entry| entry.handle() == selected.handle())
                },
            );
            let Some(selected) = next else {
                break;
            };
            let Some(encode::Write::Done(written)) = encode::Encoder::new(&self.connection.path)
                .encode(frames, limit, selected)
                .map_err(|error| transmit::Admission::Payload {
                    error,
                    requested: limit,
                })?
            else {
                break;
            };
            vacant.insert(written);
            commit.flags.set_elicit(true);
        }
        Ok(())
    }

    pub(super) fn build_probe(
        self,
        now: time::Instant,
        dst: &mut write::Append<'_>,
        max: usize,
    ) -> transmit::Built<'a, DOMAIN, B, D> {
        let Some(epoch) = self.connection.egress.recovery.probe.epoch else {
            return Ok(None);
        };
        match epoch {
            conn::Epoch::Initial => self.build_crypto::<kind::Initial, true, false>(now, dst, max),
            conn::Epoch::Handshake => {
                self.build_crypto::<kind::Handshake, true, false>(now, dst, max)
            }
            conn::Epoch::Application if self.connection.handshake.keys.has_write() => {
                rtt::build::<true, false, DOMAIN, B, D>(self, now, dst, max, None, false)
            }
            conn::Epoch::Application => early::build(self, dst, max, true),
        }
    }

    pub(super) fn build_crypto<K, const PTO_PROBE: bool, const ACK_ONLY: bool>(
        self,
        now: time::Instant,
        dst: &mut write::Append<'_>,
        max: usize,
    ) -> transmit::Built<'a, DOMAIN, B, D>
    where
        K: seals::LongKind<DOMAIN> + numbers::AckSpace,
    {
        let epoch = <K as numbers::AckSpace>::EPOCH;
        let Some((number, limit, elicits)) =
            fit::crypto::<K, DOMAIN, B, D>(&permit::Permit::new(self.connection), max)
        else {
            return Ok(None);
        };
        if PTO_PROBE && (!elicits || ACK_ONLY) {
            return Ok(None);
        }
        let pn = number.full();
        let limit = limit.get();

        let mut frames = mem::take(&mut self.connection.scratch.frames);
        frames.clear();
        let ack = ack::append::<K, ACK_ONLY>(
            &self.connection.receive.packet_numbers,
            now,
            &mut frames,
            if PTO_PROBE { limit - 1 } else { limit },
        )
        .inspect_err(|_| self.connection.scratch.frames = mem::take(&mut frames))
        .map_err(transmit::Admission::into_error)?;
        let room = limit.saturating_sub(frames.len());
        if PTO_PROBE {
            crypto::append::<true>(
                &self.connection.handshake.crypto,
                self.crypto,
                epoch,
                room,
                &mut frames,
            )
            .inspect_err(|_| {
                self.connection.scratch.frames = mem::take(&mut frames);
            })?;
            if self.crypto.is_none() {
                frames.write_byte(frame::TYPE_PING).map_err(|error| {
                    self.connection.scratch.frames = mem::take(&mut frames);
                    transmit::Admission::Payload {
                        error,
                        requested: 1,
                    }
                })?;
            }
        } else if !ACK_ONLY
            && elicits
            && self
                .connection
                .egress
                .recovery
                .packet_journals
                .space(epoch)
                .has_room_for(pn, 2)
        {
            crypto::append::<false>(
                &self.connection.handshake.crypto,
                self.crypto,
                epoch,
                room,
                &mut frames,
            )
            .inspect_err(|_| {
                self.connection.scratch.frames = mem::take(&mut frames);
            })?;
        }

        if !PTO_PROBE && frames.is_empty() {
            self.connection.scratch.frames = frames;
            return Ok(None);
        }

        let elicit = PTO_PROBE || self.crypto.is_some();
        let padded = K::TYPE == packet::LONG_INITIAL
            && (matches!(self.connection.peer.local, Initiator::Client) || elicit)
            && frames.len() < limit;
        if padded {
            let needed = limit - frames.len();
            write::Append::new(&mut frames)
                .try_fill(needed, 0)
                .map_err(|error| {
                    self.connection.scratch.frames = mem::take(&mut frames);
                    transmit::Admission::Payload {
                        error,
                        requested: needed,
                    }
                })?;
        }
        let mut commit = Plan::new(epoch, number);
        commit.flags.set_elicit(elicit);
        commit.flags.set_flight(elicit || padded);
        commit.flags.ack = ack;
        commit.flags.set_probe(PTO_PROBE);
        let Some(target) = self.target(commit.path.route) else {
            frames.clear();
            self.connection.scratch.frames = frames;
            return Ok(None);
        };
        let prepared =
            match pending::Packet::try_new(journal::Schedule::new(self).finish(), commit, target) {
                Ok(prepared) => prepared,
                Err((scratch, error)) => {
                    frames.clear();
                    scratch.frames = frames;
                    return Err(error.into_error());
                }
            };
        let ((), mut prepared) = match seals::long::<DOMAIN, B, D, K>(dst, &frames, prepared) {
            Ok(output) => output,
            Err(mut failure) => {
                let scratch = failure.scratch();
                frames.clear();
                scratch.frames = frames;
                return failure.into_error().map_or(Ok(None), Err);
            }
        };
        frames.clear();
        prepared.scratch().frames = frames;
        Ok(Some(prepared))
    }
}

// SAFETY: the builder retains the original connection and its two private
// selection lists. Only this schedule can append Fresh records. Its context
// excludes the transmit state and stream selections, and finish moves the same
// owner and both lists without exposing a new selection phase.
unsafe impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> journal::raw::Schedule
    for Builder<'a, DOMAIN, B, D>
{
    type Send = D;
    type Output = Input<'a, DOMAIN, B, D>;
    type Context<'b>
        = Preparation<'b>
    where
        Self: 'b;

    fn parts(
        &mut self,
    ) -> (
        &mut State<D>,
        &mut array::Vec<journal::Entry, { conn::PACKET_STREAM_CAPACITY }>,
        Self::Context<'_>,
    ) {
        let conn = &mut *self.connection;
        (
            &mut conn.streams.state.transmit,
            self.streams,
            Preparation {
                controls: self.controls,
                control: &mut conn.control,
                path: &conn.path,
                scratch: &mut conn.scratch,
            },
        )
    }

    fn finish(self) -> Self::Output {
        let Builder {
            connection: conn,
            controls,
            streams,
            crypto,
            ..
        } = self;
        Input {
            connection: conn,
            controls,
            streams,
            crypto,
        }
    }
}

const _: () = assert!(mem::size_of::<encode::Written>() == 24);
