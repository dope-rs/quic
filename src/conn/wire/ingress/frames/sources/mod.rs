use crate::errors::detail;
use std::{marker, mem, num::NonZero, ops};

use o3::buffer::{self, write};
use o3::depot::array::init;

use crate::wire::stream::Id;
use crate::wire::{frame, ranges::plan, varint};
use crate::{conn, stream};
use conn::stream::{resident, state::receive};
use conn::wire::{crypto::chunks, ingress, scratch};
use ingress::frames;
use receive::{planner, recv::Pending};

use frames::record;

mod backing;
mod raw;

pub(in crate::conn::wire::ingress) use backing::{Copied, Retained};

pub(in crate::conn::wire::ingress) struct Payload<'body> {
    wire: ops::Range<usize>,
    compact: ops::Range<usize>,
    bytes: &'body [u8],
}

pub(in crate::conn::wire::ingress) trait Backing<B: stream::Recv> {
    fn datagram(&self, payload: Payload<'_>) -> Result<B, detail::Backing>;
    fn stream<'body>(
        &self,
        payload: Payload<'body>,
    ) -> Result<stream::Payload<'body, B>, detail::Backing>;
}

pub(in crate::conn::wire::ingress) trait Source<B: stream::Recv>:
    Sized
{
    type Backing: Backing<B>;

    fn prepare<F>(self, bytes: usize, fill: F) -> Result<Self::Backing, detail::Preparation>
    where
        F: FnOnce(&mut write::Spare<'_>) -> Result<(), detail::Copying>;
}

/// Owns the exact admitted rows and the cursor prepared from those rows.
pub(super) struct Preparation<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send, 'crypto> {
    records: record::Records<'a, 'f, 'slots, 'id, 'r, 'recv, 's, 'send>,
    body: frame::Body<'wire, 'id>,
    crypto: chunks::Prepared<'crypto, 'id>,
}

pub(in crate::conn::wire::ingress) struct Prepared<
    'a,
    'wire,
    'f,
    'slots,
    'id,
    'r,
    'recv,
    's,
    'send,
    'crypto,
    B: stream::Recv,
    S: Backing<B>,
> {
    backing: S,
    input: Preparation<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send, 'crypto>,
    buffer: marker::PhantomData<fn() -> B>,
}

/// Terminal operations retain the packet owner after its consuming control pass.
pub(super) struct Applied<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send, 'crypto, S> {
    _backing: S,
    input: Preparation<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send, 'crypto>,
}

pub(super) enum Control<'row, 'wire, 'id> {
    Crypto(Crypto<'row, 'wire, 'id>),
    Frame(record::Operation<'row, 'id>),
}

/// An actual row loan coupled to the cursor which prepared it.
pub(in crate::conn::wire) struct Crypto<'row, 'wire, 'id> {
    cursor: chunks::Cursor<'row>,
    step: chunks::Access<'row, 'id>,
    body: frame::Body<'wire, 'id>,
}

impl<'row, 'wire, 'id> Crypto<'row, 'wire, 'id> {
    pub(in crate::conn::wire) fn into_parts(
        self,
    ) -> (
        chunks::Cursor<'row>,
        chunks::Access<'row, 'id>,
        frame::Body<'wire, 'id>,
    ) {
        (self.cursor, self.step, self.body)
    }
}

pub(in crate::conn::wire::ingress) struct Entry<'a, 'body, 'id, B: stream::Recv, S: Backing<B>> {
    backing: &'a S,
    record: &'a record::FrameRecord<'id>,
    body: frame::Body<'body, 'id>,
    buffer: marker::PhantomData<fn() -> B>,
}

pub(in crate::conn::wire::ingress) struct Stream<'a, 'body, B: stream::Recv, S: Backing<B>> {
    backing: &'a S,
    payload: Payload<'body>,
    key: Option<resident::Key>,
    offset: varint::VarInt,
    plan: plan::Record,
    boundary: frame::Boundary,
    buffer: marker::PhantomData<fn() -> B>,
}

impl<'body, B: stream::Recv, S: Backing<B>> Stream<'_, 'body, B, S> {
    pub(super) const fn key(&self) -> Option<resident::Key> {
        self.key
    }

    pub(super) fn take(self) -> Result<Pending<'body, B>, detail::Backing> {
        let data = self.backing.stream(self.payload)?;
        Ok(Pending::new(self.offset, self.plan, data, self.boundary))
    }
}

impl<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send, 'crypto>
    Preparation<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send, 'crypto>
{
    pub(super) fn try_new(
        mut records: record::Records<'a, 'f, 'slots, 'id, 'r, 'recv, 's, 'send>,
        body: frame::Body<'wire, 'id>,
        spaces: &'crypto mut chunks::Spaces,
        epoch: conn::Epoch,
        scratch: &mut chunks::Scratch,
    ) -> Result<Self, chunks::Failure> {
        let crypto = records.try_crypto(spaces, epoch, &body, scratch)?;
        Ok(Self {
            records,
            body,
            crypto,
        })
    }

    pub(super) fn body(&self) -> frame::Body<'wire, 'id> {
        self.body
    }

    pub(super) fn frames(&self) -> &[record::FrameRecord<'id>] {
        self.records.as_slice()
    }

    pub(super) fn prepare<B: stream::Recv, D: buffer::raw::Segment, S: Source<B>>(
        mut self,
        source: S,
        bytes: usize,
        work: &mut scratch::Buffers,
        state: &receive::Update<'_, B, D>,
        token: frames::CommitPermit<'_>,
    ) -> Result<
        Prepared<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send, 'crypto, B, S::Backing>,
        detail::Preparation,
    > {
        use o3::buffer::write::Sink as _;
        let body = self.body;
        let records = &mut self.records;
        let backing = source.prepare(bytes, |output| {
            records.try_datagram(|mut payload| {
                let bytes = body.resolve(payload.data().clone())?;
                payload.set_start(token, output.len());
                output.write_slice(bytes)?;
                Ok::<_, detail::Copying>(())
            })?;
            records.try_receives(|group| {
                planner::Planner::new(state).commit(
                    group,
                    planner::Commit::new(&mut work.segments, &mut work.parts, body, output, token),
                )
            })?;
            Ok(())
        })?;
        Ok(Prepared {
            backing,
            input: self,
            buffer: marker::PhantomData,
        })
    }
}

impl<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send, 'crypto, B: stream::Recv, S: Backing<B>>
    Prepared<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send, 'crypto, B, S>
{
    pub(super) fn entries(
        &self,
    ) -> impl ExactSizeIterator<Item = Entry<'_, 'wire, 'id, B, S>> + Clone {
        self.input
            .records
            .as_slice()
            .iter()
            .map(move |record| Entry {
                backing: &self.backing,
                record,
                body: self.input.body,
                buffer: marker::PhantomData,
            })
    }

    pub(super) fn entry(&self, index: record::RecvIndex<'slots>) -> Entry<'_, 'wire, 'id, B, S> {
        Entry {
            backing: &self.backing,
            record: self.input.records.get(index),
            body: self.input.body,
            buffer: marker::PhantomData,
        }
    }

    pub(super) fn id(&self, index: record::RecvIndex<'slots>) -> Id {
        self.input.records.receive_id(index)
    }

    pub(super) fn frames(&self) -> &[record::FrameRecord<'id>] {
        self.input.records.as_slice()
    }

    pub(super) fn order(&self) -> &[record::RecvIndex<'slots>] {
        self.input.records.order()
    }

    pub(super) fn source(
        &self,
    ) -> &init::Prefix<'r, 'recv, record::RecvIndex<'slots>, { conn::MAX_FRAMES_PER_PACKET }> {
        self.input.records.source()
    }

    pub(super) fn try_datagram(&self) -> Result<Vec<B>, detail::Unavailable> {
        let entries = self
            .entries()
            .filter(|entry| entry.record.admission() == record::Admission::Datagram);
        let Some(count) = NonZero::new(entries.clone().count()) else {
            return Ok(Vec::new());
        };
        // SAFETY: this exact immutable filter and its retained rows establish the count.
        unsafe { raw::try_datagram(count, entries.map(|entry| entry.datagram())) }
    }

    pub(super) fn controls(
        mut self,
        mut run: impl for<'row> FnMut(
            Control<'row, 'wire, 'id>,
        ) -> Result<frames::Disposition, conn::Error>,
    ) -> (
        Applied<'a, 'wire, 'f, 'slots, 'id, 'r, 'recv, 's, 'send, 'crypto, S>,
        Result<frames::Disposition, conn::Error>,
    ) {
        let body = self.input.body;
        let crypto = &mut self.input.crypto;
        let mut result = Ok(frames::Disposition::Commit);
        for control in self.input.records.controls() {
            let control = match control {
                record::Control::Crypto(step) => Control::Crypto(Crypto {
                    cursor: crypto.borrow(),
                    step,
                    body,
                }),
                record::Control::Frame(op) => Control::Frame(op),
            };
            result = run(control);
            if !matches!(result, Ok(frames::Disposition::Commit)) {
                break;
            }
        }
        (
            Applied {
                _backing: self.backing,
                input: self.input,
            },
            result,
        )
    }
}

impl<'id, S> Applied<'_, '_, '_, '_, 'id, '_, '_, '_, '_, '_, S> {
    pub(super) fn operations(&self) -> impl Iterator<Item = record::Operation<'_, 'id>> {
        self.input
            .records
            .as_slice()
            .iter()
            .map(record::FrameRecord::operation)
    }
}

impl<'a, 'body, 'id, B: stream::Recv, S: Backing<B>> Entry<'a, 'body, 'id, B, S> {
    pub(in crate::conn::wire::ingress) fn datagram(&self) -> Result<B, detail::Backing> {
        let frame::View::Datagram { data, .. } = self.record.view() else {
            return Err(detail::Backing::Body(frame::Projection));
        };
        self.backing
            .datagram(Payload::try_new(self.record, self.body, data.clone())?)
    }

    pub(super) fn try_stream(self) -> Result<Option<Stream<'a, 'body, B, S>>, detail::Backing> {
        let record::Operation::Stream {
            key,
            offset,
            data,
            plan,
            boundary,
            ..
        } = self.record.operation()
        else {
            return Ok(None);
        };
        let payload = Payload::try_new(self.record, self.body, data.clone())?;
        Ok(Some(Stream {
            backing: self.backing,
            payload,
            key,
            offset,
            plan,
            boundary,
            buffer: marker::PhantomData,
        }))
    }
}

impl<'body> Payload<'body> {
    fn try_new<'id>(
        record: &record::FrameRecord<'id>,
        body: frame::Body<'body, 'id>,
        wire: ops::Range<usize>,
    ) -> Result<Self, detail::Backing> {
        let bytes = body.resolve(wire.clone()).map_err(detail::Backing::Body)?;
        Ok(Self {
            wire,
            compact: record.range(),
            bytes,
        })
    }
}

const _: () = assert!(
    mem::size_of::<
        Prepared<
            'static,
            'static,
            'static,
            'static,
            'static,
            'static,
            'static,
            'static,
            'static,
            'static,
            Vec<u8>,
            Copied<Vec<u8>>,
        >,
    >() == mem::size_of::<
        Preparation<
            'static,
            'static,
            'static,
            'static,
            'static,
            'static,
            'static,
            'static,
            'static,
            'static,
        >,
    >()
);
const _: () = assert!(mem::size_of::<detail::Projection>() == 4 * mem::size_of::<usize>());
