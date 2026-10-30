use crate::errors::detail;
use o3::mem::slice::Ext as _;
use o3::{
    alloc,
    depot::{array::init, capacity},
};
use std::{mem, ops};

use crate::conn;
use crate::conn::stream::resident;
use crate::conn::wire::crypto::chunks;
use crate::wire::{
    frame::{self, Repr},
    stream,
};

use crate::conn::wire::ingress::frames::record::{
    Admission, FrameRecord, Kind, Operation, Receive, Stored,
};

type Rows<'a, 'slots, 'id> =
    init::Prefix<'a, 'slots, FrameRecord<'id>, { conn::MAX_FRAMES_PER_PACKET }>;
type Indices<'a, 'scope, I> = init::Prefix<'a, 'scope, I, { conn::MAX_FRAMES_PER_PACKET }>;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub(in crate::conn) struct RecvIndex<'slots>(capacity::Key<'slots, u8>);

impl RecvIndex<'_> {
    pub(in crate::conn) fn get(self) -> usize {
        *self.0.as_inner() as usize
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct SendIndex<'slots>(capacity::Key<'slots, u8>);

/// These backing arrays contain no live packet values outside their scopes.
pub(in crate::conn) struct Storage {
    frames: Box<[mem::MaybeUninit<FrameRecord<'static>>; conn::MAX_FRAMES_PER_PACKET]>,
    receives: [mem::MaybeUninit<RecvIndex<'static>>; conn::MAX_FRAMES_PER_PACKET],
    sends: [mem::MaybeUninit<SendIndex<'static>>; conn::MAX_FRAMES_PER_PACKET],
}

pub(in super::super) struct Records<'a, 'f, 'slots, 'id, 'r, 'recv, 's, 'send> {
    frames: &'a mut Rows<'f, 'slots, 'id>,
    receives: &'a mut Indices<'r, 'recv, RecvIndex<'slots>>,
    sends: &'a mut Indices<'s, 'send, SendIndex<'slots>>,
}

pub(in super::super) struct Vacant<'a, 'f, 'slots, 'id, 'r, 'recv, 's, 'send> {
    frame: init::Slot<'a, 'f, 'slots, FrameRecord<'id>, { conn::MAX_FRAMES_PER_PACKET }>,
    receives: &'a mut Indices<'r, 'recv, RecvIndex<'slots>>,
    sends: &'a mut Indices<'s, 'send, SendIndex<'slots>>,
}

impl Storage {
    pub(in crate::conn) fn try_new() -> Result<Self, alloc::Error> {
        use o3::alloc::BoxArrayExt as _;
        Ok(Self {
            frames: Box::try_uninit()?,
            receives: [const { mem::MaybeUninit::uninit() }; conn::MAX_FRAMES_PER_PACKET],
            sends: [const { mem::MaybeUninit::uninit() }; conn::MAX_FRAMES_PER_PACKET],
        })
    }

    pub(in super::super) fn with<'id, R>(
        &mut self,
        run: impl for<'slots, 'recv, 'send> FnOnce(
            Records<'_, '_, 'slots, 'id, '_, 'recv, '_, 'send>,
        ) -> R,
    ) -> R {
        init::Prefix::<FrameRecord<'id>, { conn::MAX_FRAMES_PER_PACKET }>::with(
            &mut self.frames,
            |frames| {
                init::Prefix::<RecvIndex<'_>, { conn::MAX_FRAMES_PER_PACKET }>::with(
                    &mut self.receives,
                    |receives| {
                        init::Prefix::<SendIndex<'_>, { conn::MAX_FRAMES_PER_PACKET }>::with(
                            &mut self.sends,
                            |sends| {
                                run(Records {
                                    frames,
                                    receives,
                                    sends,
                                })
                            },
                        )
                    },
                )
            },
        )
    }
}

impl<'id> Vacant<'_, '_, '_, 'id, '_, '_, '_, '_> {
    pub(in super::super) fn insert(
        self,
        record: FrameRecord<'id>,
        app: bool,
    ) -> Result<(), detail::Plan> {
        let receive = app && matches!(record.kind, Kind::Stream(_) | Kind::Reset(_));
        let send = app
            && matches!(
                record.kind,
                Kind::Stop(_) | Kind::Other(Repr::MaxStreamData { .. })
            );
        let key = self.frame.insert(record);
        if receive {
            self.receives
                .vacancy()
                .ok_or(detail::Plan::Capacity {
                    slot: detail::Slot::Receive,
                    needed: conn::MAX_FRAMES_PER_PACKET + 1,
                    available: conn::MAX_FRAMES_PER_PACKET,
                })?
                .insert(RecvIndex(key));
        }
        if send {
            self.sends
                .vacancy()
                .ok_or(detail::Plan::Capacity {
                    slot: detail::Slot::Send,
                    needed: conn::MAX_FRAMES_PER_PACKET + 1,
                    available: conn::MAX_FRAMES_PER_PACKET,
                })?
                .insert(SendIndex(key));
        }
        Ok(())
    }
}

pub(in crate::conn) struct Group<'a, 'f, 'slots, 'id> {
    id: stream::Id,
    indices: &'a [RecvIndex<'slots>],
    frames: &'a mut Rows<'f, 'slots, 'id>,
}

impl<'a, 'f, 'slots, 'id> Group<'a, 'f, 'slots, 'id> {
    pub(in crate::conn) fn id(&self) -> stream::Id {
        self.id
    }
    pub(in crate::conn) fn records(&self) -> impl Iterator<Item = &FrameRecord<'id>> {
        self.indices.iter().map(|index| self.frames.get(index.0))
    }
    pub(in crate::conn) fn try_for_each<T, E>(
        &mut self,
        mut visit: impl FnMut(RecvIndex<'slots>, Option<Receive<'_>>) -> Result<ops::ControlFlow<T>, E>,
    ) -> Result<ops::ControlFlow<T>, E> {
        for &index in self.indices {
            if let ops::ControlFlow::Break(value) =
                visit(index, self.frames.get_mut(index.0).receive())?
            {
                return Ok(ops::ControlFlow::Break(value));
            }
        }
        Ok(ops::ControlFlow::Continue(()))
    }
}

pub(in super::super) struct SendGroup<'a, 'f, 'slots, 'id, 'r> {
    id: stream::Id,
    indices: &'a [SendIndex<'slots>],
    frames: &'a mut Rows<'f, 'slots, 'id>,
    receives: &'a mut &'r [RecvIndex<'slots>],
}

impl<'id> SendGroup<'_, '_, '_, 'id, '_> {
    pub(in super::super) fn id(&self) -> stream::Id {
        self.id
    }
    pub(in super::super) fn has_stop(&self) -> bool {
        self.indices
            .iter()
            .any(|index| matches!(self.frames.get(index.0).kind, Kind::Stop(_)))
    }
    pub(in super::super) fn admit_stops(&mut self, key: Option<resident::Key>) {
        for index in self.indices {
            if let Kind::Stop(record) = &mut self.frames.get_mut(index.0).kind {
                record.key = key;
                record.admitted = true;
            }
        }
    }
    pub(in super::super) fn receive(&mut self) -> Option<&FrameRecord<'id>> {
        while let Some((index, rest)) = self.receives.split_first() {
            if self.frames.get(index.0).id.get() >= self.id.get() {
                break;
            }
            *self.receives = rest;
        }
        self.receives
            .iter()
            .map(|index| self.frames.get(index.0))
            .take_while(|record| record.id == self.id)
            .find(|record| {
                matches!(
                    record.admission(),
                    Admission::Stream | Admission::StreamTransient,
                )
            })
    }
}

impl<'a, 'f, 'slots, 'id, 'r, 'recv, 's, 'send> Records<'a, 'f, 'slots, 'id, 'r, 'recv, 's, 'send> {
    pub(in crate::conn::wire::ingress::frames) fn sort(&mut self) {
        // SAFETY: both keys read immutable row identities through the same
        // retained frame prefix. Sorting cannot mutate those identities.
        unsafe {
            sort(self.receives, |index| self.frames.get(index.0).id.get());
            sort(self.sends, |index| self.frames.get(index.0).id.get());
        }
    }

    pub(in super::super) fn vacancy(
        &mut self,
    ) -> Option<Vacant<'_, 'f, 'slots, 'id, 'r, 'recv, 's, 'send>> {
        Some(Vacant {
            frame: self.frames.vacancy()?,
            receives: self.receives,
            sends: self.sends,
        })
    }
    pub(in super::super) fn as_slice(&self) -> &[FrameRecord<'id>] {
        self.frames.as_slice()
    }
    pub(in super::super) fn get(&self, index: RecvIndex<'slots>) -> &FrameRecord<'id> {
        self.frames.get(index.0)
    }
    pub(in super::super) fn order(&self) -> &[RecvIndex<'slots>] {
        self.receives.as_slice()
    }
    pub(in super::super) fn receive_id(&self, index: RecvIndex<'slots>) -> stream::Id {
        self.frames.get(index.0).id
    }
    pub(in super::super) fn source(&self) -> &Indices<'r, 'recv, RecvIndex<'slots>> {
        self.receives
    }

    pub(in super::super) fn try_receives<E>(
        &mut self,
        mut apply: impl FnMut(Group<'_, 'f, 'slots, 'id>) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut order = self.receives.as_slice();
        while let Some(first) = order.first() {
            let id = self.frames.get(first.0).id;
            let (indices, rest) = order.split_while(|index| self.frames.get(index.0).id == id);
            apply(Group {
                id,
                indices,
                frames: self.frames,
            })?;
            order = rest;
        }
        Ok(())
    }

    pub(in super::super) fn try_sends<E>(
        &mut self,
        mut apply: impl FnMut(SendGroup<'_, 'f, 'slots, 'id, '_>) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut order = self.sends.as_slice();
        let mut receives = self.receives.as_slice();
        while let Some(first) = order.first() {
            let id = self.frames.get(first.0).id;
            let (indices, rest) = order.split_while(|index| self.frames.get(index.0).id == id);
            apply(SendGroup {
                id,
                indices,
                frames: self.frames,
                receives: &mut receives,
            })?;
            order = rest;
        }
        Ok(())
    }

    pub(in super::super) fn try_datagram<E>(
        &mut self,
        mut apply: impl FnMut(Stored<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        for record in self.frames.as_mut_slice() {
            if let Some(stored) = record.stored_dgram() {
                apply(stored)?;
            }
        }
        Ok(())
    }

    pub(in super::super) fn try_crypto<'crypto>(
        &mut self,
        spaces: &'crypto mut chunks::Spaces,
        epoch: conn::Epoch,
        body: &frame::Body<'_, 'id>,
        scratch: &mut chunks::Scratch,
    ) -> Result<chunks::Prepared<'crypto, 'id>, chunks::Failure> {
        spaces.prepare(
            epoch,
            self.frames
                .as_mut_slice()
                .iter_mut()
                .filter_map(|record| match &mut record.kind {
                    Kind::Crypto(record) => {
                        Some((record.offset.get(), record.data.clone(), &mut record.step))
                    }
                    _ => None,
                }),
            body,
            scratch,
        )
    }

    pub(in super::super) fn controls(&mut self) -> impl Iterator<Item = Control<'_, 'id>> {
        self.frames
            .as_mut_slice()
            .iter_mut()
            .map(|record| match record {
                FrameRecord {
                    kind: Kind::Crypto(record),
                    ..
                } => Control::Crypto(record.step.borrow()),
                record => Control::Frame(record.operation()),
            })
    }
}

pub(in super::super) enum Control<'a, 'id> {
    Crypto(chunks::Access<'a, 'id>),
    Frame(Operation<'a, 'id>),
}

/// # Safety
/// The key must return the same value for each index throughout this sort.
unsafe fn sort<I: Copy>(indices: &mut Indices<'_, '_, I>, key: impl Fn(I) -> u64) {
    let extent = indices.extent();
    let values = indices.as_mut_slice();
    let [first, _, ..] = &*values else {
        return;
    };
    let first = *first;
    if values.is_sorted_by_key(|value| key(*value)) {
        return;
    }
    let mut scratch = [first; conn::MAX_FRAMES_PER_PACKET];
    let scratch = extent.prefix_mut(&mut scratch);
    let spread = |source: &[I], target: &mut [I], shift: u32| {
        let mut slots = [0_u16; 256];
        for &value in source {
            let bucket = ((key(value) >> shift) & 0xff) as usize;
            slots[bucket] += 1;
        }
        let mut start = 0_u16;
        for slot in &mut slots {
            let count = *slot;
            *slot = start;
            start += count;
        }
        for &value in source {
            let bucket = ((key(value) >> shift) & 0xff) as usize;
            let slot = slots[bucket] as usize;
            // SAFETY: both passes use the same immutable keys. Prefix sums
            // partition exactly source.len() destinations, and this bucket
            // advances once per counted source member. Both slices retain
            // the same admitted extent, at most MAX_FRAMES_PER_PACKET.
            *unsafe { target.get_unchecked_mut(slot) } = value;
            slots[bucket] += 1;
        }
    };
    for pass in 0..8 {
        let shift = pass * 8;
        if pass & 1 == 0 {
            spread(values, scratch, shift);
        } else {
            spread(scratch, values, shift);
        }
    }
}

const _: () = assert!(mem::size_of::<RecvIndex<'_>>() == 1);
const _: () = assert!(mem::size_of::<SendIndex<'_>>() == 1);
const _: () = assert!(conn::MAX_FRAMES_PER_PACKET <= u8::MAX as usize + 1);
