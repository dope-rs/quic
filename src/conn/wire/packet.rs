use o3::buffer::{storage, write};
use std::{mem, num};

use dope::core::io::datagram;
use o3::alloc::{self, VecExt as _};

use crate::conn::wire::permits;
use crate::conn::wire::permits::Reservation as _;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::conn) enum Allocation {
    Segments {
        error: alloc::Error,
        requested: usize,
    },
    Packets {
        error: alloc::Error,
        requested: usize,
    },
    Payload {
        error: alloc::Error,
        requested: usize,
    },
}

pub(in crate::conn) trait Sink {
    type Reservation<'sink>: permits::Reservation
    where
        Self: 'sink;

    /// A segmented UDP flight requires every datagram except possibly the
    /// last to have one wire width. The packet builder can satisfy that
    /// invariant with authenticated QUIC PADDING before protection.
    const PAD_TO_CEILING: bool = false;

    fn reserve(&mut self, limit: usize) -> Result<Option<Self::Reservation<'_>>, Allocation>;

    /// Publishes metadata only after byte validation and state commit succeed.
    fn try_emit<'a, C, T, U, E>(
        &mut self,
        context: &'a mut C,
        limit: usize,
        build: impl FnOnce(&'a mut C, &mut write::Append<'_>, usize) -> Result<Option<T>, E>,
        commit: impl FnOnce(T) -> U,
    ) -> Result<Option<U>, E>
    where
        E: From<Allocation>,
    {
        let Some(mut permit) = self.reserve(limit).map_err(E::from)? else {
            return Ok(None);
        };
        let limit = permit.limit();
        let built = {
            let mut out = permit.out();
            build(context, &mut out, limit)
        };
        let built = match built {
            Ok(built) => built,
            Err(error) => {
                permit.rollback();
                return Err(error);
            }
        };
        let Some(state) = built else {
            permit.rollback();
            return Ok(None);
        };
        let ready = match permit.validate() {
            Ok(ready) => ready,
            Err(permit) => {
                permit.rollback();
                return Ok(None);
            }
        };
        Ok(Some(
            <Self::Reservation<'_> as permits::Reservation>::publish(ready, state, commit),
        ))
    }
}

pub(crate) trait Fresh {
    fn prepare(&mut self);
}

#[derive(Default)]
pub struct Batch {
    pub(crate) buf: Vec<u8>,
    pub(crate) segs: Vec<u32>,
}

impl Batch {
    pub fn is_empty(&self) -> bool {
        self.segs.is_empty()
    }

    pub fn byte_len(&self) -> usize {
        self.buf.len()
    }

    pub fn packets(&self) -> usize {
        self.segs.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.segs.iter().scan(0usize, |offset, &length| {
            let start = *offset;
            let end = start.checked_add(length as usize)?;
            let packet = self.buf.get(start..end)?;
            *offset = end;
            Some(packet)
        })
    }

    /// Iterates over packet storage for in-place delivery to a receiver.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut [u8]> {
        let mut rest = self.buf.as_mut_slice();
        self.segs.iter().map_while(move |&length| {
            let (packet, tail) = mem::take(&mut rest).split_at_mut_checked(length as usize)?;
            rest = tail;
            Some(packet)
        })
    }
}

impl Sink for Batch {
    type Reservation<'sink> = permits::Batch<'sink>;

    fn reserve(&mut self, limit: usize) -> Result<Option<Self::Reservation<'_>>, Allocation> {
        self.segs
            .try_grow(1)
            .map_err(|error| Allocation::Segments {
                error,
                requested: 1,
            })?;
        self.buf
            .try_grow(limit)
            .map_err(|error| Allocation::Payload {
                error,
                requested: limit,
            })?;
        Ok(Some(permits::Batch::new(self, limit)))
    }
}

impl Fresh for Batch {
    fn prepare(&mut self) {
        self.buf.clear();
        self.segs.clear();
    }
}

pub(crate) struct Gso {
    limits: datagram::GsoLimits,
    pub(super) storage: Storage,
}

pub(super) enum Storage {
    Vacant(Vec<u8>),
    Ready(Ready),
}

pub(crate) struct Ready {
    pub(crate) payload: storage::NonEmpty<Vec<u8>>,
    pub(crate) segment_size: num::NonZero<u16>,
    pub(crate) packets: num::NonZero<u8>,
    pub(super) sealed: bool,
}

/// Connection-local append view over a shared GSO flight.
pub(in crate::conn) struct GsoAppend<'batch> {
    batch: &'batch mut Gso,
}

impl Gso {
    pub(crate) const fn new(limits: datagram::GsoLimits) -> Self {
        Self {
            limits,
            storage: Storage::Vacant(Vec::new()),
        }
    }

    pub(crate) const fn limits(&self) -> datagram::GsoLimits {
        self.limits
    }

    pub(crate) const fn packets(&self) -> usize {
        match &self.storage {
            Storage::Vacant(_) => 0,
            Storage::Ready(ready) => ready.packets.get() as usize,
        }
    }

    pub(super) fn len(&self) -> usize {
        match &self.storage {
            Storage::Vacant(value) => value.len(),
            Storage::Ready(ready) => ready.payload.len().get(),
        }
    }

    pub(super) const fn segment_size(&self) -> Option<num::NonZero<u16>> {
        match &self.storage {
            Storage::Vacant(_) => None,
            Storage::Ready(ready) => Some(ready.segment_size),
        }
    }

    pub(super) fn out(&mut self) -> write::Append<'_> {
        match &mut self.storage {
            Storage::Vacant(value) => write::Append::new(value),
            Storage::Ready(ready) => ready.payload.append(),
        }
    }

    pub(crate) fn recycle(&mut self, mut value: Vec<u8>) -> Result<(), Vec<u8>> {
        if matches!(&self.storage, Storage::Vacant(current) if current.capacity() == 0) {
            value.clear();
            self.storage = Storage::Vacant(value);
            Ok(())
        } else {
            Err(value)
        }
    }

    pub(in crate::conn) fn append(&mut self) -> GsoAppend<'_> {
        GsoAppend { batch: self }
    }

    pub(crate) fn take(&mut self) -> Option<Ready> {
        match mem::replace(&mut self.storage, Storage::Vacant(Vec::new())) {
            Storage::Vacant(value) => {
                self.storage = Storage::Vacant(value);
                None
            }
            Storage::Ready(ready) => Some(ready),
        }
    }
}

impl Sink for Gso {
    type Reservation<'sink> = permits::Gso<'sink>;

    const PAD_TO_CEILING: bool = true;

    fn reserve(&mut self, max: usize) -> Result<Option<Self::Reservation<'_>>, Allocation> {
        if matches!(&self.storage, Storage::Ready(ready) if ready.sealed)
            || self.packets() >= self.limits.capacity().count()
        {
            return Ok(None);
        }
        let room = self
            .limits
            .max_bytes()
            .into_raw()
            .saturating_sub(self.len());
        let limit = self
            .segment_size()
            .map_or(max, |size| max.min(usize::from(size.get())))
            .min(room);
        if limit == 0 {
            return Ok(None);
        }
        self.out()
            .try_grow(limit)
            .map_err(|error| Allocation::Payload {
                error,
                requested: limit,
            })?;
        Ok(Some(permits::Gso::new(self, limit)))
    }
}

impl Fresh for Gso {
    fn prepare(&mut self) {
        let mut value = match mem::replace(&mut self.storage, Storage::Vacant(Vec::new())) {
            Storage::Vacant(value) => value,
            Storage::Ready(ready) => ready.payload.into_storage(),
        };
        value.clear();
        self.storage = Storage::Vacant(value);
    }
}

const _: () = {
    assert!(size_of::<Storage>() == 4 * size_of::<usize>());
    assert!(size_of::<Gso>() == 5 * size_of::<usize>());
};

impl<'batch> Sink for GsoAppend<'batch> {
    type Reservation<'sink>
        = permits::Gso<'sink>
    where
        Self: 'sink;

    const PAD_TO_CEILING: bool = true;

    fn reserve(&mut self, limit: usize) -> Result<Option<Self::Reservation<'_>>, Allocation> {
        self.batch.reserve(limit)
    }
}

impl Sink for Vec<Vec<u8>> {
    type Reservation<'sink> = permits::Fresh<'sink>;

    fn reserve(&mut self, limit: usize) -> Result<Option<Self::Reservation<'_>>, Allocation> {
        self.try_grow(1).map_err(|error| Allocation::Packets {
            error,
            requested: 1,
        })?;
        permits::Fresh::new(self, limit).map(Some)
    }
}

pub(in crate::conn) struct Slot<'a> {
    pub(in crate::conn) packet: &'a mut Vec<u8>,
    pub(in crate::conn) emitted: bool,
}

impl<'packet> Sink for Slot<'packet> {
    type Reservation<'sink>
        = permits::Single<'sink, 'packet>
    where
        Self: 'sink;

    fn reserve(&mut self, limit: usize) -> Result<Option<Self::Reservation<'_>>, Allocation> {
        permits::Single::new(self, limit).map(Some)
    }
}
