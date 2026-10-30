use o3::buffer::pool::owners;
use o3::buffer::{self, pool, storage};
use pool::{borrowed, state};
use std::num::NonZero;

use crate::conn;

pub mod batch;
mod size;

pub(crate) use size::Size;

pub struct Arena {
    pool: pool::Pool<state::Initialized>,
}

/// An exclusive packet slot borrowed from its arena.
#[must_use = "a pooled QUIC datagram packet owns one exclusive arena slot"]
pub struct Packet<'pool> {
    pub(crate) lease: borrowed::Slice<'pool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Full;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Full(Full),
    Storage(borrowed::Error),
    Maximum {
        bytes: usize,
        maximum: usize,
    },
    Resident {
        required: NonZero<usize>,
        maximum: usize,
    },
}

/// Protected wire bytes retaining their original arena slot until consumed.
pub struct Sealed<'pool>(storage::Shared<owners::Edge<owners::Plain, pool::Borrowed<'pool>>>);

impl Arena {
    pub const fn payload_max(bytes: usize, cid: usize) -> Option<usize> {
        let Some(overhead) = cid.checked_add(conn::MAX_PACKET_NUMBER_LEN as usize) else {
            return None;
        };
        let Some(overhead) = overhead.checked_add(conn::TAG_LEN + 2) else {
            return None;
        };
        bytes.checked_sub(overhead)
    }

    pub fn try_new(slots: usize, bytes: usize) -> Result<Self, pool::CreateError> {
        let pool = pool::Pool::try_new(slots, bytes)?;
        Ok(Self { pool })
    }

    pub fn try_acquire(&self, payload: usize) -> Result<Packet<'_>, Error> {
        let source = borrowed::Source::try_new(&self.pool, payload, conn::TAG_LEN)
            .map_err(Error::Storage)?;
        let lease = source.acquire().ok_or(Error::Full(Full))?;
        Ok(Packet { lease })
    }

    /// Acquires one exact payload and lends its fixed extent before publishing the packet.
    pub fn try_with<const N: usize>(
        &self,
        write: impl FnOnce(&mut [u8; N]),
    ) -> Result<Packet<'_>, Error> {
        let mut packet = self.try_acquire(N)?;
        // SAFETY: this acquisition retains exactly N initialized payload bytes in
        // its exclusive slot; the callback's borrow ends before the packet moves.
        let out = unsafe { &mut *packet.payload_mut().as_mut_ptr().cast::<[u8; N]>() };
        write(out);
        Ok(packet)
    }

    pub fn available(&self) -> usize {
        self.pool.available()
    }

    pub fn slots(&self) -> usize {
        self.pool.slots()
    }
}

impl<'pool> Packet<'pool> {
    pub fn payload(&self) -> &[u8] {
        self.lease.as_slice()
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        self.lease.as_mut_slice()
    }

    pub fn len(&self) -> usize {
        self.lease.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AsRef<[u8]> for Packet<'_> {
    fn as_ref(&self) -> &[u8] {
        self.lease.as_slice()
    }
}

impl buffer::Residency for Packet<'_> {
    fn resident(&self) -> usize {
        self.lease.resident()
    }
}

impl<'pool> Sealed<'pool> {
    pub(crate) fn new(
        bytes: storage::Shared<owners::Edge<owners::Plain, pool::Borrowed<'pool>>>,
    ) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for Sealed<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl buffer::Residency for Sealed<'_> {
    fn resident(&self) -> usize {
        self.0.resident()
    }
}

const _: () = {
    assert!(
        size_of::<Sealed<'static>>()
            == size_of::<storage::Shared<owners::Edge<owners::Plain, pool::Borrowed<'static>>>>()
    );
    assert!(
        align_of::<Sealed<'static>>()
            == align_of::<storage::Shared<owners::Edge<owners::Plain, pool::Borrowed<'static>>>>()
    );
    assert!(size_of::<Packet<'static>>() == 3 * size_of::<usize>());
    assert!(size_of::<Error>() == 3 * size_of::<usize>());
    assert!(size_of::<Result<Packet<'static>, Error>>() == 4 * size_of::<usize>());
};

// SAFETY: the sealed packet retains its immutable arena extent and original borrow.
unsafe impl buffer::raw::Source for Sealed<'_> {}
