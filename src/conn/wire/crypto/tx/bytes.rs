use crate::conn::{self, output::delivery, wire, wire::tls};
use crate::wire::varint;
use rustls::quic;
use std::{mem, ptr};

#[derive(Clone, Copy)]
#[repr(transparent)]
struct Reclaim(usize);

struct Offsets {
    stored: u64,
    reclaim: Reclaim,
    next_unsent: u64,
}

struct Space {
    bytes: Vec<u8>,
    offsets: Offsets,
}

impl Reclaim {
    const EMPTY: Self = Self(0);

    const fn new(index: usize) -> Self {
        Self(index)
    }

    const fn get(self) -> usize {
        self.0
    }
}

impl Space {
    const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            offsets: Offsets {
                stored: 0,
                reclaim: Reclaim::EMPTY,
                next_unsent: 0,
            },
        }
    }

    /// Appends fit VarInt::MAX; reclaiming and compaction preserve their end.
    fn end_offset(&self) -> u64 {
        self.offsets.stored + self.bytes.len() as u64
    }

    fn index(&self, offset: u64) -> Option<usize> {
        let index = usize::try_from(offset.checked_sub(self.offsets.stored)?).ok()?;
        (index <= self.bytes.len()).then_some(index)
    }

    fn reclaim_to(&mut self, offset: u64) {
        let Some(index) = self.index(offset) else {
            return;
        };
        if index < self.offsets.reclaim.get() {
            return;
        }
        self.offsets.reclaim = Reclaim::new(index);
        if index == self.bytes.len() {
            self.bytes.clear();
            self.offsets.stored = offset;
            self.offsets.reclaim = Reclaim::EMPTY;
        }
    }

    /// Retains the initialized prefix and reclaim index admitted by `index`;
    /// every shortening transition clears that index.
    fn compact(&mut self) {
        let start = self.offsets.reclaim.get();
        if start == 0 {
            return;
        }
        let len = self.bytes.len() - start;
        let bytes = self.bytes.as_mut_ptr();
        // SAFETY: reclaim retains this initialized prefix in the same exclusive allocation.
        unsafe {
            ptr::copy(bytes.add(start), bytes, len);
            self.bytes.set_len(len);
        }
        self.offsets.stored += start as u64;
        self.offsets.reclaim = Reclaim::EMPTY;
    }
}

/// Unique owner of all outbound TLS bytes and their epoch-local offsets.
pub(in crate::conn::wire) struct Store {
    spaces: [Space; 3],
    spare: Vec<u8>,
}

impl Store {
    pub(super) fn new() -> Self {
        Self {
            spaces: [const { Space::new() }; 3],
            spare: Vec::new(),
        }
    }

    /// Native output consumes TLS state. A rejected suffix is unpublished and
    /// the caller must fail the handshake before exposing returned key changes.
    pub(in crate::conn::wire) fn try_write(
        &mut self,
        epoch: conn::Epoch,
        state: &mut quic::Connection,
    ) -> Result<Option<quic::KeyChange>, wire::Tls> {
        let space = epoch.bind_mut(&mut self.spaces);
        space.compact();
        if space.bytes.is_empty() && self.spare.capacity() > space.bytes.capacity() {
            mem::swap(&mut space.bytes, &mut self.spare);
        }
        let start = space.bytes.len();
        let offset = varint::VarInt::MAX
            .saturating_sub(space.offsets.stored)
            .saturating_sub(start as u64);
        let room = (tls::MAX_CRYPTO_BYTES - start).min(offset.min(usize::MAX as u64) as usize);
        let change = state.write_hs(&mut space.bytes);
        let actual = space.bytes.len() - start;
        if actual > room {
            space.bytes.truncate(start);
            return Err(wire::Tls::Output {
                epoch,
                actual,
                available: room,
            });
        }
        Ok(change)
    }

    pub(super) fn has_unsent(&self, epoch: conn::Epoch) -> bool {
        let space = epoch.bind(&self.spaces);
        space.offsets.next_unsent < space.end_offset()
    }

    pub(super) fn peek_unsent(&self, epoch: conn::Epoch) -> Option<delivery::Crypto> {
        let space = epoch.bind(&self.spaces);
        let len =
            usize::try_from(space.end_offset().checked_sub(space.offsets.next_unsent)?).ok()?;
        delivery::Crypto::new(space.offsets.next_unsent, len)
    }

    pub(super) fn slice(&self, epoch: conn::Epoch, record: delivery::Crypto) -> Option<&[u8]> {
        let space = epoch.bind(&self.spaces);
        let start = space.index(record.offset())?;
        let end = start.checked_add(record.len())?;
        space.bytes.get(start..end)
    }

    pub(super) fn advance(&mut self, epoch: conn::Epoch, record: delivery::Crypto) {
        epoch.bind_mut(&mut self.spaces).offsets.next_unsent = record.end();
    }

    pub(super) fn reclaim_to(&mut self, epoch: conn::Epoch, offset: u64) {
        epoch.bind_mut(&mut self.spaces).reclaim_to(offset);
    }

    pub(super) fn discard(&mut self, epoch: conn::Epoch) {
        let space = epoch.bind_mut(&mut self.spaces);
        let end = space.end_offset();
        let mut bytes = mem::take(&mut space.bytes);
        bytes.clear();
        if bytes.capacity() > self.spare.capacity() {
            mem::swap(&mut bytes, &mut self.spare);
        }
        space.offsets.stored = end;
        space.offsets.reclaim = Reclaim::EMPTY;
        space.offsets.next_unsent = end;
    }

    pub(super) fn retry(&mut self, epoch: conn::Epoch) {
        let space = epoch.bind_mut(&mut self.spaces);
        space.offsets.next_unsent = space.offsets.stored;
    }

    pub(super) fn bytes(&self, epoch: conn::Epoch) -> &[u8] {
        &epoch.bind(&self.spaces).bytes
    }
}

const _: () = {
    assert!(usize::BITS <= u64::BITS);
    assert!(mem::size_of::<Reclaim>() == mem::size_of::<usize>());
};
