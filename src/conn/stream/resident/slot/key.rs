use o3::depot;
use o3::depot::index::Stored;
use std::num;

use crate::conn::stream::resident::slot;

// SAFETY: the packed handle preserves its slot generation, reserves zero as
// vacancy, and derives its direct index from the low word.
unsafe impl<Side> depot::raw::Key for slot::Handle<Side> {
    type Raw = u64;
    type Live = Self;

    const VACANT: Self::Raw = 0;

    fn index(self) -> usize {
        self.index() as usize
    }

    fn into_raw(self) -> Self::Raw {
        self.raw().get()
    }

    fn from_raw(raw: Stored<Self>) -> Self {
        // SAFETY: Stored proves this identity was emitted by a live slot Handle.
        let raw = raw.into_raw();
        let raw = unsafe { num::NonZero::<u64>::new_unchecked(raw) };
        slot::Handle::from_raw(raw)
    }

    fn decode(raw: Self::Raw) -> Option<Self> {
        num::NonZero::<u64>::new(raw)
            .filter(|raw| raw.get() as u32 != 0)
            .map(slot::Handle::from_raw)
    }

    fn into_live(self) -> Self::Live {
        self
    }

    fn from_live(live: Self::Live) -> Self {
        live
    }
}
