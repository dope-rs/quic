use std::num;

use crate::{conn::stream::resident::Key, wire::Mark};

const FLAG: u64 = 1 << 63;

/// One resident key and one owner-defined bit in the key's proved spare bit.
#[doc(hidden)]
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Tag(u64);

impl Tag {
    #[doc(hidden)]
    pub const fn new(key: Option<Key>, mark: Mark) -> Self {
        let raw = match key {
            Some(key) => key.raw().get(),
            None => 0,
        };
        let marker = match mark {
            Mark::Clear => 0,
            Mark::Set => FLAG,
        };
        Self(raw | marker)
    }

    #[doc(hidden)]
    pub const fn key(self) -> Option<Key> {
        match num::NonZero::<u64>::new(self.0 & !FLAG) {
            Some(raw) => Key::from_raw(raw),
            None => None,
        }
    }

    #[doc(hidden)]
    pub const fn mark(self) -> Mark {
        if self.0 & FLAG == 0 {
            Mark::Clear
        } else {
            Mark::Set
        }
    }
}

const _: () = assert!(size_of::<Tag>() == size_of::<u64>());
