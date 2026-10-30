use o3::depot;
use std::num;

use o3::depot::capacity;

use crate::conn::{self, life::options::builder};

#[derive(Clone, Copy)]
#[repr(transparent)]
pub(in crate::conn) struct Plan(num::NonZero<u32>);

impl Plan {
    pub(in crate::conn) const DEFAULT: Self = {
        assert!(1024 <= conn::MAX_QUEUE_CAPACITY);
        Self(num::NonZero::<u32>::MIN.saturating_add(1023))
    };

    pub(in crate::conn) const fn try_new(capacity: usize) -> Result<Self, builder::Invalid> {
        const {
            assert!(conn::MAX_QUEUE_CAPACITY <= u32::MAX as usize);
        }
        if capacity == 0 || capacity > conn::MAX_QUEUE_CAPACITY {
            return Err(builder::Invalid::StreamEvents {
                actual: capacity,
                minimum: 1,
                maximum: conn::MAX_QUEUE_CAPACITY,
            });
        }
        Ok(Self(
            num::NonZero::<u32>::MIN.saturating_add(capacity as u32 - 1),
        ))
    }

    pub(in crate::conn) const fn get(self) -> usize {
        self.0.get() as usize
    }
}

// SAFETY: every copy retains the same nonzero, bounded stream-event capacity.
unsafe impl depot::raw::Count for Plan {
    const MAX: u32 = conn::MAX_QUEUE_CAPACITY as u32;

    fn count(self) -> capacity::Count {
        capacity::Count::new(self.0.get())
    }
}
