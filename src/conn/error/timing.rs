use o3::base::num::bounded::U32;
use std::time;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Timing {
    Add {
        left: time::Duration,
        right_secs: u64,
        right_nanos: U32<0, 999_999_999>,
    },
    Mul {
        duration: time::Duration,
        factor: u32,
    },
    Deadline {
        at: time::Instant,
        duration_secs: u64,
        duration_nanos: U32<0, 999_999_999>,
    },
}

impl Timing {
    pub(crate) fn try_add(
        left: time::Duration,
        right: time::Duration,
    ) -> Result<time::Duration, Self> {
        left.checked_add(right).ok_or(Self::Add {
            left,
            right_secs: right.as_secs(),
            right_nanos: U32::clamp(right.subsec_nanos() as usize),
        })
    }

    pub(crate) fn try_mul(duration: time::Duration, factor: u32) -> Result<time::Duration, Self> {
        duration
            .checked_mul(factor)
            .ok_or(Self::Mul { duration, factor })
    }

    pub(crate) fn try_deadline(
        at: time::Instant,
        duration: time::Duration,
    ) -> Result<time::Instant, Self> {
        at.checked_add(duration).ok_or(Self::Deadline {
            at,
            duration_secs: duration.as_secs(),
            duration_nanos: U32::clamp(duration.subsec_nanos() as usize),
        })
    }
}
