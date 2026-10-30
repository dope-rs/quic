use std::num;
use std::time;

use crate::runtime::mux;
use crate::stream;
use mux::{auth, handler, protocol};
use protocol::rotation;
use rotation::Local as _;

/// Endpoint-wide policy for bounded rotation of live local connection IDs.
/// It retains no connection handle, packet owner, borrow, or side table.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Rotation {
    interval_ns: Option<num::NonZero<u64>>,
    scan_budget: num::NonZero<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Interval { actual: u128, maximum: u64 },
}

impl Rotation {
    pub const fn disabled() -> Self {
        Self {
            interval_ns: None,
            scan_budget: num::NonZero::<u16>::MIN,
        }
    }

    pub fn try_periodic(
        interval: time::Duration,
        budget: num::NonZero<u16>,
    ) -> Result<Self, Error> {
        let actual = interval.as_nanos();
        let Ok(period) = u64::try_from(actual).and_then(num::NonZero::<u64>::try_from) else {
            return Err(Error::Interval {
                actual,
                maximum: u64::MAX,
            });
        };
        Ok(Self::from_nanos(period, budget))
    }

    pub const fn from_nanos(period: num::NonZero<u64>, budget: num::NonZero<u16>) -> Self {
        Self {
            interval_ns: Some(period),
            scan_budget: budget,
        }
    }

    pub const fn is_enabled(self) -> bool {
        self.interval_ns.is_some()
    }

    pub const fn scan_budget(self) -> num::NonZero<u16> {
        self.scan_budget
    }

    pub fn interval(self) -> Option<time::Duration> {
        self.interval_ns
            .map(|interval| time::Duration::from_nanos(interval.get()))
    }

    pub(crate) fn schedule_at(self, now: time::Instant) -> Schedule {
        let (period, deadline) = match self.interval_ns {
            Some(period) => {
                let interval = time::Duration::from_nanos(period.get());
                let deadline = now.checked_add(interval);
                (period, deadline)
            }
            None => (num::NonZero::<u64>::MIN, None),
        };
        Schedule {
            interval_ns: period,
            scan_budget: self.scan_budget,
            deadline,
            cursor: 0,
        }
    }
}

/// Owner-free, allocation-free state of one endpoint's periodic CID sweep.
pub struct Schedule {
    deadline: Option<time::Instant>,
    interval_ns: num::NonZero<u64>,
    cursor: u16,
    scan_budget: num::NonZero<u16>,
}

impl Schedule {
    pub const fn deadline(&self) -> Option<time::Instant> {
        self.deadline
    }

    /// Permanently retires the periodic maintenance owner at endpoint
    /// shutdown. An installed endpoint has a single lifecycle, so no restart
    /// can follow this transition.
    pub(crate) fn seal(&mut self) {
        self.deadline = None;
        self.cursor = 0;
    }

    /// Advances at most `scan_budget` slots, reconciling each borrow in place.
    pub(crate) fn maintain_at<H, const DOMAIN: u8, B, A>(
        &mut self,
        now: time::Instant,
        protocol: &mut protocol::Io<'_, '_, H, DOMAIN, B, A>,
    ) -> Progress
    where
        H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
        B: stream::Recv,
        A: auth::Mode<DOMAIN>,
    {
        let Some(deadline) = self.deadline else {
            return Progress::idle();
        };
        if now < deadline {
            return Progress::idle();
        }

        let sweep = protocol.sweep(now, self.cursor, self.scan_budget);
        self.cursor = sweep.next_cursor();
        if sweep.is_complete() {
            self.cursor = 0;
            let interval = time::Duration::from_nanos(self.interval_ns.get());
            self.deadline = now.checked_add(interval);
        } else {
            self.deadline = Some(now);
        }
        Progress {
            visited: sweep.batch().visited(),
            started: sweep.batch().started(),
            scanned: sweep.scanned(),
            complete: sweep.is_complete(),
        }
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct Progress {
    visited: usize,
    started: usize,
    scanned: usize,
    complete: bool,
}

impl Progress {
    const fn idle() -> Self {
        Self {
            visited: 0,
            started: 0,
            scanned: 0,
            complete: false,
        }
    }

    pub const fn visited(self) -> usize {
        self.visited
    }

    pub const fn started(self) -> usize {
        self.started
    }

    pub const fn scanned(self) -> usize {
        self.scanned
    }

    pub const fn is_complete(self) -> bool {
        self.complete
    }
}

const _: () = {
    assert!(std::mem::size_of::<Rotation>() <= 2 * std::mem::size_of::<usize>());
    assert!(!std::mem::needs_drop::<Rotation>());
    assert!(std::mem::size_of::<Schedule>() <= 4 * std::mem::size_of::<usize>());
    assert!(!std::mem::needs_drop::<Schedule>());
    assert!(!std::mem::needs_drop::<Progress>());
};
