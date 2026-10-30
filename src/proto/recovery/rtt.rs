use o3::base::time::DurationExt as _;
use std::{cmp::Ordering, time};

use crate::conn::Timing;

pub(crate) const GRANULARITY: time::Duration = time::Duration::from_millis(1);

pub(crate) const INITIAL_RTT: time::Duration = time::Duration::from_millis(333);

pub(crate) const PACKET_THRESHOLD: u64 = 3;

#[derive(Clone)]
pub(crate) struct RttTracker {
    pub(crate) latest_rtt: Option<time::Duration>,
    pub(crate) min_rtt: Option<time::Duration>,
    pub(crate) smoothed_rtt: Option<time::Duration>,
    pub(crate) rttvar: time::Duration,
}

impl Default for RttTracker {
    fn default() -> Self {
        Self {
            latest_rtt: None,
            min_rtt: None,
            smoothed_rtt: None,
            rttvar: time::Duration::ZERO.average::<2>(INITIAL_RTT),
        }
    }
}

impl RttTracker {
    pub(crate) fn update(&mut self, sample: time::Duration, delay: time::Duration) {
        let min_rtt = self.min_rtt.map_or(sample, |prior| prior.min(sample));
        let adjusted = match Self::difference(sample, delay) {
            (Ordering::Equal | Ordering::Greater, adjusted) if adjusted >= min_rtt => adjusted,
            _ => sample,
        };
        let (smoothed, variance) = match self.smoothed_rtt {
            None => (adjusted, time::Duration::ZERO.average::<2>(adjusted)),
            Some(prev) => (
                prev.average::<8>(adjusted),
                self.rttvar.average::<4>(Self::difference(prev, adjusted).1),
            ),
        };
        self.latest_rtt = Some(sample);
        self.min_rtt = Some(min_rtt);
        self.smoothed_rtt = Some(smoothed);
        self.rttvar = variance;
    }

    /// Orders the operands once and retains the borrow when normalizing nanoseconds.
    fn difference(left: time::Duration, right: time::Duration) -> (Ordering, time::Duration) {
        let order = left.cmp(&right);
        let (larger, smaller) = if order == Ordering::Less {
            (right, left)
        } else {
            (left, right)
        };
        let secs = larger.as_secs() - smaller.as_secs();
        let left = larger.subsec_nanos();
        let right = smaller.subsec_nanos();
        let value = if left >= right {
            time::Duration::new(secs, left - right)
        } else {
            time::Duration::new(secs - 1, 1_000_000_000 - (right - left))
        };
        (order, value)
    }

    pub(crate) fn try_pto(&self, max_ack: time::Duration) -> Result<time::Duration, Timing> {
        let smoothed = self.smoothed_rtt.unwrap_or(INITIAL_RTT);
        let variance = Timing::try_mul(self.rttvar, 4)?.max(GRANULARITY);
        let period = Timing::try_add(smoothed, variance)?;
        Timing::try_add(period, max_ack)
    }

    /// Computes floor(9x/8) as x + floor(x/8), checking only the final sum.
    pub(crate) fn try_delay(&self) -> Result<time::Duration, Timing> {
        let smoothed = self.smoothed_rtt.unwrap_or(INITIAL_RTT);
        let latest = self.latest_rtt.unwrap_or(smoothed);
        let max_rtt = if smoothed > latest { smoothed } else { latest };
        Ok(Timing::try_add(max_rtt, time::Duration::ZERO.average::<8>(max_rtt))?.max(GRANULARITY))
    }
}
