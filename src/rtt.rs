use std::time;

pub(crate) const GRANULARITY: time::Duration = time::Duration::from_millis(1);

pub(crate) const INITIAL_RTT: time::Duration = time::Duration::from_millis(333);

pub(crate) const PACKET_THRESHOLD: u64 = 3;

pub(crate) const TIME_THRESHOLD_NUMERATOR: u32 = 9;
pub(crate) const TIME_THRESHOLD_DENOMINATOR: u32 = 8;

#[derive(Debug, Default, Clone)]
pub(crate) struct RttTracker {
    pub(crate) latest_rtt: Option<time::Duration>,
    pub(crate) min_rtt: Option<time::Duration>,
    pub(crate) smoothed_rtt: Option<time::Duration>,
    pub(crate) rttvar: time::Duration,
}

impl RttTracker {
    pub fn update(&mut self, sample: time::Duration, ack_delay: time::Duration) {
        self.latest_rtt = Some(sample);

        let prev_min = self.min_rtt;
        match prev_min {
            Some(prev) if sample < prev => self.min_rtt = Some(sample),
            None => self.min_rtt = Some(sample),
            _ => {}
        }
        let min_rtt = match self.min_rtt {
            Some(min_rtt) => min_rtt,
            None => sample,
        };

        let adjusted = if sample >= min_rtt + ack_delay {
            sample - ack_delay
        } else {
            sample
        };

        match self.smoothed_rtt {
            None => {
                self.smoothed_rtt = Some(adjusted);
                self.rttvar = adjusted / 2;
            }
            Some(prev) => {
                let diff = prev.abs_diff(adjusted);
                self.rttvar = (self.rttvar * 3 + diff) / 4;
                self.smoothed_rtt = Some((prev * 7 + adjusted) / 8);
            }
        }
    }

    pub fn pto_period(&self, max_ack_delay: time::Duration) -> time::Duration {
        let smoothed = self.smoothed_rtt.unwrap_or(INITIAL_RTT);
        let rttvar_scaled = if 4 * self.rttvar > GRANULARITY {
            4 * self.rttvar
        } else {
            GRANULARITY
        };
        smoothed + rttvar_scaled + max_ack_delay
    }

    pub fn loss_delay(&self) -> time::Duration {
        let smoothed = self.smoothed_rtt.unwrap_or(INITIAL_RTT);
        let latest = self.latest_rtt.unwrap_or(smoothed);
        let max_rtt = if smoothed > latest { smoothed } else { latest };
        let scaled = (max_rtt * TIME_THRESHOLD_NUMERATOR) / TIME_THRESHOLD_DENOMINATOR;
        if scaled > GRANULARITY {
            scaled
        } else {
            GRANULARITY
        }
    }
}
