use std::time::Duration;

pub const K_GRANULARITY: Duration = Duration::from_millis(1);

pub const K_INITIAL_RTT: Duration = Duration::from_millis(333);

pub const K_PACKET_THRESHOLD: u64 = 3;

pub const K_TIME_THRESHOLD_NUM: u32 = 9;
pub const K_TIME_THRESHOLD_DEN: u32 = 8;

#[derive(Debug, Default, Clone)]
pub struct RttTracker {
    pub latest_rtt: Option<Duration>,
    pub min_rtt: Option<Duration>,
    pub smoothed_rtt: Option<Duration>,
    pub rttvar: Duration,
}

impl RttTracker {
    pub fn update(&mut self, sample: Duration, ack_delay: Duration) {
        self.latest_rtt = Some(sample);

        let prev_min = self.min_rtt;
        match prev_min {
            Some(prev) if sample < prev => self.min_rtt = Some(sample),
            None => self.min_rtt = Some(sample),
            _ => {}
        }
        let min_rtt = self.min_rtt.unwrap();

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

    pub fn pto_period(&self, max_ack_delay: Duration) -> Duration {
        let smoothed = self.smoothed_rtt.unwrap_or(K_INITIAL_RTT);
        let rttvar_scaled = if 4 * self.rttvar > K_GRANULARITY {
            4 * self.rttvar
        } else {
            K_GRANULARITY
        };
        smoothed + rttvar_scaled + max_ack_delay
    }

    pub fn loss_delay(&self) -> Duration {
        let smoothed = self.smoothed_rtt.unwrap_or(K_INITIAL_RTT);
        let latest = self.latest_rtt.unwrap_or(smoothed);
        let max_rtt = if smoothed > latest { smoothed } else { latest };
        let scaled = (max_rtt * K_TIME_THRESHOLD_NUM) / K_TIME_THRESHOLD_DEN;
        if scaled > K_GRANULARITY {
            scaled
        } else {
            K_GRANULARITY
        }
    }
}
