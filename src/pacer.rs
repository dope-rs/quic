use std::time::{Duration, Instant};

const PACER_BURST_PACKETS: u32 = 10;
const PACER_RATE_NUM: u64 = 5;
const PACER_RATE_DEN: u64 = 4;

#[derive(Debug, Clone)]
pub struct Pacer {
    next_release: Instant,
    burst_left: u32,
}

impl Pacer {
    pub fn new(now: Instant) -> Self {
        Self {
            next_release: now,
            burst_left: PACER_BURST_PACKETS,
        }
    }

    pub fn allows_send(&self, now: Instant) -> bool {
        self.burst_left > 0 || now >= self.next_release
    }

    pub fn next_release_time(&self) -> Instant {
        self.next_release
    }

    pub fn packet_sent(&mut self, bytes: u64, now: Instant, cwnd: u64, srtt: Duration) {
        if self.burst_left > 0 {
            self.burst_left -= 1;
            self.next_release = now;
            return;
        }
        let srtt_nanos = srtt.as_nanos().min(u64::MAX as u128) as u64;
        let denom = cwnd.max(1).saturating_mul(PACER_RATE_NUM);
        let interval_nanos = bytes
            .saturating_mul(srtt_nanos)
            .saturating_mul(PACER_RATE_DEN)
            / denom.max(1);
        self.next_release = now
            .checked_add(Duration::from_nanos(interval_nanos))
            .unwrap_or(now);
    }
}
