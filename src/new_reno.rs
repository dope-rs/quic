use std::time;

pub(crate) const MAX_DATAGRAM_SIZE: u64 = 1200;

pub(crate) const INITIAL_WINDOW: u64 = 12_000;

pub(crate) const MINIMUM_WINDOW: u64 = 2_400;

const LOSS_REDUCTION_DENOMINATOR: u64 = 2;

#[derive(Debug, Clone)]
pub(crate) struct NewReno {
    pub(crate) cwnd: u64,
    pub(crate) ssthresh: u64,
    pub(crate) bytes_in_flight: u64,
    pub(crate) last_congestion_event: Option<time::Instant>,
}

impl Default for NewReno {
    fn default() -> Self {
        Self {
            cwnd: INITIAL_WINDOW,
            ssthresh: u64::MAX,
            bytes_in_flight: 0,
            last_congestion_event: None,
        }
    }
}

impl NewReno {
    pub fn allows_send(&self) -> bool {
        self.bytes_in_flight < self.cwnd
    }

    pub fn packet_sent(&mut self, sent_bytes: u64, in_flight: bool) {
        if in_flight {
            self.bytes_in_flight = self.bytes_in_flight.saturating_add(sent_bytes);
        }
    }

    pub fn discard(&mut self, bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
    }

    pub fn packet_acked(&mut self, acked_bytes: u64, in_flight: bool) {
        if in_flight {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);
        }
        if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(acked_bytes);
        } else {
            let inc = MAX_DATAGRAM_SIZE.saturating_mul(acked_bytes) / self.cwnd.max(1);
            self.cwnd = self.cwnd.saturating_add(inc.max(1));
        }
    }

    pub fn packets_lost(&mut self, lost_bytes: u64, lost_sent_time: time::Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);

        let in_recovery = matches!(
            self.last_congestion_event,
            Some(prev) if lost_sent_time <= prev
        );
        if !in_recovery {
            self.last_congestion_event = Some(lost_sent_time);
            self.ssthresh = (self.cwnd / LOSS_REDUCTION_DENOMINATOR).max(MINIMUM_WINDOW);
            self.cwnd = self.ssthresh;
        }
    }
}
