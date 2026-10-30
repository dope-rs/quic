use std::time;

const INITIAL_MINIMUM: u64 = 14_720;
const INITIAL_PACKETS: u64 = 10;
const MINIMUM_PACKETS: u64 = 2;
const LOSS_REDUCTION_DENOMINATOR: u64 = 2;

#[derive(Clone)]
pub(crate) struct NewReno {
    cwnd: u64,
    ssthresh: u64,
    max_datagram_size: u64,
    congestion_avoidance_acked: u64,
    last_congestion_event: Option<time::Instant>,
}

impl NewReno {
    pub(crate) fn new(mtu: u64) -> Self {
        Self {
            cwnd: Self::initial(mtu),
            ssthresh: u64::MAX,
            max_datagram_size: mtu,
            congestion_avoidance_acked: 0,
            last_congestion_event: None,
        }
    }

    pub(crate) fn allows_send(&self, flight: u64) -> bool {
        flight < self.cwnd
    }

    pub(crate) fn packet_acked(&mut self, bytes: u64, sent: time::Instant, tracked: bool) {
        if !tracked {
            return;
        }
        if self
            .last_congestion_event
            .is_some_and(|event| sent <= event)
        {
            return;
        }
        if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(bytes);
        } else {
            self.congestion_avoidance_acked = self.congestion_avoidance_acked.saturating_add(bytes);
            if self.congestion_avoidance_acked >= self.cwnd {
                self.congestion_avoidance_acked =
                    self.congestion_avoidance_acked.saturating_sub(self.cwnd);
                self.cwnd = self.cwnd.saturating_add(self.max_datagram_size);
            }
        }
    }

    pub(crate) fn packets_lost(&mut self, sent: time::Instant, now: time::Instant) {
        let active = matches!(
            self.last_congestion_event,
            Some(previous) if sent <= previous
        );
        if !active {
            self.last_congestion_event = Some(now);
            self.congestion_avoidance_acked = 0;
            self.ssthresh =
                (self.cwnd / LOSS_REDUCTION_DENOMINATOR).max(Self::minimum(self.max_datagram_size));
            self.cwnd = self.ssthresh;
        }
    }

    pub(crate) fn collapse(&mut self) {
        let minimum = Self::minimum(self.max_datagram_size);
        self.congestion_avoidance_acked = 0;
        self.cwnd = minimum;
        self.ssthresh = minimum;
    }

    pub(crate) fn set_mtu(&mut self, mtu: u64) {
        self.max_datagram_size = mtu;
        let minimum = Self::minimum(mtu);
        self.cwnd = self.cwnd.max(minimum);
        self.ssthresh = self.ssthresh.max(minimum);
    }

    pub(crate) const fn window(&self) -> u64 {
        self.cwnd
    }

    pub(crate) const fn threshold(&self) -> u64 {
        self.ssthresh
    }

    pub(crate) const fn mtu(&self) -> u64 {
        self.max_datagram_size
    }

    const fn initial(mtu: u64) -> u64 {
        let ten = mtu.saturating_mul(INITIAL_PACKETS);
        let two = mtu.saturating_mul(MINIMUM_PACKETS);
        let floor = if two > INITIAL_MINIMUM {
            two
        } else {
            INITIAL_MINIMUM
        };
        if ten < floor { ten } else { floor }
    }

    const fn minimum(mtu: u64) -> u64 {
        mtu.saturating_mul(MINIMUM_PACKETS)
    }
}

const _: () = assert!(std::mem::size_of::<NewReno>() <= 56);
