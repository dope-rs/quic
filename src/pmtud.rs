pub const BASE_PMTU: u64 = 1200;
pub const DEFAULT_MAX_PMTU: u64 = 1500;
const MAX_PROBES_PER_SIZE: u32 = 3;
const SEARCH_DONE_INTERVAL: u64 = 4;

#[derive(Debug, Clone)]
pub struct Pmtud {
    current: u64,
    upper_bound: u64,
    in_flight_size: Option<u64>,
    probes_at_size: u32,
    done: bool,
}

impl Pmtud {
    pub fn new(max_pmtu: u64) -> Self {
        Self {
            current: BASE_PMTU,
            upper_bound: max_pmtu.max(BASE_PMTU),
            in_flight_size: None,
            probes_at_size: 0,
            done: false,
        }
    }

    pub fn current(&self) -> u64 {
        self.current
    }

    pub fn done(&self) -> bool {
        self.done
    }

    pub fn next_probe(&self) -> Option<u64> {
        if self.done || self.in_flight_size.is_some() {
            return None;
        }
        if self.upper_bound <= self.current + SEARCH_DONE_INTERVAL {
            return None;
        }
        Some((self.current + self.upper_bound) / 2)
    }

    pub fn arm_probe(&mut self, size: u64) {
        self.in_flight_size = Some(size);
    }

    pub fn on_probe_acked(&mut self) {
        if let Some(size) = self.in_flight_size.take() {
            self.current = size.max(self.current);
            self.probes_at_size = 0;
        }
        self.recompute_done();
    }

    pub fn on_probe_lost(&mut self) {
        let Some(size) = self.in_flight_size else {
            return;
        };
        self.probes_at_size += 1;
        if self.probes_at_size >= MAX_PROBES_PER_SIZE {
            self.upper_bound = size.saturating_sub(1).max(self.current);
            self.in_flight_size = None;
            self.probes_at_size = 0;
            self.recompute_done();
        } else {
            self.in_flight_size = None;
        }
    }

    fn recompute_done(&mut self) {
        if self.upper_bound <= self.current + SEARCH_DONE_INTERVAL {
            self.done = true;
        }
    }
}

impl Default for Pmtud {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_PMTU)
    }
}
