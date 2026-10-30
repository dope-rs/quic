use std::{num, time};

const RATE_NUMERATOR: u64 = 5;
const RATE_DENOMINATOR: u64 = 4;
const FIXED_SHIFT: u32 = 32;
const FIXED_ONE: u128 = 1_u128 << FIXED_SHIFT;

/// Connection-local fixed-point token bucket with no synthetic initial instant.
#[derive(Clone)]
pub(crate) struct Pacer {
    updated_at: Option<time::Instant>,
    credit: u64,
    bytes_per_ns: u64,
    ns_per_byte: u64,
    wait_nanos: u64,
}

impl Pacer {
    pub(crate) fn new(cwnd: u64, srtt: time::Duration, mtu: u64) -> Self {
        let (rate, pace) = Self::rate(cwnd, srtt);
        Self {
            updated_at: None,
            credit: Self::capacity(cwnd, mtu),
            bytes_per_ns: rate,
            ns_per_byte: pace,
            wait_nanos: 0,
        }
    }

    pub(crate) fn allows_send(&self, now: time::Instant) -> bool {
        self.updated_at.is_none_or(|updated| {
            now.saturating_duration_since(updated).as_nanos() >= u128::from(self.wait_nanos)
        })
    }

    pub(crate) fn release_at(&self) -> Option<time::Instant> {
        self.updated_at?
            .checked_add(time::Duration::from_nanos(self.wait_nanos))
    }

    /// Reprices existing credit at a feedback boundary. This is the only
    /// division-bearing path and is called after a complete ACK/loss batch.
    pub(crate) fn reconfigure(
        &mut self,
        now: time::Instant,
        cwnd: u64,
        srtt: time::Duration,
        mtu: u64,
    ) {
        let capacity = Self::capacity(cwnd, mtu);
        self.accrue(now, capacity);
        (self.bytes_per_ns, self.ns_per_byte) = Self::rate(cwnd, srtt);
        self.schedule(mtu);
    }

    pub(crate) fn packet_sent(&mut self, bytes: u64, now: time::Instant, cwnd: u64, mtu: u64) {
        self.accrue(now, Self::capacity(cwnd, mtu));
        self.credit = self.credit.saturating_sub(bytes);
        self.schedule(mtu);
    }

    fn accrue(&mut self, now: time::Instant, capacity: u64) {
        let Some(updated) = self.updated_at.replace(now) else {
            self.credit = self.credit.min(capacity);
            return;
        };
        let elapsed = now.saturating_duration_since(updated).as_nanos();
        if elapsed != 0 {
            let earned = elapsed.saturating_mul(u128::from(self.bytes_per_ns)) >> FIXED_SHIFT;
            self.credit = self
                .credit
                .saturating_add(earned.min(u128::from(u64::MAX)) as u64)
                .min(capacity);
        } else {
            self.credit = self.credit.min(capacity);
        }
    }

    fn schedule(&mut self, bytes: u64) {
        let missing = bytes.saturating_sub(self.credit);
        if missing == 0 {
            self.wait_nanos = 0;
            return;
        }
        let fixed = u128::from(missing).saturating_mul(u128::from(self.ns_per_byte));
        self.wait_nanos = ((fixed.saturating_add(FIXED_ONE - 1)) >> FIXED_SHIFT)
            .clamp(1, u128::from(u64::MAX)) as u64;
    }

    fn rate(cwnd: u64, srtt: time::Duration) -> (u64, u64) {
        let bytes = u128::from(cwnd)
            .saturating_mul(u128::from(RATE_NUMERATOR))
            .max(1);
        let nanos = srtt
            .as_nanos()
            .max(1)
            .saturating_mul(u128::from(RATE_DENOMINATOR));
        let (Some(bytes), Some(nanos)) = (
            num::NonZero::<u128>::new(bytes),
            num::NonZero::<u128>::new(nanos),
        ) else {
            return (1, u64::MAX);
        };
        let bytes = bytes.get();
        let nanos = nanos.get();
        let rate = (bytes.saturating_mul(FIXED_ONE) / nanos).clamp(1, u128::from(u64::MAX)) as u64;
        let pace = nanos
            .saturating_mul(FIXED_ONE)
            .div_ceil(bytes)
            .clamp(1, u128::from(u64::MAX)) as u64;
        (rate, pace)
    }

    const fn capacity(cwnd: u64, mtu: u64) -> u64 {
        let burst = mtu.saturating_mul(10);
        if cwnd < burst { cwnd } else { burst }
    }
}

const _: () = assert!(std::mem::size_of::<Pacer>() <= 48);
