use std::time;

pub(crate) struct WallClock(time::SystemTime);

impl WallClock {
    pub(crate) fn now() -> Self {
        Self(time::SystemTime::now())
    }

    pub(crate) fn now_millis() -> u64 {
        Self::now().millis()
    }

    pub(crate) fn millis(&self) -> u64 {
        self.saturating_epoch_duration().as_millis() as u64
    }

    pub(crate) fn unix_seconds(&self) -> u64 {
        self.saturating_epoch_duration().as_secs()
    }

    fn saturating_epoch_duration(&self) -> time::Duration {
        match self.0.duration_since(time::UNIX_EPOCH) {
            Ok(duration) => duration,
            Err(error) => {
                debug_assert_eq!(self.0 + error.duration(), time::UNIX_EPOCH);
                time::Duration::ZERO
            }
        }
    }
}
