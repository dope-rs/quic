use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) struct WallClock(SystemTime);

impl WallClock {
    pub(crate) fn now() -> Self {
        Self(SystemTime::now())
    }

    pub(crate) fn now_millis() -> u64 {
        Self::now().millis()
    }

    pub(crate) fn millis(&self) -> u64 {
        self.0
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0)
    }

    pub(crate) fn unix_seconds(&self) -> u64 {
        self.0
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }
}
