//! TLS-owned, lane-local 0-RTT replay auth.

pub type ReplayCap = o3::depot::capacity::Limit<{ 1 << 16 }>;
