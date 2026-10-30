#![deny(unsafe_code)]

pub mod app;
#[doc(hidden)]
pub mod auth;
pub mod builder;
pub mod handler;
pub mod manage;
pub mod output;
pub mod protocol;
pub mod router;

/// Settlement of one leased stream notification.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Accept,
    Defer,
}

pub(crate) const DEFAULT_MAX_CONNS: usize = 1024;
pub(crate) const DEFAULT_OUTGOING_CAP: usize = 4096;
pub(crate) const DEFAULT_OUTGOING_BYTES_CAP: usize = 16 << 20;
pub(crate) const MAX_CONNECTIONS: usize = 65_536;
pub(crate) const MAX_OUTGOING_CAPACITY: usize = 65_536;
pub(crate) const MAX_OUTGOING_BYTES: usize = 1 << 30;
pub(crate) const FLUSH_PACKET_QUANTUM: usize = 8;
pub(in crate::runtime::mux) const FLUSH_BYTE_QUANTUM: usize = 64 << 10;
pub(in crate::runtime::mux) const DIRECT_DRIVE_BUDGET: usize = 256;
pub(in crate::runtime) const NOTIFY_QUEUE: usize = 0;
pub(in crate::runtime) const FLUSH_QUEUE: usize = 1;
pub(in crate::runtime) const REAP_QUEUE: usize = 2;
pub(in crate::runtime) const APPLICATION_QUEUE: usize = 3;
pub(in crate::runtime) const FREE_QUEUE: usize = 4;
pub(in crate::runtime) const QUEUE_PLANES: usize = 5;
