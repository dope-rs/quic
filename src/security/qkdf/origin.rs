//! Sender provenance for traffic secrets and packet keys.

/// Absolute client sender at the Initial KDF boundary.
pub struct Client;

/// Absolute server sender at the Initial KDF boundary.
pub struct Server;

/// Connection-relative local sender.
pub struct Local;

/// Connection-relative peer sender.
pub struct Peer;
