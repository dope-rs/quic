use o3::buffer;
use std::time;

use crate::conn;
use crate::conn::output::transmit::permit::{self, earliest, fit};
use crate::stream;

/// Canonical scheduler projection for one connection.
pub(crate) fn deadline<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>(
    conn: &conn::Machine<DOMAIN, B, D>,
    now: time::Instant,
    send: bool,
) -> Option<time::Instant> {
    let retry = permit::Permit::new(conn).retry_at(now);
    deadline_with_retry(conn, now, send, retry)
}

/// Reuses the retry projection from this same connection's reconciliation.
pub(crate) fn deadline_with_retry<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>(
    conn: &conn::Machine<DOMAIN, B, D>,
    now: time::Instant,
    send: bool,
    retry: Option<time::Instant>,
) -> Option<time::Instant> {
    if conn.egress.lifecycle.state == crate::conn::State::Closed {
        return Some(now);
    }
    let permit = permit::Permit::new(conn);
    let recovery = fit::timer_deadline(&permit);
    let path = conn.path.output().deadline();
    let output = if send { permit.deadline(now) } else { None };
    let next = earliest(earliest(recovery, path), earliest(output, retry));
    earliest(next, conn.deadline())
}
