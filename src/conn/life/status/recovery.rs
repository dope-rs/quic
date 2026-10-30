use std::{mem, time};

use o3::buffer::{self, resident};

use crate::conn::output::transmit::permit::{self, fit};
use crate::conn::{self, Epoch};
use crate::stream;

#[repr(transparent)]
pub struct View<
    'conn,
    const DOMAIN: u8,
    B: stream::Recv = Vec<u8>,
    D: buffer::raw::Segment = resident::Shared<'conn>,
> {
    connection: &'conn conn::Machine<DOMAIN, B, D>,
}

/// Non-temporal recovery metrics safe for endpoint inspection.
#[repr(transparent)]
pub struct Metrics<
    'conn,
    const DOMAIN: u8 = 0,
    B: stream::Recv = Vec<u8>,
    D: buffer::raw::Segment = resident::Shared<'conn>,
> {
    inner: View<'conn, DOMAIN, B, D>,
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> View<'conn, DOMAIN, B, D> {
    pub(crate) fn new(conn: &'conn conn::Machine<DOMAIN, B, D>) -> Self {
        Self { connection: conn }
    }

    pub fn next_timer(&self) -> Option<time::Instant> {
        fit::timer_deadline(&permit::Permit::new(self.connection))
    }

    pub fn send_at(&self, ready_at: time::Instant) -> time::Instant {
        match self
            .connection
            .egress
            .cc
            .release()
            .or(self.connection.egress.activity.last_activity)
        {
            Some(at) => at.max(ready_at),
            None => ready_at,
        }
    }

    pub fn window(&self) -> u64 {
        self.connection.egress.cc.metrics().window()
    }

    pub fn in_flight(&self) -> u64 {
        self.connection
            .egress
            .recovery
            .in_flight()
            .unwrap_or(u64::MAX)
    }

    pub fn slow_limit(&self) -> u64 {
        self.connection.egress.cc.metrics().slow_limit()
    }

    pub fn unacked(&self, space: Epoch) -> usize {
        self.connection
            .egress
            .recovery
            .packet_journals
            .space(space)
            .count()
    }

    pub fn smoothed_rtt(&self) -> Option<time::Duration> {
        self.connection.egress.recovery.rtt.smoothed_rtt
    }

    pub fn min_rtt(&self) -> Option<time::Duration> {
        self.connection.egress.recovery.rtt.min_rtt
    }
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    Metrics<'conn, DOMAIN, B, D>
{
    pub(crate) fn new(conn: &'conn conn::Machine<DOMAIN, B, D>) -> Self {
        Self {
            inner: View::new(conn),
        }
    }

    pub fn window(&self) -> u64 {
        self.inner.window()
    }

    pub fn in_flight(&self) -> u64 {
        self.inner.in_flight()
    }

    pub fn slow_limit(&self) -> u64 {
        self.inner.slow_limit()
    }

    pub fn unacked(&self, space: Epoch) -> usize {
        self.inner.unacked(space)
    }

    pub fn smoothed_rtt(&self) -> Option<time::Duration> {
        self.inner.smoothed_rtt()
    }

    pub fn min_rtt(&self) -> Option<time::Duration> {
        self.inner.min_rtt()
    }
}

const _: () = {
    assert!(mem::size_of::<View<'static, 0>>() == mem::size_of::<&conn::Machine<0, Vec<u8>>>());
    assert!(mem::size_of::<Metrics<'static, 0>>() == mem::size_of::<&conn::Machine<0, Vec<u8>>>());
    assert!(!mem::needs_drop::<Metrics<'static, 0>>());
};
