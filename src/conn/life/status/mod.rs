pub mod journal;
pub mod phase;
pub mod recovery;
pub mod routing;
pub(crate) mod schedule;

use crate::runtime::brand;

use std::{mem, time};

use o3::buffer::{self, resident};

use dope::core::driver::schedule::clock;

use crate::conn;
use crate::conn::output::transmit::permit;
use crate::conn::stream::access;
use crate::stream;

/// A read-only view of a connection for the lifetime of its borrow.
pub struct View<
    'conn,
    const DOMAIN: u8,
    B: stream::Recv = Vec<u8>,
    D: buffer::raw::Segment = resident::Shared<'conn>,
> {
    connection: &'conn conn::Machine<DOMAIN, B, D>,
}

/// Read-only endpoint inspection with no raw temporal output.
#[repr(transparent)]
pub struct Inspection<
    'conn,
    const DOMAIN: u8 = 0,
    B: stream::Recv = Vec<u8>,
    D: buffer::raw::Segment = resident::Shared<'conn>,
> {
    connection: &'conn conn::Machine<DOMAIN, B, D>,
}

/// Read-only state bound to one exact driver time domain.
/// Temporal output retains the driver identity as a deadline.
#[repr(C)]
pub struct TemporalView<
    'conn,
    'd,
    const DOMAIN: u8,
    B: stream::Recv = Vec<u8>,
    D: buffer::raw::Segment = resident::Shared<'conn>,
> {
    connection: &'conn conn::Machine<DOMAIN, B, D>,
    now: clock::Moment<'d>,
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> View<'conn, DOMAIN, B, D> {
    pub(in crate::conn) fn new(conn: &'conn conn::Machine<DOMAIN, B, D>) -> Self {
        Self { connection: conn }
    }

    pub fn lifecycle(&self) -> phase::State<'conn, DOMAIN, B, D> {
        phase::State::new(self.connection)
    }

    pub fn path(&self) -> routing::Path<'conn, DOMAIN, B, D> {
        routing::Path::new(self.connection)
    }

    pub fn recovery(&self) -> recovery::View<'conn, DOMAIN, B, D> {
        recovery::View::new(self.connection)
    }

    pub fn peer(&self) -> routing::Peer<'conn, DOMAIN, B, D> {
        routing::Peer::new(self.connection)
    }

    pub fn with_streams<R>(
        &self,
        read: impl for<'scope> FnOnce(access::View<'scope, 'scope, DOMAIN, B, D>) -> R,
    ) -> R {
        brand::Token::with_ref(self.connection, |brand, conn| {
            read(access::View::new(conn, brand))
        })
    }

    pub fn journal(&self) -> journal::Backing {
        journal::Backing::new(self.connection)
    }

    pub(crate) fn permit(&self) -> permit::Permit<'conn, DOMAIN, B, D> {
        permit::Permit::new(self.connection)
    }
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    Inspection<'conn, DOMAIN, B, D>
{
    pub(in crate::conn) fn new(conn: &'conn conn::Machine<DOMAIN, B, D>) -> Self {
        Self { connection: conn }
    }

    pub fn lifecycle(&self) -> phase::State<'conn, DOMAIN, B, D> {
        phase::State::new(self.connection)
    }

    /// Number of application DATAGRAM payloads queued for packet construction.
    pub fn tx_queued(&self) -> usize {
        self.connection.egress.datagrams.pending_datagrams.len()
    }

    pub fn recovery(&self) -> recovery::Metrics<'conn, DOMAIN, B, D> {
        recovery::Metrics::new(self.connection)
    }

    pub fn with_streams<R>(
        &self,
        read: impl for<'scope> FnOnce(access::View<'scope, 'scope, DOMAIN, B, D>) -> R,
    ) -> R {
        brand::Token::with_ref(self.connection, |brand, conn| {
            read(access::View::new(conn, brand))
        })
    }
}

impl<'conn, 'd, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    TemporalView<'conn, 'd, DOMAIN, B, D>
{
    pub(in crate::conn) fn new(
        conn: &'conn conn::Machine<DOMAIN, B, D>,
        now: clock::Moment<'d>,
    ) -> Self {
        Self {
            connection: conn,
            now,
        }
    }

    /// Earliest exact proto or app wakeup.
    pub fn deadline(&self) -> Option<clock::Deadline<'d>> {
        self.now
            .at(self.connection)
            .deadline(|conn, now| schedule::deadline(conn, now, true))
    }
}

const _: () = {
    assert!(mem::size_of::<View<'static, 0>>() == mem::size_of::<&conn::Machine<0, Vec<u8>>>());
    assert!(
        mem::size_of::<Inspection<'static, 0>>() == mem::size_of::<&conn::Machine<0, Vec<u8>>>()
    );
    assert!(!mem::needs_drop::<Inspection<'static, 0>>());
    assert!(
        mem::size_of::<TemporalView<'static, 'static, 0>>()
            == mem::size_of::<(&conn::Machine<0, Vec<u8>>, time::Instant)>()
    );
    assert!(!mem::needs_drop::<TemporalView<'static, 'static, 0>>());
};
