use dope::core::driver::schedule::clock;
use o3::buffer;

use crate::{conn, stream};
use conn::life::{datagram, status};
use conn::scope;
use conn::stream::access;
use scope::path;

/// Connection auth bound to one exact driver observation.
#[repr(C)]
pub struct Temporal<'conn, 'd, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    inner: scope::Access<'conn, DOMAIN, B, true, D>,
    now: clock::Moment<'d>,
}

impl<'conn, 'd, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    Temporal<'conn, 'd, DOMAIN, B, D>
{
    pub(crate) fn new(
        inner: scope::Access<'conn, DOMAIN, B, true, D>,
        now: clock::Moment<'d>,
    ) -> Self {
        Self { inner, now }
    }

    pub fn streams(&mut self) -> access::Streams<'_, 'conn, DOMAIN, B, true, D> {
        self.inner.streams()
    }

    pub fn datagrams(&mut self) -> datagram::Datagrams<'_, DOMAIN, B, true, D> {
        self.inner.datagrams()
    }

    pub fn path(&mut self) -> path::Path<'_, DOMAIN, B, true, D> {
        self.inner.path()
    }

    pub fn lifecycle(&mut self) -> scope::Life<'_, DOMAIN, B, true, D> {
        self.inner.lifecycle()
    }

    pub fn security(&mut self) -> scope::Security<'_, DOMAIN, B, true, D, clock::Moment<'d>> {
        scope::Security {
            machine: self.inner.machine,
            time: self.now,
        }
    }

    pub fn view(&self) -> status::TemporalView<'_, 'd, DOMAIN, B, D> {
        status::TemporalView::new(self.inner.machine, self.now)
    }
}
