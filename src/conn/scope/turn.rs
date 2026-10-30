use o3::buffer;
use std::time;

use crate::{conn, stream};
use conn::life::status;
use conn::scope;
use conn::stream::access;
use scope::path;

/// Time auth for one deterministic standalone mux turn.
#[repr(C)]
pub struct Turn<'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    inner: scope::Access<'conn, DOMAIN, B, true, D>,
    now: time::Instant,
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Turn<'conn, DOMAIN, B, D> {
    pub(crate) fn new(inner: scope::Access<'conn, DOMAIN, B, true, D>, now: time::Instant) -> Self {
        Self { inner, now }
    }

    pub(crate) fn into_tracked(self) -> scope::Access<'conn, DOMAIN, B, true, D> {
        self.inner
    }

    pub fn streams(&mut self) -> access::Streams<'_, 'conn, DOMAIN, B, true, D> {
        self.inner.streams()
    }

    pub fn path(&mut self) -> path::Path<'_, DOMAIN, B, true, D> {
        self.inner.path()
    }

    pub fn lifecycle(&mut self) -> scope::Life<'_, DOMAIN, B, true, D> {
        self.inner.lifecycle()
    }

    pub fn security(&mut self) -> scope::Security<'_, DOMAIN, B, true, D, time::Instant> {
        scope::Security::raw(self.inner.machine, self.now)
    }

    pub fn view(&self) -> status::View<'_, DOMAIN, B, D> {
        self.inner.view()
    }
}
