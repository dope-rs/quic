use dope::core::driver::schedule::app;
use std::{marker, pin, time};

use o3::buffer::resident;

use crate::conn::id;
use crate::runtime::routing::Plain;
use crate::stream;

use crate::runtime::mux::{self, auth, handler, manage, router};

enum Step {
    Advanced,
    Idle,
}

#[repr(transparent)]
pub struct Shutdown<
    'a,
    'tls,
    H,
    const DOMAIN: u8,
    B = Vec<u8>,
    A = auth::Pooled<'tls, Plain, id::Static>,
> where
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
    A: auth::Mode<DOMAIN>,
{
    mux: pin::Pin<&'a mut router::Router<H, DOMAIN, B, A>>,
    lifetime: marker::PhantomData<&'tls ()>,
}

impl<
    'a,
    'tls,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
    A: auth::Mode<DOMAIN>,
> Shutdown<'a, 'tls, H, DOMAIN, B, A>
{
    pub(crate) fn new(mux: pin::Pin<&'a mut router::Router<H, DOMAIN, B, A>>) -> Self {
        Self {
            mux,
            lifetime: marker::PhantomData,
        }
    }

    pub(crate) fn bounded_at(&mut self, now: time::Instant) -> manage::Status {
        self.begin();
        for _ in 0..mux::DIRECT_DRIVE_BUDGET {
            if matches!(self.step_inner(now), Step::Idle) {
                break;
            }
        }
        if self.is_complete() {
            manage::Status::Complete
        } else {
            manage::Status::Pending
        }
    }

    pub(crate) fn begin(&mut self) {
        let state = self.mux.as_mut().project().state;
        if state.lifecycle.shutting_down {
            return;
        }
        state.lifecycle.shutting_down = true;
        state.lifecycle.cursor.reset();
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.mux.as_ref().get_ref().is_done()
    }

    fn step_inner(&mut self, now: time::Instant) -> Step {
        let mut mux = router::Turn::new(self.mux.as_mut());
        let entries = mux.registry.capacity();
        if let Some(index) = mux.lifecycle.cursor.advance(entries) {
            mux.remove_at(index, now);
            return Step::Advanced;
        }
        if mux.outgoing.pop_front().is_some() {
            return Step::Advanced;
        }
        if mux.outgoing.cache.recycled.pop().is_some() {
            return Step::Advanced;
        }
        if mux.outgoing.cache.batch.take().is_some() {
            return Step::Advanced;
        }
        Step::Idle
    }
}

impl<
    'a,
    'tls,
    'd,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
    A: auth::Mode<DOMAIN, Send = resident::Shared<'d>>,
> Shutdown<'a, 'tls, H, DOMAIN, B, A>
{
    pub(crate) fn step<'turn>(&mut self, permit: app::Permit<'turn, 'd>, now: time::Instant) {
        permit.run(|| {
            if self.mux.as_ref().get_ref().state.lifecycle.shutting_down {
                self.step_inner(now);
            }
        });
    }
}
