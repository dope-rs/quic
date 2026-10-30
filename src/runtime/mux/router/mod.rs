use crate::{
    conn::{self, id},
    runtime::{
        brand,
        mux::{self, auth, handler, manage, output},
    },
    stream,
};
use dope::core::driver::schedule::{app, clock};
use handler::{
    hook::{
        set::{Dispatch, Socket as _},
        wire::socket,
    },
    net,
};
use manage::config;
use o3::{
    alloc,
    depot::{capacity, heap, queue::indexed::planes},
};
pub(in crate::runtime::mux) use records::AddressProof;
pub(in crate::runtime::mux) use state::{Binding, Flush, State};
use std::{ops, pin, time};
pub(in crate::runtime::mux) use turn::Turn;

pub(crate) mod drive;
pub mod observed;
mod records;
pub(in crate::runtime) mod reset;
pub(in crate::runtime) mod routing;
mod state;
mod turn;

/// Exact failure to allocate the router's resident indices.
#[derive(Debug)]
pub enum Error {
    Entries {
        capacity: capacity::Limit<{ mux::MAX_CONNECTIONS }>,
        error: alloc::Error,
    },
    Cids {
        capacity: capacity::Limit<{ mux::MAX_CONNECTIONS }>,
        error: alloc::Error,
    },
    Reset {
        capacity: capacity::Limit<{ mux::MAX_CONNECTIONS }>,
        error: alloc::Error,
    },
    Deadlines(heap::Error<capacity::Limit<{ mux::MAX_CONNECTIONS }>>),
}

impl From<planes::Error<capacity::Limit<{ mux::MAX_CONNECTIONS }>>> for Error {
    fn from(error: planes::Error<capacity::Limit<{ mux::MAX_CONNECTIONS }>>) -> Self {
        match error {
            planes::Error::Values { capacity, error } => Self::Entries { capacity, error },
            planes::Error::Heap(error) => Self::Deadlines(error),
        }
    }
}

#[pin_project::pin_project]
#[doc(hidden)]
pub struct Router<
    H,
    const DOMAIN: u8 = 0,
    B: stream::Recv = Vec<u8>,
    A: auth::Mode<DOMAIN> = auth::Owned,
> where
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
{
    pub(in crate::runtime) state: State<A, H::Connection, DOMAIN, B>,
    #[pin]
    pub(in crate::runtime) handler: H,
}

impl<
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
> Router<H, DOMAIN, B, A>
{
    pub fn config<'a, 'tls>(
        self: pin::Pin<&'a mut Self>,
    ) -> config::Config<'a, 'tls, H, DOMAIN, B, A> {
        config::Config::new(self)
    }

    pub fn output<'a, 'tls>(
        self: pin::Pin<&'a mut Self>,
    ) -> output::Queue<'a, 'tls, H, DOMAIN, B, A> {
        output::Queue::new(self)
    }

    pub fn active_conns(&self) -> usize {
        self.state.registry.len()
    }

    #[doc(hidden)]
    pub const fn domain(&self) -> id::Domain<A::Identity, DOMAIN> {
        self.state.domain()
    }

    pub fn seal(self: pin::Pin<&mut Self>) {
        self.project().state.lifecycle.admission_closed = true;
    }

    pub fn is_sealed(&self) -> bool {
        self.state.lifecycle.admission_closed
    }

    pub(crate) fn has_output(&self) -> bool {
        !self.state.outgoing.pending.is_empty()
    }

    pub fn sole(&self) -> Option<id::Handle<A::Identity, DOMAIN>> {
        self.state.registry.sole(self.state.binding.domain)
    }

    pub fn handler(&self) -> &H {
        &self.handler
    }

    pub fn handler_mut(self: pin::Pin<&mut Self>) -> pin::Pin<&mut H> {
        self.project().handler
    }

    pub fn conn(
        &self,
        handle: id::Handle<A::Identity, DOMAIN>,
    ) -> Option<&conn::Connection<DOMAIN, B, A::Send>> {
        self.state
            .registry
            .get(self.state.binding.domain, handle)
            .map(|slot| &slot.conn)
    }

    pub fn inspect<R>(
        &self,
        handle: id::Handle<A::Identity, DOMAIN>,
        read: impl FnOnce(&H, &H::Connection, &conn::Connection<DOMAIN, B, A::Send>) -> R,
    ) -> Option<R> {
        let slot = self.state.registry.get(self.state.binding.domain, handle)?;
        Some(read(&self.handler, &slot.connection, &slot.conn))
    }

    pub fn observe<'mux, R>(
        self: pin::Pin<&'mux mut Self>,
        now: <A::Identity as id::Temporal>::Observation,
        apply: impl for<'observation> FnOnce(
            observed::Observed<'mux, 'observation, A, H, DOMAIN, B>,
        ) -> R,
    ) -> R
    where
        A::Identity: id::Temporal,
    {
        brand::Token::with(|brand| apply(observed::Observed::new(self, now, brand)))
    }

    pub(crate) fn is_done(&self) -> bool {
        self.state.lifecycle.shutting_down
            && self
                .state
                .lifecycle
                .cursor
                .is_complete(self.state.registry.capacity())
            && self.state.outgoing.pending.is_empty()
            && self.state.outgoing.cache.recycled.is_empty()
            && self.state.outgoing.cache.batch.is_none()
    }

    pub(crate) fn drive_net<'turn, 'd>(
        self: pin::Pin<&mut Self>,
        permit: app::Permit<'turn, 'd>,
        now: clock::Moment<'d>,
    ) where
        A: auth::Mode<DOMAIN, Identity = id::Driver<'d>>,
    {
        permit.run(|| {
            let mut turn = Turn::new(self);
            if let Err(error) = drive::drive_one(&mut turn, now) {
                let handle = *error.connection();
                <H::Events as Dispatch<H, DOMAIN, B, A::Send, id::Driver<'d>>>::Socket::call(
                    || socket::Event::new(turn.handler.as_mut(), net::Event::Transmit(error)),
                );
                let _ = turn.try_remove(handle, Into::<time::Instant>::into(now));
            }
        });
    }

    /// Stops at runnable work, retaining its exact deadline for observations.
    pub(crate) fn schedule(
        &self,
        now: time::Instant,
    ) -> ops::ControlFlow<time::Instant, Option<time::Instant>> {
        let registry = &self.state.registry;
        if !registry.is_empty_in::<{ mux::NOTIFY_QUEUE }>()
            || !registry.is_empty_in::<{ mux::REAP_QUEUE }>()
            || (!registry.is_empty_in::<{ mux::FLUSH_QUEUE }>()
                && self.state.outgoing.pending.len() < self.state.outgoing.pending.capacity()
                && self.state.outgoing.pending.bytes() < self.state.outgoing.bytes_capacity)
        {
            return ops::ControlFlow::Break(now);
        }
        let Some(at) = registry.deadline() else {
            return ops::ControlFlow::Continue(None);
        };
        if at <= now {
            ops::ControlFlow::Break(at)
        } else {
            ops::ControlFlow::Continue(Some(at))
        }
    }
}
