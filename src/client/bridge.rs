use crate::runtime::brand;

use std::pin;

use o3::buffer::resident;

use dope::core::driver::schedule::clock;

use crate::client;
use crate::client::life;
use crate::client::protocol;
use crate::conn::{id, stream::Event};
use crate::runtime::{mux, routing};
use data::{datagram, stream};
use handler::hook;
use hook::life::{close, closing, create, ready};
use hook::{data, set, wire, writable};
use life::view;
use mux::handler;
use wire::{cert, endpoint, ingress, packet};
use writable::Interest as _;

#[pin_project::pin_project]
pub struct Bridge<'d, const DOMAIN: u8, P: protocol::Protocol<'d>, A, B, R: routing::PeerRoute> {
    #[pin]
    protocol: P,
    lifecycle: clock::Bound<'d, life::Lifecycle<'d, DOMAIN, A, B, R>>,
    writable: <P::Writable as writable::Interest>::State,
}

impl<'d, const DOMAIN: u8, P: protocol::Protocol<'d>, A, B: client::Backoff, R: routing::PeerRoute>
    Bridge<'d, DOMAIN, P, A, B, R>
{
    pub(super) fn new(
        protocol: P,
        life: clock::Bound<'d, life::Lifecycle<'d, DOMAIN, A, B, R>>,
    ) -> Self {
        Self {
            protocol,
            lifecycle: life,
            writable: P::Writable::EMPTY,
        }
    }

    pub(super) fn protocol(&self) -> &P {
        &self.protocol
    }

    pub(super) fn take(self: pin::Pin<&mut Self>) -> writable::Receipt {
        P::Writable::exchange(self.project().writable, writable::Receipt::Idle)
    }

    pub(super) fn protocol_pin(self: pin::Pin<&mut Self>) -> pin::Pin<&mut P> {
        self.project().protocol
    }

    pub(super) fn lifecycle(&self) -> view::View<'_, 'd, DOMAIN, A, B, R> {
        self.lifecycle.view()
    }

    pub(super) fn life_mut(self: pin::Pin<&mut Self>) -> &mut life::Lifecycle<'d, DOMAIN, A, B, R> {
        self.project().lifecycle
    }

    /// Completes resident lifecycle transitions and then invokes the matching
    /// pinned protocol callbacks. Both normal driver progress and shutdown use
    /// this one ordering auth.
    pub(super) fn drain_events(self: pin::Pin<&mut Self>, budget: usize) -> usize {
        brand::Token::with(|scope| self.drain_in(scope, budget))
    }

    fn drain_in(mut self: pin::Pin<&mut Self>, scope: brand::Token<'_>, budget: usize) -> usize {
        let mut left = budget;
        while left != 0 {
            let slot = {
                let this = self.as_mut().project();
                this.lifecycle.settle_close(scope.reborrow())
            };
            let Some(slot) = slot else { break };
            left -= 1;
            let this = self.as_mut().project();
            protocol::Protocol::close(this.protocol, slot);
        }
        while left != 0 {
            let slot = {
                let this = self.as_mut().project();
                this.lifecycle.settle_ready(scope.reborrow())
            };
            let Some(slot) = slot else { break };
            left -= 1;
            let this = self.as_mut().project();
            protocol::Protocol::connect(this.protocol, slot);
        }
        budget - left
    }
}

impl<'d, const DOMAIN: u8, P, A, B, R>
    handler::Handler<DOMAIN, P::Receive, resident::Shared<'d>, id::Driver<'d>>
    for Bridge<'d, DOMAIN, P, A, B, R>
where
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    R: routing::PeerRoute,
{
    type Connection = ();
    type Create = create::Unit;
    type Events = set::Set<
        set::On,
        set::On,
        set::On,
        set::Off,
        set::Off,
        set::Off,
        ingress::Off,
        packet::On,
        endpoint::Off,
        closing::On,
        close::On,
        <P::Writable as writable::Interest>::Hook<
            Self,
            DOMAIN,
            P::Receive,
            resident::Shared<'d>,
            id::Driver<'d>,
        >,
    >;
}

impl<'d, const DOMAIN: u8, P, A, B, R> cert::Sink<DOMAIN, id::Driver<'d>>
    for Bridge<'d, DOMAIN, P, A, B, R>
where
    P: protocol::Protocol<'d>,
    R: routing::PeerRoute,
{
    fn certificate(event: cert::Event<'_, '_, Self, DOMAIN, id::Driver<'d>>) {
        let (this, handle, from, failure) = event.into_parts();
        this.project().protocol.certificate(handle, from, failure);
    }
}

impl<'d, const DOMAIN: u8, P, A, B, R>
    packet::Sink<DOMAIN, P::Receive, resident::Shared<'d>, id::Driver<'d>>
    for Bridge<'d, DOMAIN, P, A, B, R>
where
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    R: routing::PeerRoute,
{
    fn packet(event: packet::Event<'_, Self>) {
        let (this, from, error, len) = event.into_parts();
        this.project().protocol.packet(from, error, len);
    }
}

impl<'d, const DOMAIN: u8, P, A, B, R>
    ready::Sink<DOMAIN, P::Receive, resident::Shared<'d>, id::Driver<'d>>
    for Bridge<'d, DOMAIN, P, A, B, R>
where
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    R: routing::PeerRoute,
{
    fn established(
        event: ready::Event<'_, Self, DOMAIN, P::Receive, resident::Shared<'d>, id::Driver<'d>>,
    ) {
        let (this, _, handle, _) = event.into();
        this.project().lifecycle.establish(handle);
    }
}

impl<'d, const DOMAIN: u8, P, A, B, R>
    datagram::Sink<DOMAIN, P::Receive, resident::Shared<'d>, id::Driver<'d>>
    for Bridge<'d, DOMAIN, P, A, B, R>
where
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    R: routing::PeerRoute,
{
    fn datagram(
        event: datagram::Event<'_, Self, DOMAIN, P::Receive, resident::Shared<'d>, id::Driver<'d>>,
    ) {
        let (this, slot, handle, data, _) = event.into();
        let scope = slot.brand();
        let this = this.project();
        if let Some(bound) = this.lifecycle.view().bind(scope, handle) {
            protocol::Protocol::datagram(this.protocol, bound, data);
        }
    }
}

impl<'d, const DOMAIN: u8, P, A, B, R>
    stream::Sink<DOMAIN, P::Receive, resident::Shared<'d>, id::Driver<'d>>
    for Bridge<'d, DOMAIN, P, A, B, R>
where
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    R: routing::PeerRoute,
{
    fn stream(
        event: stream::Event<'_, Self, DOMAIN, P::Receive, resident::Shared<'d>, id::Driver<'d>>,
    ) -> mux::Disposition {
        let (this, mut slot, handle, event, _) = event.into();
        let scope = slot.brand();
        let this = this.project();
        let Some(bound) = this.lifecycle.view().bind(scope, handle) else {
            return mux::Disposition::Accept;
        };
        let id = match event.event() {
            Event::Writable => {
                P::Writable::exchange(this.writable, writable::Receipt::Ready);
                return mux::Disposition::Accept;
            }
            Event::Readable { id } => id,
            event @ (Event::Reset { .. } | Event::Stopped { .. }) => {
                protocol::Protocol::stream_event(this.protocol, bound, event);
                return mux::Disposition::Accept;
            }
        };
        let mut streams = slot.transport().streams();
        let Ok(stream) = streams.view().resolve_recv(id) else {
            return mux::Disposition::Accept;
        };
        let data = streams.receive().recv_buffer(stream);
        let end = streams.view().is_recv_eof(stream);
        if data.is_none() && !end {
            return mux::Disposition::Accept;
        }
        protocol::Protocol::stream(this.protocol, bound, id, data, end);
        if end {
            mux::Disposition::Accept
        } else {
            mux::Disposition::Defer
        }
    }
}

impl<'d, const DOMAIN: u8, P, A, B, R>
    writable::Sink<DOMAIN, P::Receive, resident::Shared<'d>, id::Driver<'d>>
    for Bridge<'d, DOMAIN, P, A, B, R>
where
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    R: routing::PeerRoute,
{
    fn writable(self: pin::Pin<&mut Self>) {
        P::Writable::exchange(self.project().writable, writable::Receipt::Ready);
    }

    fn has_writable(&self) -> bool {
        P::Writable::is_pending(&self.writable)
    }

    fn clear(self: pin::Pin<&mut Self>) {
        P::Writable::exchange(self.project().writable, writable::Receipt::Idle);
    }
}

impl<'d, const DOMAIN: u8, P, A, B, R>
    close::Sink<DOMAIN, P::Receive, resident::Shared<'d>, id::Driver<'d>>
    for Bridge<'d, DOMAIN, P, A, B, R>
where
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    R: routing::PeerRoute,
{
    fn close(
        event: close::Event<'_, Self, DOMAIN, P::Receive, resident::Shared<'d>, id::Driver<'d>>,
    ) {
        let (this, close, (), handle) = event.into_parts();
        this.project()
            .lifecycle
            .close_at(close.brand(), handle, close.at());
    }
}

impl<'d, const DOMAIN: u8, P, A, B, R>
    closing::Sink<DOMAIN, P::Receive, resident::Shared<'d>, id::Driver<'d>>
    for Bridge<'d, DOMAIN, P, A, B, R>
where
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    R: routing::PeerRoute,
{
    fn closing(
        event: closing::Event<'_, Self, DOMAIN, P::Receive, resident::Shared<'d>, id::Driver<'d>>,
    ) {
        let (event, again) = event.into_saved();
        let (this, _, handle) = event.into();
        this.project().lifecycle.reconnect(handle, again);
    }
}
