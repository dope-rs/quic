use crate::runtime::endpoint::control::actions;

use std::net;
use std::ops;
use std::pin;
use std::time;

use o3::buffer::resident;

use dope::core::driver::{route, schedule::clock};
use dope::core::io;
use dope::manifold::app::dispatch::{self, event};
use dope::runtime::executor;

use crate::client;
use crate::client::auth;
use crate::client::build;
use crate::client::protocol;
use crate::conn::scope;
use crate::errors;
use crate::proto::datagram;
use crate::runtime::endpoint::{self, owner};
use crate::runtime::routing;

mod engine;
pub(super) use engine::Engine;

pub(super) enum Connection {
    Current(client::SlotId),
    Attempt(client::AttemptId),
}

/// Pinned client retaining its packet pool, driver, and TLS owners.
///
/// A pooled auth cannot be widened to `'static`:
///
/// Retained packets cannot outlive their pool:
#[pin_project::pin_project]
pub struct Dialer<
    'pool,
    'd,
    const ID: u8,
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    A: auth::Mode = auth::Owned,
    C: client::ConfigSource = client::StaticConfig,
    R: routing::PeerRoute = routing::Plain,
> where
    A::Binding: owner::Binding<'d, ID>,
{
    #[pin]
    pub(super) inner: Engine<'pool, 'd, ID, P, B, A, C, R>,
    pub(super) limits: build::WorkLimits,
}

impl<'pool, 'd, const ID: u8, P, B, A, C, R> dispatch::raw::Projection<'d>
    for Dialer<'pool, 'd, ID, P, B, A, C, R>
where
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    A: auth::Mode,
    A::Binding: owner::Binding<'d, ID>,
    C: client::ConfigSource,
    R: routing::PeerRoute,
    endpoint::Endpoint<
        'd,
        ID,
        client::Bridge<'d, ID, P, A, B, R>,
        P::Receive,
        endpoint::Idle,
        A::Binding,
        datagram::Sealed<'pool>,
    >: dispatch::raw::Manifold<'d>,
{
    type Inner = endpoint::Endpoint<
        'd,
        ID,
        client::Bridge<'d, ID, P, A, B, R>,
        P::Receive,
        endpoint::Idle,
        A::Binding,
        datagram::Sealed<'pool>,
    >;

    fn inner(self: pin::Pin<&Self>) -> pin::Pin<&Self::Inner> {
        self.project_ref().inner.project_ref().endpoint
    }

    fn inner_mut(self: pin::Pin<&mut Self>) -> pin::Pin<&mut Self::Inner> {
        self.project().inner.project().endpoint
    }
}

impl<'pool, 'd, const ID: u8, P, B, A, C, R> event::Drive<'d>
    for Dialer<'pool, 'd, ID, P, B, A, C, R>
where
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    A: auth::Mode,
    A::Binding: owner::Binding<'d, ID>,
    C: client::ConfigSource,
    R: routing::PeerRoute,
    Self: dispatch::raw::Projection<'d>,
    <Self as dispatch::raw::Projection<'d>>::Inner: event::Drive<'d, Access = dispatch::raw::Plain>
        + dispatch::raw::Manifold<
            'd,
            Route = route::KeyTag<ID>,
            PrePark = dispatch::raw::Retained,
            Shutdown = dispatch::raw::Plain,
        >,
{
    type Access = dispatch::raw::Plain;

    fn dispatch<'app, 'driver, 'root>(
        call: executor::raw::Call<
            'app,
            Self,
            (),
            (
                io::Event<'d>,
                dispatch::raw::Context<'driver, 'root, 'd, Self::Access>,
            ),
        >,
    ) -> ops::ControlFlow<io::Event<'d>>
    where
        'd: 'root,
    {
        event::Drive::dispatch(call.map_owner(|owner| owner.project().inner.project().endpoint))
    }
}

impl<'pool, 'd, const ID: u8, P, B, A, C, R> Dialer<'pool, 'd, ID, P, B, A, C, R>
where
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    A: auth::Mode,
    A::Binding: owner::Binding<'d, ID>,
    C: client::ConfigSource,
    R: routing::PeerRoute,
{
    pub fn protocol(&self) -> &P {
        self.inner.endpoint.handler().protocol()
    }

    pub(super) fn protocol_mut(self: pin::Pin<&mut Self>) -> pin::Pin<&mut P> {
        self.project()
            .inner
            .project()
            .endpoint
            .handler_mut()
            .protocol_pin()
    }

    pub fn local_addr(&self) -> net::SocketAddr {
        self.inner.endpoint.local_addr()
    }

    pub fn len(&self) -> usize {
        self.inner.endpoint.handler().lifecycle().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_connected(&self, slot: client::SlotId) -> bool {
        self.inner
            .endpoint
            .handler()
            .lifecycle()
            .handle(slot)
            .is_some()
    }

    pub fn smoothed_rtt(&self, slot: client::SlotId) -> Option<time::Duration> {
        let handle = self.inner.endpoint.handler().lifecycle().handle(slot)?;
        self.inner.endpoint.conn(handle)?.recovery().smoothed_rtt()
    }

    pub fn path_stats(&self, slot: client::SlotId) -> Option<client::PathStats> {
        let handle = self.inner.endpoint.handler().lifecycle().handle(slot)?;
        let conn = self.inner.endpoint.conn(handle)?;
        Some(client::PathStats {
            srtt: conn.recovery().smoothed_rtt(),
            min_rtt: conn.recovery().min_rtt(),
            cwnd: conn.recovery().window(),
            bytes_in_flight: conn.recovery().in_flight(),
        })
    }

    pub fn active_len(&self) -> usize {
        self.inner.endpoint.len()
    }

    /// Exact endpoint slots whose current generation completed protocol
    /// establishment. This deliberately differs from physical mux connection
    /// count during handshakes and reconnect teardown.
    pub fn live_len(&self) -> usize {
        self.inner.endpoint.handler().lifecycle().live()
    }

    /// Closes every retained generation at one driver-branded observation.
    /// This direct pinned-owner surface is used during forced shutdown, where
    /// no generated coordination control exists.
    pub fn close_all(self: pin::Pin<&mut Self>, now: clock::Moment<'d>) {
        now.at(self)
            .apply(|dialer, now| dialer.project().inner.close_at(now));
    }

    pub fn seal(self: pin::Pin<&mut Self>) {
        self.project()
            .inner
            .project()
            .endpoint
            .handler_mut()
            .life_mut()
            .seal();
    }

    /// Closes the whole logical endpoint set while leaving reconnect
    /// admission open. Multipath applications use this to rotate every path
    /// into one new app generation after any constituent path fails.
    pub(super) fn restart_all(self: pin::Pin<&mut Self>, now: clock::Moment<'d>) {
        now.at(self)
            .apply(|dialer, now| dialer.project().inner.restart_at(now));
    }

    pub(super) fn try_send(
        self: pin::Pin<&mut Self>,
        slot: client::SlotId,
        data: Vec<u8>,
        now: clock::Moment<'d>,
    ) -> Result<(), errors::SendFailure<Vec<u8>>> {
        now.at(self)
            .apply(|dialer, raw| dialer.project().inner.try_send_at(slot, data, raw))
    }

    pub(super) fn with_conn<T>(
        self: pin::Pin<&mut Self>,
        target: Connection,
        now: clock::Moment<'d>,
        op: impl for<'scope> FnOnce(
            scope::Temporal<'scope, 'd, ID, P::Receive, resident::Shared<'d>>,
        ) -> T,
    ) -> Result<T, errors::Access> {
        let life = self.as_ref().get_ref().inner.endpoint.handler().lifecycle();
        let handle = match target {
            Connection::Current(slot) => life.handle(slot).ok_or(errors::Access::Closed)?,
            Connection::Attempt(attempt) => {
                let Some((current, handle)) = life.current(attempt.slot()) else {
                    return Err(errors::Access::Closed);
                };
                if current != attempt {
                    return Err(errors::Access::InvalidHandle);
                }
                handle
            }
        };
        actions::with_connection(self.project().inner.project().endpoint, handle, now, op)
    }

    pub(super) fn try_packet(
        self: pin::Pin<&mut Self>,
        slot: client::SlotId,
        packet: datagram::Packet<'pool>,
        now: clock::Moment<'d>,
    ) -> Result<(), errors::SendFailure<datagram::Packet<'pool>>> {
        now.at(self)
            .apply(|dialer, raw| dialer.project().inner.try_pool_at(slot, packet, raw))
    }
}
