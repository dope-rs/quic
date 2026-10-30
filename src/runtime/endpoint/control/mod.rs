use crate::conn::life;
use crate::conn::life::tls::clients;
use crate::conn::scope;
use crate::conn::{id, output::transmit};
use crate::errors;
use crate::proto::datagram;
use crate::proto::param;
use crate::runtime::endpoint;
use crate::runtime::endpoint::owner;
use crate::runtime::endpoint::reactor::buffers;
use crate::runtime::mux::app;
use crate::runtime::mux::manage;
use crate::runtime::mux::protocol;
use crate::runtime::mux::protocol::control::Control as _;
use crate::runtime::mux::router::observed;
use crate::runtime::mux::{handler, router};
use crate::runtime::receive::Storage;
use crate::runtime::routing;
use crate::stream;
use dope::core::driver::schedule::clock;
use dope::core::io::datagram::Residency;
use dope::manifold::app::dispatch;
use life::options;
use life::status;
use manage::config;
use o3::buffer::resident;
use o3::buffer::{self, Residency as _};
use o3::mem;
use std::{net, num, pin, time};

pub(crate) mod actions;
pub(crate) mod conn;

#[repr(transparent)]
pub struct Control<
    'step,
    'd,
    const ID: u8,
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv = Vec<u8>,
    A = endpoint::Idle,
    M = owner::Owned,
    Q: buffer::Residency + buffer::raw::Source = datagram::Sealed<'d>,
> where
    'd: 'step,
    B: Storage<'d, resident::Shared<'d>>,
    M: owner::Binding<'d, ID>,
{
    endpoint: dispatch::raw::Installed<'step, 'd, endpoint::Endpoint<'d, ID, H, B, A, M, Q>>,
}

/// Failure to acquire the endpoint's single pooled-output position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    Full,
    Closed,
}

/// Exclusive pooled-output admission retaining its endpoint and clock sample.
#[must_use = "a sender retains one vacant endpoint output position"]
pub struct Sender<
    'a,
    'd,
    const ID: u8,
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv = Vec<u8>,
    M: owner::Binding<'d, ID> = owner::Owned,
    Q: buffer::Residency + buffer::raw::Source = datagram::Sealed<'d>,
> {
    slot: buffers::Vacant<'a, Q, endpoint::Interest<'d, H, ID, B>>,
    mux: pin::Pin<&'a mut router::Router<H, ID, B, M::Mode>>,
    now: time::Instant,
}

impl<'a, 'd, const ID: u8, H, B, M, Q> Sender<'a, 'd, ID, H, B, M, Q>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv,
    M: owner::Binding<'d, ID>,
    Q: buffer::Residency + buffer::raw::Source,
{
    pub(super) fn new(
        slot: buffers::Vacant<'a, Q, endpoint::Interest<'d, H, ID, B>>,
        mux: pin::Pin<&'a mut router::Router<H, ID, B, M::Mode>>,
        now: time::Instant,
    ) -> Self {
        Self { slot, mux, now }
    }

    pub fn handler(&self) -> &H {
        self.mux.as_ref().get_ref().handler()
    }

    pub(crate) fn close(&mut self, handle: id::Handle<id::Driver<'d>, ID>) {
        protocol::Io::new(self.mux.as_mut()).close_at(handle, self.now);
    }
}

impl<'pool, 'd, const ID: u8, H, B, M> Sender<'_, 'd, ID, H, B, M, datagram::Sealed<'pool>>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv,
    M: owner::Binding<'d, ID>,
{
    pub fn try_send(
        mut self,
        handle: id::Handle<id::Driver<'d>, ID>,
        packet: datagram::Packet<'pool>,
    ) -> Result<(), mem::Rejected<Self, errors::SendFailure<datagram::Packet<'pool>>>> {
        use crate::runtime::mux::protocol::dgram::Dgram as _;

        let maximum = self.mux.as_mut().output().byte_limit();
        if let Some(required) =
            num::NonZero::new(packet.resident()).filter(|required| required.get() > maximum)
        {
            let cause = datagram::Error::Resident { required, maximum };
            return Err(mem::Rejected::new(
                self,
                errors::SendFailure::Admission(packet, transmit::Admission::Datagram(cause)),
            ));
        }
        let (addr, packet) =
            match protocol::Io::new(self.mux.as_mut()).try_packet(handle, packet, self.now) {
                Ok(sent) => sent,
                Err(cause) => return Err(mem::Rejected::new(self, cause)),
            };
        self.slot.insert((addr, buffers::Entry { packet }));
        Ok(())
    }
}

/// Endpoint mutations bound to one sampled driver turn.
#[repr(transparent)]
pub struct Turn<'turn, 'd, C: ?Sized>(clock::At<'d, &'turn mut C>);

impl<'step, 'd, const ID: u8, H, B, A, M, Q: buffer::Residency + buffer::raw::Source>
    Control<'step, 'd, ID, H, B, A, M, Q>
where
    'd: 'step,
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    M: owner::Binding<'d, ID>,
{
    pub(super) fn new(
        inner: dispatch::raw::Installed<'step, 'd, endpoint::Endpoint<'d, ID, H, B, A, M, Q>>,
    ) -> Self {
        Self { endpoint: inner }
    }

    pub fn at<'turn>(&'turn mut self, clock: clock::Clock<'turn, 'd>) -> Turn<'turn, 'd, Self>
    where
        'step: 'turn,
    {
        Turn(clock.at(self))
    }

    pub fn handler(&self) -> &H {
        self.endpoint.as_ref().get_ref().handler()
    }

    pub fn len(&self) -> usize {
        self.endpoint.as_ref().get_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_sealed(&self) -> bool {
        self.endpoint.as_ref().get_ref().is_sealed()
    }

    #[doc(hidden)]
    pub fn residency(&self) -> Option<Residency> {
        self.endpoint.as_ref().get_ref().residency()
    }

    pub fn seal(&mut self) {
        self.endpoint.as_mut().seal();
    }

    pub fn sole(&self) -> Option<id::Handle<id::Driver<'d>, ID>> {
        self.endpoint.as_ref().get_ref().sole()
    }

    pub fn inspect<R>(
        &self,
        handle: id::Handle<id::Driver<'d>, ID>,
        read: impl for<'scope> FnOnce(
            &'scope H,
            &'scope H::Connection,
            status::Inspection<'scope, ID, B, resident::Shared<'d>>,
        ) -> R,
    ) -> Option<R> {
        self.endpoint.as_ref().get_ref().inspect(handle, read)
    }

    pub fn enable_gso(&mut self) -> Result<(), manage::GsoError> {
        self.endpoint
            .as_mut()
            .project()
            .udp
            .handler_mut()
            .config()
            .enable_gso()
    }

    pub fn disable_gso(&mut self) {
        self.endpoint
            .as_mut()
            .project()
            .udp
            .handler_mut()
            .config()
            .disable_gso();
    }

    /// Rejects future early data while retaining native resumption tickets.
    pub fn reject_early(&mut self) -> Result<(), config::TlsError> {
        self.endpoint
            .as_mut()
            .project()
            .udp
            .handler_mut()
            .config()
            .reject_early()
    }

    pub fn reconfigure(&mut self, config: rustls::ServerConfig) -> Result<(), config::TlsError> {
        self.endpoint
            .as_mut()
            .project()
            .udp
            .handler_mut()
            .config()
            .reconfigure(config)
    }
}

impl<'step, 'd, const ID: u8, H, B, A, M, Q: buffer::Residency + buffer::raw::Source>
    Control<'step, 'd, ID, H, B, A, M, Q>
where
    'd: 'step,
    H: endpoint::raw::Control<'d, ID, B>,
    B: Storage<'d, resident::Shared<'d>>,
    M: owner::Binding<'d, ID>,
{
    pub fn view(&mut self) -> H::View<'_> {
        let app = self.endpoint.project(|ep| ep.handler_mut());
        H::view(app)
    }

    /// Lends the handler and connection access for the same driver turn.
    pub fn split<'v, T, R>(
        &'v mut self,
        clock: clock::Clock<'v, 'd>,
        mut op: impl for<'scope> FnMut(scope::Temporal<'scope, 'd, ID, B, resident::Shared<'d>>, T) -> R
        + 'v,
    ) -> (
        H::View<'v>,
        impl FnMut(id::Handle<id::Driver<'d>, ID>, T) -> protocol::control::Result<R> + 'v,
    ) {
        let (app, call) = self.endpoint.project_with(|ep| {
            let mux = ep.project().udp.handler_mut().mux_mut().project();
            (mux.handler, move |handle, value| {
                let now = clock.now();
                mux.state.with(handle, now.into_raw(), |scope| {
                    op(scope::Temporal::new(scope, now), value)
                })
            })
        });
        (H::view(app), call)
    }
}

impl<'turn, 'step, 'd, const ID: u8, H, B, A, M, Q: buffer::Residency + buffer::raw::Source>
    Turn<'turn, 'd, Control<'step, 'd, ID, H, B, A, M, Q>>
where
    'd: 'step,
    'step: 'turn,
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    M: owner::Binding<'d, ID>,
{
    pub fn connect(
        &mut self,
        peer: net::SocketAddr,
        auth: &clients::Authority,
        params: param::Set,
        dcid: Vec<u8>,
    ) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Connect> {
        self.connect_with(peer, auth, options::Options::try_from(params)?, dcid)
    }

    pub fn connect_with(
        &mut self,
        peer: net::SocketAddr,
        auth: &clients::Authority,
        config: options::Options,
        dcid: Vec<u8>,
    ) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Connect> {
        self.0.apply_mut(|ctl, now| {
            conn::connect_with_config(ctl.endpoint.as_mut(), peer, auth, config, dcid, now)
        })
    }

    pub fn reconnect<R: routing::PeerRoute>(
        &mut self,
        config: options::Options,
        again: life::Reconnect,
        route: R,
    ) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Reconnect> {
        self.0
            .apply_mut(|ctl, now| conn::reconnect(ctl.endpoint.as_mut(), config, again, route, now))
    }

    pub fn with_conn<R>(
        &mut self,
        handle: id::Handle<id::Driver<'d>, ID>,
        op: impl for<'scope> FnOnce(scope::Temporal<'scope, 'd, ID, B, resident::Shared<'d>>) -> R,
    ) -> Result<R, errors::Access> {
        self.0
            .apply_mut(|ctl, now| actions::with_connection(ctl.endpoint.as_mut(), handle, now, op))
    }

    /// Lends the exact app connection and its proto auth in
    /// one branded observation. Neither capability can escape the callback.
    pub fn with_app<R>(
        &mut self,
        handle: id::Handle<id::Driver<'d>, ID>,
        op: impl for<'scope> FnOnce(
            app::Connection<'scope, H::Connection, ID, B, resident::Shared<'d>, id::Driver<'d>>,
        ) -> R,
    ) -> Result<R, errors::Access> {
        self.0.apply_mut(|ctl, now| {
            ctl.endpoint
                .as_mut()
                .project()
                .udp
                .handler_mut()
                .mux_mut()
                .observe(now, |mut turn| turn.with_app(handle, op))
        })
    }

    pub fn try_datagram(
        &mut self,
        handle: id::Handle<id::Driver<'d>, ID>,
        data: Vec<u8>,
    ) -> Result<(), errors::SendFailure<Vec<u8>>> {
        self.0.apply_mut(|ctl, now| {
            actions::try_send_datagram(ctl.endpoint.as_mut(), handle, data, now.into_raw())
        })
    }

    pub fn try_close(
        &mut self,
        handle: id::Handle<id::Driver<'d>, ID>,
    ) -> Result<(), errors::Access> {
        self.0.apply_mut(|ctl, now| {
            protocol::Io::new(ctl.endpoint.as_mut().project().udp.handler_mut().mux_mut())
                .try_close_at(handle, now.into_raw())
        })
    }

    pub fn quiesce<R>(
        &mut self,
        run: impl for<'mux, 'observation> FnOnce(
            Result<observed::Observed<'mux, 'observation, M::Mode, H, ID, B, true>, observed::Open>,
        ) -> R,
    ) -> R {
        self.0.apply_mut(|ctl, now| {
            ctl.endpoint
                .as_mut()
                .project()
                .udp
                .handler_mut()
                .mux_mut()
                .observe(now, |observed| run(observed.try_quiesce()))
        })
    }
}

impl<'turn, 'step, 'd, 'tls, const ID: u8, H, B, R, Q: buffer::Residency + buffer::raw::Source>
    Turn<'turn, 'd, Control<'step, 'd, ID, H, B, endpoint::Idle, owner::Pooled<'tls, R>, Q>>
where
    'd: 'step,
    'step: 'turn,
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    R: routing::LocalRoute,
{
    pub fn pool_connect(
        &mut self,
        peer: net::SocketAddr,
        pool: &'tls clients::Pool,
        params: param::Set,
        dcid: Vec<u8>,
    ) -> Result<id::Handle<id::Driver<'d>, ID>, errors::Connect> {
        self.0.apply_mut(|ctl, now| {
            conn::connect_pooled(ctl.endpoint.as_mut(), peer, pool, params, dcid, now)
        })
    }
}

impl<'turn, 'step, 'pool, 'd, const ID: u8, H, B, A, M>
    Turn<'turn, 'd, Control<'step, 'd, ID, H, B, A, M, datagram::Sealed<'pool>>>
where
    'd: 'step,
    'step: 'turn,
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    M: owner::Binding<'d, ID>,
{
    /// Acquires one output position before selecting a connection.
    pub fn try_sender(
        self,
    ) -> Result<Sender<'turn, 'd, ID, H, B, M, datagram::Sealed<'pool>>, SendError> {
        self.0
            .apply(|ctl, now| actions::try_sender(ctl.endpoint.as_mut(), now))
    }

    pub fn try_pooled(
        &mut self,
        handle: id::Handle<id::Driver<'d>, ID>,
        packet: datagram::Packet<'pool>,
    ) -> Result<(), errors::SendFailure<datagram::Packet<'pool>>> {
        self.0.apply_mut(|ctl, now| {
            let sender = match actions::try_sender(ctl.endpoint.as_mut(), now.into_raw()) {
                Ok(sender) => sender,
                Err(SendError::Full) => return Err(errors::SendFailure::Full(packet)),
                Err(SendError::Closed) => return Err(errors::SendFailure::Closed(packet)),
            };
            sender
                .try_send(handle, packet)
                .map_err(mem::Rejected::discard)
        })
    }
}
