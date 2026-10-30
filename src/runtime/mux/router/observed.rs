use std::{net, ops, pin, time};

use dope::core::driver::schedule::clock;
use dope::manifold::network::datagram::packet::{Packet, Retainer};
use dope::runtime;
use o3::buffer::storage::provided::Mutable;
use runtime::civil;

use crate::conn::life;
use crate::{
    conn, errors,
    proto::{cid, epoch},
    runtime::{brand, mux, receive, routing},
    stream,
};
use app::{Selected as _, Set as _};
use conn::{id, scope};
use control::Control as _;
use dgram::Dgram as _;
use dial::{direct, pooled};
use direct::Direct as _;
use handler::{
    hook::{
        set,
        wire::{cert, ingress, packet},
    },
    net::Ingress,
};
use life::{options, tls};
use mux::{app, auth, handler, manage, output, protocol, router};
use protocol::{control, dgram, dial, recv, rotation};
use recv::Recv as _;
use rotation::Local as _;
use router::routing::issuer;
use scope::path;
use stream::retain;
use tls::clients;

/// Lexical observation coupling one pinned router borrow to one exact instant.
/// Its invariant brand prevents subviews from crossing observation boundaries.
#[repr(C)]
pub struct Observed<
    'mux,
    'observation,
    A,
    H,
    const DOMAIN: u8,
    B: stream::Recv = Vec<u8>,
    const SEALED: bool = false,
> where
    A: auth::Mode<DOMAIN>,
    A::Identity: id::Temporal,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
{
    mux: pin::Pin<&'mux mut router::Router<H, DOMAIN, B, A>>,
    observed_at: <A::Identity as id::Temporal>::Observation,
    brand: brand::Token<'observation>,
}

/// Admission remains open in the observed endpoint.
pub struct Open;

impl<'mux, 'observation, A, H, const DOMAIN: u8, B> Observed<'mux, 'observation, A, H, DOMAIN, B>
where
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
    A::Identity: id::Temporal,
{
    pub(super) fn new(
        mux: pin::Pin<&'mux mut router::Router<H, DOMAIN, B, A>>,
        seen: <A::Identity as id::Temporal>::Observation,
        brand: brand::Token<'observation>,
    ) -> Self {
        Self {
            mux,
            observed_at: seen,
            brand,
        }
    }

    /// An ordinary observation cannot close every generation.
    pub fn try_quiesce(self) -> Result<Observed<'mux, 'observation, A, H, DOMAIN, B, true>, Open> {
        let state = &self.mux.as_ref().get_ref().state;
        if !state.lifecycle.admission_closed {
            return Err(Open);
        }
        Ok(self.closed())
    }

    pub fn seal(mut self) -> Observed<'mux, 'observation, A, H, DOMAIN, B, true> {
        self.mux.as_mut().seal();
        self.closed()
    }

    fn closed(self) -> Observed<'mux, 'observation, A, H, DOMAIN, B, true> {
        Observed {
            mux: self.mux,
            observed_at: self.observed_at,
            brand: self.brand,
        }
    }

    /// Returns the next deadline relative to this exact observation.
    pub fn deadline(&self) -> Option<time::Instant> {
        match self
            .mux
            .as_ref()
            .schedule(Into::<time::Instant>::into(self.observed_at))
        {
            ops::ControlFlow::Break(at) => Some(at),
            ops::ControlFlow::Continue(at) => at,
        }
    }

    /// Borrows the time-dependent output plane for this observation.
    pub fn output(&mut self) -> Output<'_, 'observation, A, H, DOMAIN, B> {
        Output {
            queue: self.mux.as_mut().output(),
            observed_at: self.observed_at,
            _brand: self.brand,
        }
    }

    /// Borrows the time-dependent protocol plane for this observation.
    pub fn protocol(&mut self) -> Protocol<'_, 'observation, A, H, DOMAIN, B> {
        Protocol {
            io: protocol::Io::new(self.mux.as_mut()),
            now: Into::<time::Instant>::into(self.observed_at),
            brand: self.brand,
        }
    }

    /// Runs one exact app/proto txn for a live connection.
    /// The generative slot capability cannot escape this observation.
    pub fn with_app<R>(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
        op: impl for<'scope> FnOnce(
            app::Connection<'scope, H::Connection, DOMAIN, B, A::Send, A::Identity>,
        ) -> R,
    ) -> Result<R, errors::Access> {
        let mut turn = router::Turn::new(self.mux.as_mut());
        app::execute(
            &mut turn,
            Into::<time::Instant>::into(self.observed_at),
            |turn| {
                let conns = turn.into_parts().1;
                match conns.try_select(handle) {
                    Ok(chosen) => Ok(chosen.run(op)),
                    Err(reject) => Err(reject.discard()),
                }
            },
        )
    }

    /// Advances the endpoint-wide CID rotation schedule with this turn's
    /// exact observation and protocol auth.
    pub fn maintain_cid(&mut self, plan: &mut cid::Schedule) -> cid::Progress {
        plan.maintain_at(
            Into::<time::Instant>::into(self.observed_at),
            &mut protocol::Io::new(self.mux.as_mut()),
        )
    }

    /// Anchors a CID-rotation schedule to this observation's time domain.
    pub fn plan_cid(&self, next: cid::Rotation) -> cid::Schedule {
        next.schedule_at(Into::<time::Instant>::into(self.observed_at))
    }
}

impl<'mux, 'observation, A, H, const DOMAIN: u8, B, const SEALED: bool>
    Observed<'mux, 'observation, A, H, DOMAIN, B, SEALED>
where
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
    A::Identity: id::Temporal,
{
    /// Borrows the time-dependent shutdown plane for this observation.
    pub fn lifecycle(&mut self) -> Lifecycle<'_, 'observation, A, H, DOMAIN, B> {
        Lifecycle {
            shutdown: manage::Shutdown::new(self.mux.as_mut()),
            now: Into::<time::Instant>::into(self.observed_at),
            _brand: self.brand,
        }
    }
}

impl<A, H, const DOMAIN: u8, B> Observed<'_, '_, A, H, DOMAIN, B, true>
where
    A: auth::Mode<DOMAIN>,
    A::Identity: id::Temporal,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
{
    pub fn close_all(&mut self) -> usize {
        router::Turn::new(self.mux.as_mut()).clear(Into::<time::Instant>::into(self.observed_at))
    }

    pub fn handler(&self) -> &H {
        self.mux.as_ref().get_ref().handler()
    }

    pub fn len(&self) -> usize {
        self.mux.as_ref().get_ref().active_conns()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'mux, 'observation, 'd, A, H, const DOMAIN: u8, B>
    Observed<'mux, 'observation, A, H, DOMAIN, B>
where
    A: auth::Mode<DOMAIN, Identity = id::Driver<'d>>,
    id::Driver<'d>: id::Temporal<Observation = clock::Moment<'d>>,
    H: handler::Handler<DOMAIN, B, A::Send, id::Driver<'d>>,
    B: receive::Input<'d, A::Send>,
{
    pub(in crate::runtime) fn receive<'turn, Q, W, T: Mutable<'d, Account: retain::Retain<'d>>>(
        &mut self,
        from: net::SocketAddr,
        input: Packet<'turn, 'd, T>,
        keep: Retainer<'d>,
    ) -> W::Output
    where
        H::Events: set::Dispatch<H, DOMAIN, B, A::Send, id::Driver<'d>, Ingress = Q, Packet = W>,
        Q: ingress::Mode<H, DOMAIN, B, A::Send, id::Driver<'d>>,
        W: packet::Mode<H, DOMAIN, B, A::Send, id::Driver<'d>>,
        H: cert::Sink<DOMAIN, id::Driver<'d>>,
    {
        let len = input.len();
        let now = Into::<time::Instant>::into(self.observed_at);
        let result = B::recv(
            &mut protocol::Io::new(self.mux.as_mut()),
            from,
            input,
            keep,
            now,
        );
        let app = self.mux.as_mut().handler_mut();
        let seen = self.observed_at;
        let result = Q::finish(result, || {
            ingress::Event::new(app, Ingress::new(from, len, seen))
        });
        let app = self.mux.as_mut().handler_mut();
        W::finish(result, |error| packet::Event::new(app, from, error, len))
    }
}

/// Shutdown auth borrowed from one [`Observed`] turn.
pub struct Lifecycle<'mux, 'observation, A, H, const DOMAIN: u8, B>
where
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
{
    shutdown: manage::Shutdown<'mux, 'mux, H, DOMAIN, B, A>,
    now: time::Instant,
    _brand: brand::Token<'observation>,
}

impl<'mux, 'observation, A, H, const DOMAIN: u8, B> Lifecycle<'mux, 'observation, A, H, DOMAIN, B>
where
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
{
    pub fn advance(&mut self) -> manage::Status {
        self.shutdown.bounded_at(self.now)
    }
}

/// Output auth borrowed from one [`Observed`] turn.
pub struct Output<'mux, 'observation, A, H, const DOMAIN: u8, B>
where
    A: auth::Mode<DOMAIN>,
    A::Identity: id::Temporal,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
{
    queue: output::Queue<'mux, 'mux, H, DOMAIN, B, A>,
    observed_at: <A::Identity as id::Temporal>::Observation,
    _brand: brand::Token<'observation>,
}

impl<'mux, 'observation, A, H, const DOMAIN: u8, B> Output<'mux, 'observation, A, H, DOMAIN, B>
where
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
    A::Identity: id::Temporal,
{
    pub fn drive(&mut self) -> Result<usize, errors::Transmit<A::Identity, DOMAIN>> {
        self.queue.drive_at(self.observed_at)
    }

    /// Returns one fully consumed flight to this mux's packet pool.
    pub fn recycle(&mut self, flight: output::Flight) {
        self.queue.recycle(flight);
    }

    pub fn drain(self) -> impl Iterator<Item = output::Flight> + 'mux + use<'mux, A, H, DOMAIN, B> {
        self.queue.drain()
    }
}

/// Protocol auth borrowed from one [`Observed`] turn.
pub struct Protocol<'mux, 'observation, A, H, const DOMAIN: u8, B>
where
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
{
    io: protocol::Io<'mux, 'mux, H, DOMAIN, B, A>,
    now: time::Instant,
    brand: brand::Token<'observation>,
}

impl<'mux, 'observation, A, H, const DOMAIN: u8, B> Protocol<'mux, 'observation, A, H, DOMAIN, B>
where
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
{
    pub fn connect(
        &mut self,
        peer: net::SocketAddr,
        auth: &clients::Authority,
        opts: options::Options,
        dcid: Vec<u8>,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Connect> {
        self.io.connect(peer, auth, opts, dcid, self.now)
    }

    pub fn connect_with<R: routing::PeerRoute>(
        &mut self,
        peer: net::SocketAddr,
        auth: &clients::Authority,
        opts: options::Options,
        route: R,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Connect> {
        self.io.connect_with(peer, auth, opts, route, self.now)
    }

    pub fn reconnect<R: routing::PeerRoute>(
        &mut self,
        opts: options::Options,
        again: life::Reconnect,
        route: R,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Reconnect> {
        self.io.reconnect(opts, again, route, self.now)
    }

    pub fn recv<S>(
        &mut self,
        from: net::SocketAddr,
        data: &mut [u8],
        epoch: epoch::Sample<S>,
    ) -> Result<(), errors::Receive>
    where
        S: civil::Source,
        B: stream::Recv,
        H: cert::Sink<DOMAIN, A::Identity>,
    {
        self.io.recv_input(from, data, (), self.now, epoch)
    }

    pub fn with_conn<R>(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
        op: impl for<'scope> FnOnce(scope::Turn<'scope, DOMAIN, B, A::Send>) -> R,
    ) -> Result<R, errors::Access> {
        self.io.with(handle, self.now, op)
    }

    pub fn rotate_cid(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
    ) -> Result<path::Rotation, errors::Access> {
        self.io.rotate(handle, self.now)
    }

    pub fn try_datagram(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
        data: Vec<u8>,
    ) -> Result<(), errors::SendFailure<Vec<u8>>> {
        self.io.try_send(handle, data, self.now)
    }

    pub fn try_close(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
    ) -> Result<(), errors::Access> {
        self.io.try_close_at(handle, self.now)
    }
}

impl<'mux, 'observation, 'tls, H, const DOMAIN: u8, B, Route, E>
    Protocol<'mux, 'observation, auth::Pooled<'tls, Route, E>, H, DOMAIN, B>
where
    H: handler::Handler<DOMAIN, B, E::Send, E::Identity>,
    B: stream::Recv,
    Route: routing::LocalRoute,
    E: issuer::Binding,
{
    pub fn pool_connect(
        &mut self,
        peer: net::SocketAddr,
        pool: &'tls clients::Pool,
        opts: options::Options,
        dcid: Vec<u8>,
    ) -> Result<id::Handle<E::Identity, DOMAIN>, errors::Connect> {
        use crate::wire::packet::cid::Id;
        use pooled::Pooled;

        let dcid = Id::try_from(dcid)?;
        Pooled::connect_in(&mut self.io, self.brand, peer, pool, opts, dcid, self.now)
    }
}
