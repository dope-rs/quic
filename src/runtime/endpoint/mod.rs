use crate::wire::packet::long::retry;
use std::{marker, mem, net, ops, pin};

use dope::{
    core::{
        driver::{
            self, route,
            schedule::{self, clock},
            settings::{self, claim, errors::Claim},
        },
        io::{self, datagram::Residency},
    },
    manifold::{
        app::{
            creation,
            dispatch::{self, event},
        },
        network::datagram::{self, hook, plan},
    },
    runtime::executor,
};
use o3::{
    base::cell::region,
    buffer::{self, resident},
};
pub use run::Run;
use schedule::ready::task::owner::Capacity;
use settings::demands;

use crate::{
    conn::{id, life::status},
    errors,
    proto::{
        cid,
        datagram::{Sealed, Size},
    },
    runtime::{
        mux::{
            auth, builder,
            handler::{
                self,
                hook::{
                    set::{self, Dispatch},
                    wire::{cert, packet},
                    writable,
                },
            },
        },
        receive::{self, Storage},
    },
    stream,
};

pub mod client;
pub mod config;
pub mod owner;
pub mod raw;
pub mod server;

pub mod control;
pub mod reactor;
mod run;

/// The handler's socket policy applies to both transport and application scheduling.
type Socket<'d, const ID: u8, H, B> = <<H as handler::Handler<
    ID,
    B,
    resident::Shared<'d>,
    id::Driver<'d>,
>>::Events as Dispatch<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::Socket;

type Interest<'d, H, const ID: u8, B> =
    <<<H as handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>>::Events as Dispatch<
        H,
        ID,
        B,
        resident::Shared<'d>,
        id::Driver<'d>,
    >>::Writable as writable::Mode<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::Interest;

/// Datagram ownership and the engine share exactly one driver and packet residency.
type Transport<'d, const ID: u8, H, B, A, M, Q> =
    datagram::Endpoint<'d, route::KeyTag<ID>, reactor::Engine<'d, H, ID, B, A, M, Q>, Payload<Q>>;

/// QUIC send storage carried through the driver's generic datagram owner.
#[derive(Debug)]
pub enum Payload<Q> {
    Pooled(Q),
    Retry(retry::Suffix),
}

impl<Q: AsRef<[u8]>> AsRef<[u8]> for Payload<Q> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Pooled(packet) => packet.as_ref(),
            Self::Retry(packet) => packet.as_ref(),
        }
    }
}

impl<Q: buffer::Residency> buffer::Residency for Payload<Q> {
    fn resident(&self) -> usize {
        match self {
            Self::Pooled(packet) => packet.resident(),
            Self::Retry(packet) => packet.resident(),
        }
    }
}

const _: () = {
    assert!(size_of::<Payload<Sealed<'static>>>() == 4 * size_of::<usize>());
    assert!(
        size_of::<datagram::send::Payload<'static, 'static, Payload<Sealed<'static>>>>()
            == 4 * size_of::<usize>()
    );
};

/// Binding retains the selected receive storage, packet residency, and exact failure.
type Bound<'d, const ID: u8, H, R, A = Idle, M = owner::Owned, Q = Sealed<'d>, E = BindError> =
    Result<Endpoint<'d, ID, H, <R as receive::Policy>::Buffer<'d>, A, M, Q>, E>;

/// Failure while validating an owned endpoint plan.
#[derive(Debug)]
pub enum PlanError {
    Config(config::Error),
    Connection(errors::Connect),
}

/// Failure while binding an already validated endpoint to one driver.
#[derive(Debug)]
pub enum BindError {
    Connection(errors::Connect),
    Mux(builder::Failure),
    Datagram(creation::Error),
}

/// Preserves a caller's app-construction failure at the endpoint seam.
#[derive(Debug)]
pub enum BindFailure<E> {
    Application(E),
    Endpoint(BindError),
}

/// Endpoint execution with no app scheduler.
pub struct Idle {
    work: reactor::NetGraph,
}

impl Idle {
    fn new() -> Self {
        Self {
            work: reactor::NetGraph::new(),
        }
    }
}

impl<'d, const ID: u8, H, B, M, Q>
    hook::Schedule<'d, route::KeyTag<ID>, reactor::Engine<'d, H, ID, B, Idle, M, Q>> for Idle
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    M: auth::Mode<ID, Send = resident::Shared<'d>, Identity = id::Driver<'d>>,
    Q: buffer::Residency + buffer::raw::Source,
    H: cert::Sink<ID, id::Driver<'d>>,
    <H::Events as Dispatch<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::Packet:
        packet::Mode<H, ID, B, resident::Shared<'d>, id::Driver<'d>, Output = ()>,
{
    type Plan<'turn> = <<Socket<'d, ID, H, B> as set::Socket<
        H,
        ID,
        B,
        resident::Shared<'d>,
        id::Driver<'d>,
    >>::Transport<'d, ID, reactor::Engine<'d, H, ID, B, Idle, M, Q>> as hook::Schedule<
        'd,
        route::KeyTag<ID>,
        reactor::Engine<'d, H, ID, B, Idle, M, Q>,
    >>::Plan<'turn>;

    fn select<'turn>(clock: clock::Clock<'turn, 'd>) -> Option<Self::Plan<'turn>> {
        <<Socket<'d, ID, H, B> as set::Socket<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::Transport<'d, ID, reactor::Engine<'d, H, ID, B, Idle, M, Q>> as hook::Schedule<'d, route::KeyTag<ID>, reactor::Engine<'d, H, ID, B, Idle, M, Q>>>::select(clock)
    }

    fn progress(
        endpoint: pin::Pin<&Transport<'d, ID, H, B, Idle, M, Q>>,
        plan: Self::Plan<'_>,
        token: &region::Token<region::Identity<'d, 1>>,
    ) -> schedule::Progress<'d> {
        <<Socket<'d, ID, H, B> as set::Socket<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::Transport<'d, ID, reactor::Engine<'d, H, ID, B, Idle, M, Q>> as hook::Schedule<'d, route::KeyTag<ID>, reactor::Engine<'d, H, ID, B, Idle, M, Q>>>::progress(endpoint, plan, token)
    }
}

/// Validated, receive-typed resources for exactly one endpoint route.
#[must_use = "an endpoint plan must be consumed by one endpoint binding"]
pub struct Plan<const ID: u8, R: receive::Policy> {
    config: config::Validated,
    datagram: plan::Plan<route::KeyTag<ID>>,
    receive: marker::PhantomData<fn() -> R>,
}

impl<const ID: u8, R: receive::Policy> Plan<ID, R> {
    pub fn new(config: config::Config) -> Result<Self, config::Error> {
        let (config, datagram, slots) = config.validated()?.into_parts();
        let datagram = if <R::Buffer<'_> as Storage<'_>>::RETAINS {
            datagram.retain_slots(slots)
        } else {
            datagram
        };
        let datagram = plan::Plan::new(datagram);
        Ok(Self {
            config,
            datagram,
            receive: marker::PhantomData,
        })
    }

    pub const fn len(&self) -> usize {
        self.config.connections()
    }

    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    const fn owners(&self) -> Capacity {
        self.config.capacity().owners()
    }

    const fn mux(&self) -> builder::Plan {
        self.config.capacity()
    }

    pub(crate) const fn packet(&self) -> Size {
        self.config.packet()
    }

    fn prepare<'d, Q: buffer::Residency + buffer::raw::Source>(
        self,
        driver: &mut driver::Context<'_, 'd>,
    ) -> Result<owner::Prepared<'d, ID, R, Q>, BindError> {
        let Self {
            config, datagram, ..
        } = self;
        let datagram = datagram.prepare(driver).map_err(BindError::Datagram)?;
        let rotation = config.cid_rotation(driver);
        Ok(owner::Prepared {
            config,
            datagram,
            rotation,
            receive: marker::PhantomData,
        })
    }
}

impl<const ID: u8, R: receive::Policy> settings::Resource for Plan<ID, R> {
    fn include_in(&self, needs: claim::Needs) -> Result<claim::Needs, Claim> {
        let slots = self.owners().into();
        let claim = self
            .datagram
            .claim()
            .receive(self.config.receive().into())
            .schedule(demands::Schedule::new(slots, slots));
        needs.include(claim)
    }
}

/// A driver-bound endpoint retaining the pool lifetime of queued packets.
#[pin_project::pin_project]
pub struct Endpoint<
    'd,
    const ID: u8,
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv = Vec<u8>,
    A = Idle,
    M = owner::Owned,
    Q: buffer::Residency + buffer::raw::Source = Sealed<'d>,
> where
    M: owner::Binding<'d, ID>,
{
    #[pin]
    pub(in crate::runtime::endpoint) udp: Transport<'d, ID, H, B, A, M::Mode, Q>,
    pub(in crate::runtime::endpoint) packet: Size,
    pub(in crate::runtime::endpoint) rotation: clock::Bound<'d, cid::Schedule>,
}

impl<'d, const ID: u8, H, B, A, M, Q: buffer::Residency + buffer::raw::Source>
    executor::raw::Finishes<'d, Self> for Endpoint<'d, ID, H, B, A, M, Q>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    M: owner::Binding<'d, ID>,
    Transport<'d, ID, H, B, A, M::Mode, Q>: dispatch::raw::Manifold<'d>,
{
    fn call<'app, 'finish, 'owner, 'epoch>(
        finish: executor::raw::Finish<'app, 'finish, 'owner, 'epoch, 'd, Self>,
    ) -> executor::raw::Finish<'app, 'finish, 'owner, 'epoch, 'd, Self> {
        let (mut owner, install, proof) = finish.into_parts();
        let this = owner.as_mut().project();
        this.rotation.seal();
        let child = executor::raw::Finish::new(this.udp, install, proof);
        let child = <<Transport<'d, ID, H, B, A, M::Mode, Q> as dispatch::raw::Manifold<'d>>::Finish as executor::raw::Finishes<'d, _>>::call(
            child
        );
        let (install, proof) = child.into_finish();
        executor::raw::Finish::new(owner, install, proof)
    }
}

impl<'d, const ID: u8, H, B, A, M, Q: buffer::Residency + buffer::raw::Source>
    dispatch::raw::Projection<'d> for Endpoint<'d, ID, H, B, A, M, Q>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    M: owner::Binding<'d, ID>,
    Transport<'d, ID, H, B, A, M::Mode, Q>: dispatch::raw::Manifold<'d>,
{
    type Inner = Transport<'d, ID, H, B, A, M::Mode, Q>;

    fn inner(self: pin::Pin<&Self>) -> pin::Pin<&Self::Inner> {
        self.project_ref().udp
    }

    fn inner_mut(self: pin::Pin<&mut Self>) -> pin::Pin<&mut Self::Inner> {
        self.project().udp
    }
}

impl<'d, const ID: u8, H, B, A, M, Q: buffer::Residency + buffer::raw::Source> event::Drive<'d>
    for Endpoint<'d, ID, H, B, A, M, Q>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    M: owner::Binding<'d, ID>,
    Transport<'d, ID, H, B, A, M::Mode, Q>: event::Drive<'d, Access = dispatch::raw::Plain>,
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
        event::Drive::dispatch(call.map_owner(|owner| owner.project().udp))
    }
}

impl<'d, const ID: u8, H, B, A, M, Q: buffer::Residency + buffer::raw::Source>
    Endpoint<'d, ID, H, B, A, M, Q>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    M: owner::Binding<'d, ID>,
{
    pub fn local_addr(&self) -> net::SocketAddr {
        self.udp.local_addr()
    }

    #[doc(hidden)]
    pub fn residency(&self) -> Option<Residency> {
        self.udp.residency()
    }

    pub fn handler(&self) -> &H {
        self.udp.handler().mux.handler()
    }

    pub fn len(&self) -> usize {
        self.udp.handler().mux.active_conns()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn packet(&self) -> Size {
        self.packet
    }

    pub fn is_sealed(&self) -> bool {
        self.udp.handler().mux.is_sealed()
    }

    pub fn seal(self: pin::Pin<&mut Self>) {
        self.project().udp.handler_mut().mux_mut().seal();
    }

    pub fn sole(&self) -> Option<id::Handle<id::Driver<'d>, ID>> {
        self.udp.handler().mux.sole()
    }

    pub(crate) fn conn<'a>(
        &'a self,
        handle: id::Handle<id::Driver<'d>, ID>,
    ) -> Option<status::Inspection<'a, ID, B, resident::Shared<'d>>> {
        let conn = self.udp.handler().mux.conn(handle)?;
        Some(conn.inspection())
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
        self.udp
            .handler()
            .mux
            .inspect(handle, |handler, app, conn| {
                read(handler, app, conn.inspection())
            })
    }

    pub(crate) fn handler_mut(self: pin::Pin<&mut Self>) -> pin::Pin<&mut H> {
        self.project().udp.handler_mut().handler_mut()
    }
}

const _: () = {
    assert!(
        mem::size_of::<Plan<0, receive::Copied>>()
            == mem::size_of::<(config::Validated, plan::Plan<route::KeyTag<0>>)>()
    );
    assert!(
        mem::align_of::<Plan<0, receive::Copied>>()
            == mem::align_of::<(config::Validated, plan::Plan<route::KeyTag<0>>)>()
    );
    assert!(mem::size_of::<Plan<0, receive::Copied>>() < mem::size_of::<config::Validation>());
    assert!(
        mem::size_of::<Plan<0, receive::Copied>>() == mem::size_of::<Plan<0, receive::Retained>>()
    );
    assert!(
        mem::size_of::<owner::Prepared<'static, 0, receive::Copied, Sealed<'static>>>()
            == mem::size_of::<owner::Prepared<'static, 0, receive::Retained, Sealed<'static>>>()
    );
};
