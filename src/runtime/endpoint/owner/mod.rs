use crate::runtime::endpoint::Payload;
use dope::core::driver::route;
pub mod pool;

use std::{marker, mem, net};

use o3::buffer::{self, resident};

use crate::conn::id;
use crate::runtime::mux::{
    auth, handler,
    handler::hook::{
        set::Dispatch,
        wire::{cert, packet},
    },
};
use crate::runtime::routing;

/// Connection-local TLS auth owned by an endpoint.
#[derive(Clone, Copy, Default)]
pub struct Owned;

/// External TLS auth borrowed for exactly `'tls`.
#[derive(Clone, Copy, Default)]
pub struct Pooled<'tls, R = routing::Plain> {
    lifetime: marker::PhantomData<&'tls ()>,
    route: marker::PhantomData<fn() -> R>,
}

#[doc(hidden)]
pub trait Binding<'d, const ID: u8> {
    type Mode: auth::Mode<ID, Send = resident::Shared<'d>, Identity = id::Driver<'d>>;
}

impl<'d, const ID: u8> Binding<'d, ID> for Owned {
    type Mode = auth::Owned<routing::Plain, id::Driver<'d>>;
}

impl<'d, 'tls, R, const ID: u8> Binding<'d, ID> for Pooled<'tls, R>
where
    R: routing::LocalRoute,
{
    type Mode = auth::Pooled<'tls, R, id::Driver<'d>>;
}

const _: () = assert!(mem::size_of::<Pooled<'static>>() == 0);

use crate::proto::cid;
use crate::runtime::endpoint::{BindError, Bound, Endpoint, config, reactor};
use crate::runtime::receive;
use dope::core::{
    driver::{self, schedule::clock},
    io::datagram::Lease,
};
use dope::manifold::network::datagram;

/// Driver-bound endpoint resources awaiting their one socket binding.
#[must_use = "prepared endpoint resources must be consumed by one binding"]
pub(super) struct Prepared<
    'd,
    const ID: u8,
    R: receive::Policy,
    Q: buffer::Residency + buffer::raw::Source,
> {
    pub(super) config: config::Validated,
    pub(super) datagram: datagram::Prepared<'d, route::KeyTag<ID>, Payload<Q>>,
    pub(super) rotation: clock::Bound<'d, cid::Schedule>,
    pub(super) receive: marker::PhantomData<fn() -> R>,
}

impl<'d, const ID: u8, R: receive::Policy, Q: buffer::Residency + buffer::raw::Source>
    Prepared<'d, ID, R, Q>
{
    pub(super) fn bind<H, A, M>(
        self,
        bind: net::SocketAddr,
        runtime: reactor::Engine<'d, H, ID, R::Buffer<'d>, A, M::Mode, Q>,
        driver: &mut driver::Context<'_, 'd>,
    ) -> Bound<'d, ID, H, R, A, M, Q>
    where
        H: handler::Handler<ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>,
        M: Binding<'d, ID>,
        H: cert::Sink<ID, id::Driver<'d>>,
        <H::Events as Dispatch<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>>::Packet:
            packet::Mode<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>, Output = ()>,
    {
        let udp = self
            .datagram
            .bind(bind, runtime, driver)
            .map_err(BindError::Datagram)?;
        Ok(Endpoint {
            udp,
            packet: self.config.packet(),
            rotation: self.rotation,
        })
    }

    pub(super) fn adopt<H, A, M>(
        self,
        lease: Lease,
        runtime: reactor::Engine<'d, H, ID, R::Buffer<'d>, A, M::Mode, Q>,
        driver: &mut driver::Context<'_, 'd>,
    ) -> Bound<'d, ID, H, R, A, M, Q>
    where
        H: handler::Handler<ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>,
        M: Binding<'d, ID>,
        H: cert::Sink<ID, id::Driver<'d>>,
        <H::Events as Dispatch<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>>>::Packet:
            packet::Mode<H, ID, R::Buffer<'d>, resident::Shared<'d>, id::Driver<'d>, Output = ()>,
    {
        let udp = self
            .datagram
            .adopt(lease, runtime, driver)
            .map_err(BindError::Datagram)?;
        Ok(Endpoint {
            udp,
            packet: self.config.packet(),
            rotation: self.rotation,
        })
    }
}
