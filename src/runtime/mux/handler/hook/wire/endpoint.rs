use dope::core::driver::route;
use dope::core::io::datagram::Residency;
use o3::buffer;
use std::pin;

use dope::manifold::{
    app::dispatch,
    network::datagram::{self, hook},
};

use crate::conn::id;
use crate::runtime::mux::handler::Handler;
use crate::stream;

pub enum Event<'scope, H, const DOMAIN: u8, I: id::Temporal> {
    Opened {
        handler: pin::Pin<&'scope mut H>,
        endpoint: id::Domain<I, DOMAIN>,
    },
    Finalized {
        handler: pin::Pin<&'scope mut H>,
        endpoint: id::Domain<I, DOMAIN>,
        receive: Option<Residency>,
    },
}

impl<'scope, H, const DOMAIN: u8, I: id::Temporal> Event<'scope, H, DOMAIN, I> {
    pub(crate) fn opened(
        handler: pin::Pin<&'scope mut H>,
        endpoint: id::Domain<I, DOMAIN>,
    ) -> Self {
        Self::Opened { handler, endpoint }
    }

    pub(crate) fn finalized(
        handler: pin::Pin<&'scope mut H>,
        endpoint: id::Domain<I, DOMAIN>,
        receive: Option<Residency>,
    ) -> Self {
        Self::Finalized {
            handler,
            endpoint,
            receive,
        }
    }
}

pub trait Sink<const DOMAIN: u8, B, D, I>: Handler<DOMAIN, B, D, I>
where
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn endpoint<'scope>(event: Event<'scope, Self, DOMAIN, I>);
}

pub struct On;
pub struct Off;

pub trait Mode<H, const DOMAIN: u8, B, D, I>
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    type Install<'d, const ID: u8, T>: dispatch::raw::Installs<
            'd,
            datagram::Endpoint<
                'd,
                route::KeyTag<ID>,
                T,
                <T::Hooks as hook::Bundle>::Buffer,
                <T::Hooks as hook::Bundle>::Send,
            >,
        >
    where
        T: datagram::Ingress<'d, route::KeyTag<ID>> + datagram::Install;

    type Finalize<'d, const ID: u8, T>: hook::Finalize<'d, route::KeyTag<ID>, T, hook::Enabled>
    where
        T: datagram::Settlement<'d, route::KeyTag<ID>> + datagram::Finalize;

    const ENABLED: bool;

    fn call<'scope>(event: impl FnOnce() -> Event<'scope, H, DOMAIN, I>)
    where
        H: 'scope;
}

impl<H, const DOMAIN: u8, B, D, I> Mode<H, DOMAIN, B, D, I> for On
where
    H: Sink<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    type Install<'d, const ID: u8, T>
        = hook::Enabled
    where
        T: datagram::Ingress<'d, route::KeyTag<ID>> + datagram::Install;

    type Finalize<'d, const ID: u8, T>
        = hook::Enabled
    where
        T: datagram::Settlement<'d, route::KeyTag<ID>> + datagram::Finalize;

    const ENABLED: bool = true;

    fn call<'scope>(event: impl FnOnce() -> Event<'scope, H, DOMAIN, I>)
    where
        H: 'scope,
    {
        H::endpoint(event());
    }
}

impl<H, const DOMAIN: u8, B, D, I> Mode<H, DOMAIN, B, D, I> for Off
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    type Install<'d, const ID: u8, T>
        = hook::Disabled
    where
        T: datagram::Ingress<'d, route::KeyTag<ID>> + datagram::Install;

    type Finalize<'d, const ID: u8, T>
        = hook::Disabled
    where
        T: datagram::Settlement<'d, route::KeyTag<ID>> + datagram::Finalize;

    const ENABLED: bool = false;

    fn call<'scope>(event: impl FnOnce() -> Event<'scope, H, DOMAIN, I>)
    where
        H: 'scope,
    {
        drop(event);
    }
}
