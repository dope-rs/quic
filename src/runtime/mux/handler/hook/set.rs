use dope::core::driver::route;
use dope::manifold::network::datagram::hook::app;
use dope::manifold::network::datagram::{Application, Settlement, Transfer, Transport};
use o3::buffer;
use std::{marker, ops};

use dope::manifold::network::datagram::hook;

use crate::conn::id;
use crate::runtime::mux::{self, handler::Handler};
use crate::stream::Recv;

use crate::runtime::mux::handler::hook::data::{datagram, release, stream};
use crate::runtime::mux::handler::hook::life::{close, closing, early, ready};
use crate::runtime::mux::handler::hook::wire::{endpoint, ingress, packet, socket};
use crate::runtime::mux::handler::hook::writable;

pub struct On;
pub struct Off;

pub struct Set<
    E = Off,
    D = Off,
    S = Off,
    A = Off,
    R = Off,
    N = Off,
    G = ingress::Off,
    P = packet::Off,
    O = endpoint::Off,
    L = closing::Off,
    C = close::Off,
    W = writable::Off,
> {
    established: marker::PhantomData<fn() -> E>,
    datagram: marker::PhantomData<fn() -> D>,
    stream: marker::PhantomData<fn() -> S>,
    early: marker::PhantomData<fn() -> A>,
    release: marker::PhantomData<fn() -> R>,
    socket: marker::PhantomData<fn() -> N>,
    ingress: marker::PhantomData<fn() -> G>,
    packet: marker::PhantomData<fn() -> P>,
    endpoint: marker::PhantomData<fn() -> O>,
    closing: marker::PhantomData<fn() -> L>,
    close: marker::PhantomData<fn() -> C>,
    writable: marker::PhantomData<fn() -> W>,
}

pub trait Dispatch<H, const DOMAIN: u8, B, D, I>
where
    H: Handler<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    type Established: Established<H, DOMAIN, B, D, I>;
    type Datagram: Datagram<H, DOMAIN, B, D, I>;
    type Stream: Stream<H, DOMAIN, B, D, I>;
    type Early: Early<H, DOMAIN, B, D, I>;
    type Release: release::Mode<H, DOMAIN, B, D, I>;
    type Socket: Socket<H, DOMAIN, B, D, I>;
    type Ingress: ingress::Mode<H, DOMAIN, B, D, I>;
    type Packet: packet::Mode<H, DOMAIN, B, D, I>;
    type Endpoint: endpoint::Mode<H, DOMAIN, B, D, I>;
    type Closing: closing::Mode<H, DOMAIN, B, D, I>;
    type Close: close::Mode<H, DOMAIN, B, D, I>;
    type Writable: writable::Mode<H, DOMAIN, B, D, I>;
}

pub trait Established<H, const DOMAIN: u8, B, D, I>
where
    H: Handler<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn call<'scope, F>(take: impl FnOnce() -> Option<F>) -> ops::ControlFlow<()>
    where
        F: FnOnce() -> ready::Event<'scope, H, DOMAIN, B, D, I>,
        H: 'scope,
        H::Connection: 'scope,
        B: 'scope,
        D: 'scope;
}

impl<H, const DOMAIN: u8, B, D, I> Established<H, DOMAIN, B, D, I> for On
where
    H: ready::Sink<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn call<'scope, F>(take: impl FnOnce() -> Option<F>) -> ops::ControlFlow<()>
    where
        F: FnOnce() -> ready::Event<'scope, H, DOMAIN, B, D, I>,
        H: 'scope,
        H::Connection: 'scope,
        B: 'scope,
        D: 'scope,
    {
        let Some(event) = take() else {
            return ops::ControlFlow::Continue(());
        };
        H::established(event());
        ops::ControlFlow::Break(())
    }
}

impl<H, const DOMAIN: u8, B, D, I> Established<H, DOMAIN, B, D, I> for Off
where
    H: Handler<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn call<'scope, F>(take: impl FnOnce() -> Option<F>) -> ops::ControlFlow<()>
    where
        F: FnOnce() -> ready::Event<'scope, H, DOMAIN, B, D, I>,
        H: 'scope,
        H::Connection: 'scope,
        B: 'scope,
        D: 'scope,
    {
        match take() {
            Some(_) => ops::ControlFlow::Break(()),
            None => ops::ControlFlow::Continue(()),
        }
    }
}

pub trait Datagram<H, const DOMAIN: u8, B, D, I>
where
    H: Handler<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn call<'scope, F>(take: impl FnOnce() -> Option<F>) -> ops::ControlFlow<()>
    where
        F: FnOnce() -> datagram::Event<'scope, H, DOMAIN, B, D, I>,
        H: 'scope,
        H::Connection: 'scope,
        B: 'scope,
        D: 'scope;
}

impl<H, const DOMAIN: u8, B, D, I> Datagram<H, DOMAIN, B, D, I> for On
where
    H: datagram::Sink<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn call<'scope, F>(take: impl FnOnce() -> Option<F>) -> ops::ControlFlow<()>
    where
        F: FnOnce() -> datagram::Event<'scope, H, DOMAIN, B, D, I>,
        H: 'scope,
        H::Connection: 'scope,
        B: 'scope,
        D: 'scope,
    {
        let Some(event) = take() else {
            return ops::ControlFlow::Continue(());
        };
        H::datagram(event());
        ops::ControlFlow::Break(())
    }
}

impl<H, const DOMAIN: u8, B, D, I> Datagram<H, DOMAIN, B, D, I> for Off
where
    H: Handler<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn call<'scope, F>(take: impl FnOnce() -> Option<F>) -> ops::ControlFlow<()>
    where
        F: FnOnce() -> datagram::Event<'scope, H, DOMAIN, B, D, I>,
        H: 'scope,
        H::Connection: 'scope,
        B: 'scope,
        D: 'scope,
    {
        match take() {
            Some(_) => ops::ControlFlow::Break(()),
            None => ops::ControlFlow::Continue(()),
        }
    }
}

pub trait Stream<H, const DOMAIN: u8, B, D, I>
where
    H: Handler<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn call<'scope>(
        event: impl FnOnce() -> stream::Event<'scope, H, DOMAIN, B, D, I>,
    ) -> mux::Disposition
    where
        H: 'scope,
        H::Connection: 'scope,
        B: 'scope,
        D: 'scope;
    fn early<'scope>(
        event: impl FnOnce() -> stream::Event<'scope, H, DOMAIN, B, D, I>,
    ) -> mux::Disposition
    where
        H: 'scope,
        H::Connection: 'scope,
        B: 'scope,
        D: 'scope;
}

impl<H, const DOMAIN: u8, B, D, I> Stream<H, DOMAIN, B, D, I> for On
where
    H: stream::Sink<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn call<'scope>(
        event: impl FnOnce() -> stream::Event<'scope, H, DOMAIN, B, D, I>,
    ) -> mux::Disposition
    where
        H: 'scope,
        H::Connection: 'scope,
        B: 'scope,
        D: 'scope,
    {
        H::stream(event())
    }

    fn early<'scope>(
        event: impl FnOnce() -> stream::Event<'scope, H, DOMAIN, B, D, I>,
    ) -> mux::Disposition
    where
        H: 'scope,
        H::Connection: 'scope,
        B: 'scope,
        D: 'scope,
    {
        H::early(event())
    }
}

impl<H, const DOMAIN: u8, B, D, I> Stream<H, DOMAIN, B, D, I> for Off
where
    H: Handler<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn call<'scope>(
        _: impl FnOnce() -> stream::Event<'scope, H, DOMAIN, B, D, I>,
    ) -> mux::Disposition
    where
        H: 'scope,
        H::Connection: 'scope,
        B: 'scope,
        D: 'scope,
    {
        mux::Disposition::Accept
    }

    fn early<'scope>(
        _: impl FnOnce() -> stream::Event<'scope, H, DOMAIN, B, D, I>,
    ) -> mux::Disposition
    where
        H: 'scope,
        H::Connection: 'scope,
        B: 'scope,
        D: 'scope,
    {
        mux::Disposition::Accept
    }
}

pub trait Early<H, const DOMAIN: u8, B, D, I>
where
    H: Handler<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn call<'scope, F>(take: impl FnOnce() -> Option<F>) -> ops::ControlFlow<()>
    where
        F: FnOnce() -> early::Event<'scope, H, DOMAIN, B, D, I>,
        H: 'scope,
        H::Connection: 'scope;
}

impl<H, const DOMAIN: u8, B, D, I> Early<H, DOMAIN, B, D, I> for On
where
    H: early::Sink<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn call<'scope, F>(take: impl FnOnce() -> Option<F>) -> ops::ControlFlow<()>
    where
        F: FnOnce() -> early::Event<'scope, H, DOMAIN, B, D, I>,
        H: 'scope,
        H::Connection: 'scope,
    {
        let Some(event) = take() else {
            return ops::ControlFlow::Continue(());
        };
        H::rejected(event());
        ops::ControlFlow::Break(())
    }
}

impl<H, const DOMAIN: u8, B, D, I> Early<H, DOMAIN, B, D, I> for Off
where
    H: Handler<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn call<'scope, F>(take: impl FnOnce() -> Option<F>) -> ops::ControlFlow<()>
    where
        F: FnOnce() -> early::Event<'scope, H, DOMAIN, B, D, I>,
        H: 'scope,
        H::Connection: 'scope,
    {
        match take() {
            Some(_) => ops::ControlFlow::Break(()),
            None => ops::ControlFlow::Continue(()),
        }
    }
}

pub trait Socket<H, const DOMAIN: u8, B, D, I>
where
    H: Handler<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    type Transport<'d, const ID: u8, T>: hook::raw::Drive<'d, route::KeyTag<ID>, T, hook::Enabled>
        + hook::Schedule<'d, route::KeyTag<ID>, T>
    where
        T: Settlement<'d, route::KeyTag<ID>>
            + Transport<'d, route::KeyTag<ID>>
            + Transfer<'d, route::KeyTag<ID>>;

    type Application<'d, const ID: u8, T>: hook::raw::Drive<'d, route::KeyTag<ID>, T, hook::Enabled>
        + hook::Schedule<'d, route::KeyTag<ID>, T>
    where
        T: Settlement<'d, route::KeyTag<ID>>
            + Application<'d, route::KeyTag<ID>>
            + Transfer<'d, route::KeyTag<ID>>;

    fn call<'scope, F>(take: F)
    where
        F: FnOnce() -> socket::Event<'scope, H, DOMAIN, I>,
        H: 'scope;
}

impl<H, const DOMAIN: u8, B, D, I> Socket<H, DOMAIN, B, D, I> for On
where
    H: socket::Sink<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    type Transport<'d, const ID: u8, T>
        = hook::Transit<hook::Enabled>
    where
        T: Settlement<'d, route::KeyTag<ID>>
            + Transport<'d, route::KeyTag<ID>>
            + Transfer<'d, route::KeyTag<ID>>;

    type Application<'d, const ID: u8, T>
        = app::Schedule<hook::Enabled>
    where
        T: Settlement<'d, route::KeyTag<ID>>
            + Application<'d, route::KeyTag<ID>>
            + Transfer<'d, route::KeyTag<ID>>;

    fn call<'scope, F>(take: F)
    where
        F: FnOnce() -> socket::Event<'scope, H, DOMAIN, I>,
        H: 'scope,
    {
        H::socket(take());
    }
}

impl<H, const DOMAIN: u8, B, D, I> Socket<H, DOMAIN, B, D, I> for Off
where
    H: Handler<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    type Transport<'d, const ID: u8, T>
        = hook::Transit<hook::Disabled>
    where
        T: Settlement<'d, route::KeyTag<ID>>
            + Transport<'d, route::KeyTag<ID>>
            + Transfer<'d, route::KeyTag<ID>>;

    type Application<'d, const ID: u8, T>
        = app::Schedule<hook::Disabled>
    where
        T: Settlement<'d, route::KeyTag<ID>>
            + Application<'d, route::KeyTag<ID>>
            + Transfer<'d, route::KeyTag<ID>>;

    fn call<'scope, F>(take: F)
    where
        F: FnOnce() -> socket::Event<'scope, H, DOMAIN, I>,
        H: 'scope,
    {
        drop(take);
    }
}

impl<H, const DOMAIN: u8, B, D, I, E, G, S, A, R, N, Q, P, O, L, C, W> Dispatch<H, DOMAIN, B, D, I>
    for Set<E, G, S, A, R, N, Q, P, O, L, C, W>
where
    H: Handler<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
    E: Established<H, DOMAIN, B, D, I>,
    G: Datagram<H, DOMAIN, B, D, I>,
    S: Stream<H, DOMAIN, B, D, I>,
    A: Early<H, DOMAIN, B, D, I>,
    R: release::Mode<H, DOMAIN, B, D, I>,
    N: Socket<H, DOMAIN, B, D, I>,
    Q: ingress::Mode<H, DOMAIN, B, D, I>,
    P: packet::Mode<H, DOMAIN, B, D, I>,
    O: endpoint::Mode<H, DOMAIN, B, D, I>,
    L: closing::Mode<H, DOMAIN, B, D, I>,
    C: close::Mode<H, DOMAIN, B, D, I>,
    W: writable::Mode<H, DOMAIN, B, D, I>,
{
    type Established = E;
    type Datagram = G;
    type Stream = S;
    type Early = A;
    type Release = R;
    type Socket = N;
    type Ingress = Q;
    type Packet = P;
    type Endpoint = O;
    type Closing = L;
    type Close = C;
    type Writable = W;
}
