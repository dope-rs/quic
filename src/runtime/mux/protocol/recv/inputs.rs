use crate::conn::wire::ingress::events;
use crate::stream::retain;
use o3::buffer::{self, storage::provided};
use std::time;

use crate::conn::{scope, wire::path};
use crate::runtime::brand;
use crate::{conn, runtime::mux, stream};
use dope::manifold::network::datagram::packet;
use mux::auth;

pub(in crate::runtime) trait Input<const DOMAIN: u8, B, A>:
    buffer::raw::Mutable
where
    B: stream::Recv,
    A: auth::Mode<DOMAIN>,
{
    type Retain: Copy;

    fn receive<'access, E>(
        self,
        keep: Self::Retain,
        scope: scope::Access<'access, DOMAIN, B, true, A::Send>,
        work: &'access mut conn::Workspace,
        route: brand::Branded<'access, Option<path::LocalCidKey>>,
        now: time::Instant,
        sink: &'access mut E,
    ) -> conn::Ingress<Result<(), conn::Error>>
    where
        B: 'access,
        A::Send: 'access,
        E: events::Sink + 'access;
}

impl<const DOMAIN: u8, B, A> Input<DOMAIN, B, A> for &mut [u8]
where
    B: stream::Recv,
    A: auth::Mode<DOMAIN>,
{
    type Retain = ();

    fn receive<'access, E>(
        self,
        _: Self::Retain,
        mut scope: scope::Access<'access, DOMAIN, B, true, A::Send>,
        work: &'access mut conn::Workspace,
        route: brand::Branded<'access, Option<path::LocalCidKey>>,
        now: time::Instant,
        sink: &'access mut E,
    ) -> conn::Ingress<Result<(), conn::Error>>
    where
        B: 'access,
        A::Send: 'access,
        E: events::Sink + 'access,
    {
        let mut input = scope.input(work).with_route(*route.value());
        let out = input.recv_with(self, now, sink);
        input.finish(out)
    }
}

impl<
    'turn,
    'd,
    const DOMAIN: u8,
    const ADAPTIVE: bool,
    A,
    T: provided::Mutable<'d, Account: retain::Retain<'d>>,
> Input<DOMAIN, stream::RecvBuffer<'d, ADAPTIVE>, A> for packet::Packet<'turn, 'd, T>
where
    A: auth::Mode<DOMAIN>,
{
    type Retain = packet::Retainer<'d>;

    fn receive<'access, E>(
        self,
        keep: Self::Retain,
        mut scope: scope::Access<'access, DOMAIN, stream::RecvBuffer<'d, ADAPTIVE>, true, A::Send>,
        work: &'access mut conn::Workspace,
        route: brand::Branded<'access, Option<path::LocalCidKey>>,
        now: time::Instant,
        sink: &'access mut E,
    ) -> conn::Ingress<Result<(), conn::Error>>
    where
        'd: 'access,
        A::Send: 'access,
        E: events::Sink + 'access,
    {
        let mut input = scope.input(work).with_route(*route.value());
        let out = input.recv(self, keep, now, sink);
        input.finish(out)
    }
}
