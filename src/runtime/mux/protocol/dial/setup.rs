use std::pin;

use crate::{
    conn, errors,
    proto::datagram::Size,
    runtime::{brand, mux, routing},
    stream,
    wire::packet::cid,
};
use conn::{
    id,
    life::{initial, options, tls::clients},
};
use issuer::Source as _;
use mux::{auth, handler, protocol, router};
use protocol::dial;
use router::routing::{
    issuer,
    state::cids,
    txn::{install, plan},
};
use routing::registry;

pub(super) struct Setup<
    'storage,
    'id,
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
> {
    owner: registry::Directory<'storage, 'id, H::Connection, DOMAIN, B, A::Send, A::Session>,
    handler: pin::Pin<&'storage mut H>,
    binding: &'storage mut router::Binding<A, DOMAIN>,
    closed: bool,
    ceiling: usize,
}

pub(super) struct Ready<
    'storage,
    'id,
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
> {
    local: cids::Prepared<'storage, 'id, H::Connection, DOMAIN, B, A::Send, A::Session>,
    handler: pin::Pin<&'storage mut H>,
    binding: &'storage mut router::Binding<A, DOMAIN>,
    limit: Size,
}

impl<
    'storage,
    'id,
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
> Setup<'storage, 'id, A, H, DOMAIN, B>
{
    pub(super) fn with<R>(
        io: &'storage mut protocol::Io<'_, '_, H, DOMAIN, B, A>,
        apply: impl for<'next> FnOnce(Setup<'storage, 'next, A, H, DOMAIN, B>) -> R,
    ) -> R {
        let mux = io.mux.as_mut().project();
        let state = mux.state;
        registry::Directory::with(&mut state.registry, |owner| {
            apply(Setup {
                owner,
                handler: mux.handler,
                binding: &mut state.binding,
                closed: state.lifecycle.shutting_down,
                ceiling: state.outgoing.bytes_capacity,
            })
        })
    }

    pub(super) fn reserve(
        self,
        options: &options::Options,
    ) -> Result<Ready<'storage, 'id, A, H, DOMAIN, B>, errors::Preflight> {
        if self.closed {
            return Err(errors::Preflight::Closed);
        }
        let (active, capacity) = self.owner.capacity();
        if active >= capacity.get() {
            return Err(errors::Preflight::Capacity);
        }
        let limit = options
            .packet_cap(self.ceiling)
            .ok_or(errors::Preflight::InvalidConfig)?;
        let local = cids::Source::new(self.owner)
            .reserve(&self.binding.route, &mut self.binding.issuer)
            .ok_or(errors::Preflight::Capacity)?;
        Ok(Ready {
            local,
            handler: self.handler,
            binding: self.binding,
            limit,
        })
    }

    pub(super) fn issue<R: routing::PeerRoute>(
        self,
        options: &options::Options,
        route: R,
    ) -> Result<(cid::Id, Ready<'storage, 'id, A, H, DOMAIN, B>), errors::Preflight> {
        let ready = self.reserve(options)?;
        let dcid = ready
            .binding
            .issuer
            .initial(route)
            .ok_or(errors::Preflight::IdentifierSpaceExhausted)?;
        Ok((dcid, ready))
    }
}

impl<
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
> Ready<'_, '_, A, H, DOMAIN, B>
{
    pub(super) fn finish<R: routing::PeerRoute>(
        self,
        scope: brand::Token<'_>,
        auth: clients::Authority,
        options: options::Options,
        prepared: dial::Prepared<R>,
        tls: Option<A::Session>,
    ) -> Result<id::Handle<A::Identity, DOMAIN>, errors::Connect> {
        let dial::Prepared {
            route,
            initial_dcid: dcid,
            peer_addr: peer,
            now,
            token,
        } = prepared;
        let conn = initial::Client::new(dcid, self.local.value(), options)
            .try_direct::<DOMAIN, B, A::Send>(auth, route, token)?;
        let plan = plan::Plan::new(conn, tls, peer, self.limit, now, self.local);
        match install::Install::new(self.handler, self.binding).attach(
            scope,
            plan,
            |_, _, _, _, handle| handle,
        ) {
            install::Outcome::Installed(handle) => Ok(handle),
            install::Outcome::Rejected => Err(errors::Connect::ApplicationRejected),
            install::Outcome::Unavailable => Err(errors::Connect::Capacity),
        }
    }
}
