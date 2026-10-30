use std::{net, ops, pin, time};

use dope::runtime::civil;
use o3::buffer::{self, write::Sink as _};

use crate::{
    conn, errors,
    proto::epoch,
    runtime::{brand, mux, routing::registry},
    security::secrets,
    stream,
    wire::packet::{
        self,
        long::{self, retry},
    },
};
use conn::{id, life::accept, wire::path};
use mux::handler::hook::{
    life::{close::Mode as _, closing::Mode as _},
    set::Dispatch,
};
use mux::{auth, handler, output, router};
use registry::{Directory, Scope};
use router::routing;
use routing::{state, txn};
use state::cids;
use txn::{install, plan};

pub(crate) struct Turn<
    'a,
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
> {
    pub(in crate::runtime::mux) state: &'a mut router::State<A, H::Connection, DOMAIN, B>,
    pub(in crate::runtime::mux) handler: pin::Pin<&'a mut H>,
}

impl<
    'a,
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
> Turn<'a, A, H, DOMAIN, B>
{
    pub(crate) fn new(mux: pin::Pin<&'a mut router::Router<H, DOMAIN, B, A>>) -> Self {
        let mux = mux.project();
        Self {
            state: mux.state,
            handler: mux.handler,
        }
    }

    pub(in crate::runtime::mux) fn route<I: buffer::raw::Source, S>(
        &mut self,
        from: net::SocketAddr,
        input: I,
        now: time::Instant,
        epoch: epoch::Sample<S>,
        apply: impl for<'storage, 'id, 'scope> FnOnce(
            brand::Branded<'scope, Option<path::LocalCidKey>>,
            pin::Pin<&'scope mut H>,
            &'scope mut registry::Scope<
                'storage,
                'id,
                H::Connection,
                DOMAIN,
                B,
                A::Send,
                A::Session,
            >,
            registry::Key<'id>,
            &'scope mut router::Binding<A, DOMAIN>,
            &'scope mut conn::Workspace,
            I,
        ) -> Result<(), errors::Receive>,
    ) -> Result<(), errors::Receive>
    where
        S: civil::Source,
    {
        self.run(|scope, turn| {
            let state = &mut *turn.state;
            let mut sink = turn.handler.as_mut();
            if !routing::packets::Header::new(input.as_ref()).is_initial() || state.server.is_none()
            {
                let result = Directory::with(&mut state.registry, |owner| {
                    let header = routing::packets::Header::new(input.as_ref());
                    let Some(value) = header.dcid::<A::LocalRoute>() else {
                        return Err(input);
                    };
                    let hit = match cids::Source::new(owner).find(value) {
                        Ok(hit) => hit,
                        Err(_) => return Err(input),
                    };
                    let (mut slots, key, local) = hit.into_scope();
                    Ok(apply(
                        brand::Branded::new(scope.reborrow(), local),
                        sink.as_mut(),
                        &mut slots,
                        key,
                        &mut state.binding,
                        &mut state.receive_workspace,
                        input,
                    ))
                });
                return match result {
                    Ok(result) => result,
                    Err(input) => routing::reset::receive(state, from, input.as_ref(), now),
                };
            }
            let init = match long::Admission::try_new(input) {
                Ok(packet) => packet,
                Err(_) => return Ok(()),
            };
            Directory::with(&mut state.registry, |owner| {
                match cids::Source::new(owner).lookup(init.dcid()) {
                    cids::Lookup::Routed(hit) => {
                        let (mut slots, key, local) = hit.into_scope();
                        apply(
                            brand::Branded::new(scope.reborrow(), local),
                            sink.as_mut(),
                            &mut slots,
                            key,
                            &mut state.binding,
                            &mut state.receive_workspace,
                            init.into_inner(),
                        )
                    }
                    cids::Lookup::Vacant(mut alias) => {
                        if state.lifecycle.admission_closed || alias.is_full() {
                            return Ok(());
                        }
                        let server = state
                            .server
                            .as_ref()
                            .ok_or(errors::Receive::Packet(conn::Error::HeaderDecode))?;
                        let cfg = A::config(server).0;
                        let (proof, seen) = 'gate: {
                            let Some(secret) = cfg.security.retry_token_secret.as_ref() else {
                                if !init.token().is_empty()
                                    && init.token().len() != secrets::Address::WIRE_LEN
                                {
                                    return Ok(());
                                }
                                if !cfg.security.require_address_validation {
                                    break 'gate (
                                        brand::Branded::new(
                                            scope.reborrow(),
                                            router::AddressProof::Unvalidated,
                                        ),
                                        None,
                                    );
                                }
                                return Ok(());
                            };
                            let seen = epoch
                                .observe(scope.reborrow())
                                .map_err(errors::Receive::Civil)?;
                            if let Some(odcid) =
                                secret.validate(&from, init.token(), init.dcid(), &seen)
                            {
                                break 'gate (
                                    brand::Branded::new(
                                        scope.reborrow(),
                                        router::AddressProof::Retry { odcid },
                                    ),
                                    Some(seen),
                                );
                            }
                            if secrets::Address(&secret.0).is_valid(&from, init.token(), &seen) {
                                break 'gate (
                                    brand::Branded::new(
                                        scope.reborrow(),
                                        router::AddressProof::NewToken,
                                    ),
                                    Some(seen),
                                );
                            }
                            if !init.token().is_empty()
                                && init.token().len() != secrets::Address::WIRE_LEN
                            {
                                return Ok(());
                            }
                            let Some(key) = state.retry.as_ref() else {
                                break 'gate (
                                    brand::Branded::new(
                                        scope.reborrow(),
                                        router::AddressProof::Unvalidated,
                                    ),
                                    Some(seen),
                                );
                            };
                            let expiry = seen
                                .expire(secrets::RETRY_TOKEN_TTL)
                                .map_err(errors::Receive::Expiry)?;
                            let Some(new_scid) =
                                alias.new_away(&state.binding.route, &mut state.binding.issuer)
                            else {
                                return Ok(());
                            };
                            let Some(amp) = init.datagram_len().checked_mul(3) else {
                                return Ok(());
                            };
                            let limit =
                                cfg.packet_max().min(state.outgoing.bytes_capacity).min(amp);
                            let dcid = init.dcid();
                            let scid = init.scid();
                            let len = retry::Suffix::prefix_len(scid, new_scid.as_ref_id())
                                + secrets::Retry::encoded_len(dcid)
                                + retry::INTEGRITY_TAG_LEN;
                            if len > limit {
                                return Ok(());
                            }
                            let prefix = 1 + dcid.len();
                            let mut failure = None;
                            let emission =
                                state.outgoing.emit_owned(len, prefix + len, |mut storage| {
                                    if let Err(error) = storage
                                        .write_slices([&[dcid.length().get()], dcid.into_slice()])
                                    {
                                        return Err((storage, Some(error)));
                                    }
                                    let mut storage = match retry::Suffix::encode_into(
                                        storage,
                                        packet::QUIC_V1,
                                        scid,
                                        new_scid.as_ref_id(),
                                        &[],
                                    ) {
                                        Ok(storage) => storage,
                                        Err(rejected) => {
                                            let (storage, error) = rejected.into_parts();
                                            return Err((storage, Some(error)));
                                        }
                                    };
                                    if let Err(error) = secret.issue_into(
                                        &mut storage.append(),
                                        &from,
                                        dcid,
                                        new_scid.as_ref_id(),
                                        expiry,
                                    ) {
                                        return Err((storage.into_storage(), Some(error)));
                                    }
                                    let tag = match key.tag_from_aad(storage.storage()) {
                                        Ok(tag) => tag,
                                        Err(error) => {
                                            failure = Some(error);
                                            return Err((storage.into_storage(), None));
                                        }
                                    };
                                    if let Err(error) = storage.append().write_slice(&tag) {
                                        return Err((storage.into_storage(), Some(error)));
                                    }
                                    Ok(output::Flight::suffix(from, storage))
                                });
                            if let Some(error) = failure {
                                return Err(errors::Receive::Retry(error));
                            }
                            return match emission {
                                output::Emission::Sent | output::Emission::Skipped => Ok(()),
                                output::Emission::Allocation { error, requested } => {
                                    Err(errors::Receive::Allocation { error, requested })
                                }
                            };
                        };
                        let cfg = cfg.copy();
                        let dcid = alias.value();
                        let remote = init.scid().into_owned();
                        let local = alias
                            .reserve_away(&state.binding.route, &mut state.binding.issuer)
                            .ok_or(errors::Receive::Packet(conn::Error::ConnectionIdLimit))?;
                        let cid = local.value();
                        let cap = cfg
                            .packet_cap(state.outgoing.bytes_capacity)
                            .ok_or(errors::Receive::Packet(conn::Error::PacketCeiling))?;
                        let ids = match proof.value() {
                            router::AddressProof::Retry { odcid } => {
                                accept::Ids::retry(dcid, cid, remote, *odcid, dcid)
                            }
                            router::AddressProof::NewToken => {
                                accept::Ids::validated(dcid, cid, remote)
                            }
                            router::AddressProof::Unvalidated => {
                                accept::Ids::initial(dcid, cid, remote)
                            }
                        };
                        let token = match cfg.security.retry_token_secret.as_ref() {
                            Some(secret) => match seen.as_ref() {
                                Some(seen) => {
                                    let expiry = seen
                                        .expire(secrets::ADDRESS_TOKEN_TTL)
                                        .map_err(errors::Receive::Expiry)?;
                                    Some(secrets::Address(&secret.0).issue(&from, expiry))
                                }
                                None => None,
                            },
                            None => None,
                        };
                        let ids = ids.with_token(token);
                        let (conn, tls) = A::accept(server, ids, auth::ServerConfig(cfg))
                            .map_err(errors::Receive::Accept)?;
                        match install::Install::new(sink.as_mut(), &mut state.binding).attach(
                            proof.brand(),
                            plan::Plan::new(conn, tls, from, cap, now, local),
                            |sink, binding, slots, key, _| {
                                apply(
                                    brand::Branded::new(scope.reborrow(), None),
                                    sink,
                                    slots,
                                    key,
                                    binding,
                                    &mut state.receive_workspace,
                                    init.into_inner(),
                                )
                            },
                        ) {
                            install::Outcome::Installed(value) => value,
                            install::Outcome::Rejected => Err(errors::Receive::ApplicationRejected),
                            install::Outcome::Unavailable => {
                                Err(errors::Receive::Packet(conn::Error::EventCapacity))
                            }
                        }
                    }
                }
            })
        })
    }

    /// Constructs the generative lifetime shared by one mux mutation.
    pub(in crate::runtime::mux) fn run<R>(
        &mut self,
        f: impl FnOnce(brand::Token<'_>, &mut Self) -> R,
    ) -> R {
        brand::Token::with(|brand| f(brand, self))
    }

    pub(in crate::runtime::mux) fn ready<R, const PLANE: usize>(
        &mut self,
        now: time::Instant,
        f: impl for<'scope> FnOnce(
            id::Handle<A::Identity, DOMAIN>,
            pin::Pin<&'scope mut H>,
            registry::Access<'scope, H::Connection, DOMAIN, B, A::Send, A::Session, false>,
        ) -> R,
    ) -> Option<R> {
        self.run(|scope, turn| {
            let state = &mut *turn.state;
            let binding = &mut state.binding;
            let mut sink = turn.handler.as_mut();
            Scope::with(&mut state.registry, |mut slots| {
                let key = slots.pop_front::<PLANE>()?;
                let handle = slots.handle(binding.domain, key);
                let result = {
                    let mut entry = slots.entry(key);
                    f(
                        handle,
                        sink.as_mut(),
                        entry.access::<false>(scope.reborrow()),
                    )
                };
                router::State::<A, H::Connection, DOMAIN, B>::reconcile(
                    scope, &mut slots, key, binding, now, None,
                );
                Some(result)
            })
        })
    }

    pub(in crate::runtime::mux) fn try_remove(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
        now: time::Instant,
    ) -> Result<(), errors::Access> {
        self.run(|scope, turn| {
            let domain = turn.state.binding.domain;
            Scope::with(&mut turn.state.registry, |slots| {
                let key = slots
                    .bind(domain, handle)
                    .ok_or(errors::Access::InvalidHandle)?;
                let taken = slots.into_taken(key, domain);
                Self::retire(turn.handler.as_mut(), taken, scope, now);
                Ok(())
            })
        })
    }

    pub(in crate::runtime::mux) fn remove_at(&mut self, index: usize, now: time::Instant) -> bool {
        self.run(|scope, turn| {
            let domain = turn.state.binding.domain;
            Scope::with(&mut turn.state.registry, |slots| {
                let Some(key) = slots.resolve(index) else {
                    return false;
                };
                let taken = slots.into_taken(key, domain);
                Self::retire(turn.handler.as_mut(), taken, scope, now);
                true
            })
        })
    }

    pub(in crate::runtime::mux) fn clear(&mut self, now: time::Instant) -> usize {
        let len = self.registry.capacity();
        let mut removed = 0;
        for index in 0..len {
            if self.remove_at(index, now) {
                removed += 1;
            }
        }
        removed
    }

    pub(in crate::runtime::mux) fn retire(
        mut sink: pin::Pin<&mut H>,
        taken: registry::Taken<'_, H::Connection, A::Identity, DOMAIN, B, A::Send, A::Session>,
        scope: brand::Token<'_>,
        now: time::Instant,
    ) {
        taken.close(|handle, conn, mut app| {
            <H::Events as Dispatch<H, DOMAIN, B, A::Send, A::Identity>>::Closing::retire(
                sink.as_mut(),
                conn,
                &mut app,
                scope.reborrow(),
                handle,
            );
            <H::Events as Dispatch<H, DOMAIN, B, A::Send, A::Identity>>::Close::close(
                sink.as_mut(),
                handler::Close::new(scope.reborrow(), now),
                app,
                handle,
            );
        });
    }
}

impl<
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
> ops::Deref for Turn<'_, A, H, DOMAIN, B>
{
    type Target = router::State<A, H::Connection, DOMAIN, B>;

    fn deref(&self) -> &Self::Target {
        self.state
    }
}

impl<
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
> ops::DerefMut for Turn<'_, A, H, DOMAIN, B>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.state
    }
}
