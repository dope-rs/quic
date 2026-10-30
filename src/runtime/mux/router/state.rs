use std::time;

use crate::conn::wire::path::reset::Token;
use crate::conn::{self, id, scope};
use crate::runtime::{brand, mux, routing::registry};
use crate::{errors, stream, wire::packet::long::retry};
use mux::{app, auth, builder, handler, manage, output, router};
use o3::depot::{
    capacity,
    queue::{
        indexed::{
            lanes::runtime::Group,
            planes::groups::{Buckets, Rows},
        },
        links::List,
    },
};
use registry::Scope;
use router::{drive, reset, routing};
use routing::state::cids;

pub(crate) enum Flush {
    Idle,
    More,
    Backpressure,
    Waiting,
    Closed,
}

/// Endpoint identity, local route, and entropy auth fixed at construction.
pub(in crate::runtime::mux) struct Binding<A: auth::Mode<DOMAIN>, const DOMAIN: u8> {
    pub(in crate::runtime::mux) domain: id::Domain<A::Identity, DOMAIN>,
    pub(in crate::runtime::mux) route: A::LocalRoute,
    pub(in crate::runtime::mux) issuer: A::Random,
}

pub(crate) struct State<A: auth::Mode<DOMAIN>, C, const DOMAIN: u8, B: stream::Recv> {
    pub(in crate::runtime::mux) binding: Binding<A, DOMAIN>,
    pub(in crate::runtime::mux) registry: registry::Set<C, DOMAIN, B, A::Send, A::Session>,
    pub(in crate::runtime::mux) outgoing: output::Storage,
    pub(super) drive: drive::State,
    pub(in crate::runtime::mux) receive_workspace: conn::Workspace,
    pub(in crate::runtime::mux) server: Option<A::Server>,
    pub(in crate::runtime::mux) retry: Option<retry::Key>,
    pub(in crate::runtime::mux) lifecycle: manage::State,
}

impl<A: auth::Mode<DOMAIN>, C, const DOMAIN: u8, B: stream::Recv> State<A, C, DOMAIN, B> {
    pub(in crate::runtime::mux) fn try_new(
        binding: Binding<A, DOMAIN>,
        slots: capacity::Limit<{ mux::MAX_CONNECTIONS }>,
        outgoing: capacity::Count,
        bytes: usize,
        server: Option<A::Server>,
    ) -> Result<Self, builder::Failure> {
        let registry =
            registry::Set::try_new(slots, &binding.issuer).map_err(builder::Failure::Storage)?;
        let retry = match server.as_ref().map(A::config) {
            Some(config)
                if config.0.security.require_address_validation
                    && config.0.security.retry_token_secret.is_some() =>
            {
                Some(retry::Key::try_new().map_err(builder::Failure::Retry)?)
            }
            _ => None,
        };
        Ok(Self {
            binding,
            registry,
            outgoing: output::Storage::try_new(outgoing, bytes).map_err(|error| {
                builder::Failure::Output {
                    packets: outgoing,
                    bytes,
                    error,
                }
            })?,
            drive: drive::State::default(),
            receive_workspace: conn::Workspace::try_new().map_err(builder::Failure::Workspace)?,
            server,
            retry,
            lifecycle: manage::State::default(),
        })
    }

    pub(in crate::runtime::mux) const fn domain(&self) -> id::Domain<A::Identity, DOMAIN> {
        self.binding.domain
    }

    pub(in crate::runtime::mux) fn external<T, R>(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
        now: time::Instant,
        value: T,
        f: impl for<'scope> FnOnce(
            registry::Access<'scope, C, DOMAIN, B, A::Send, A::Session, true>,
            T,
        ) -> R,
    ) -> Result<R, (errors::Access, T)> {
        if self.lifecycle.shutting_down {
            return Err((errors::Access::Closed, value));
        }
        brand::Token::with(|brand| {
            Scope::with(&mut self.registry, |mut slots| {
                let Some(key) = slots.bind(self.binding.domain, handle) else {
                    return Err((errors::Access::InvalidHandle, value));
                };
                if slots.get(key).conn.view().lifecycle().is_closed() {
                    return Err((errors::Access::Closed, value));
                }
                let result = f(slots.access::<true>(key, brand.reborrow()), value);
                Self::reconcile(brand, &mut slots, key, &mut self.binding, now, None);
                Ok(result)
            })
        })
    }

    pub(in crate::runtime::mux) fn trusted_in<'id, R, const TRACKED: bool>(
        brand: brand::Token<'_>,
        slots: &mut registry::Scope<'_, 'id, C, DOMAIN, B, A::Send, A::Session>,
        key: registry::Key<'id>,
        binding: &mut Binding<A, DOMAIN>,
        now: time::Instant,
        f: impl for<'scope> FnOnce(
            registry::Access<'scope, C, DOMAIN, B, A::Send, A::Session, TRACKED>,
        ) -> R,
    ) -> R {
        let result = f(slots.access::<TRACKED>(key, brand.reborrow()));
        Self::reconcile(brand, slots, key, binding, now, None);
        result
    }

    pub(in crate::runtime::mux) fn output_in<'id, R>(
        brand: brand::Token<'_>,
        slots: &mut registry::Scope<'_, 'id, C, DOMAIN, B, A::Send, A::Session>,
        key: registry::Key<'id>,
        binding: &mut Binding<A, DOMAIN>,
        outgoing: &mut output::Storage,
        now: time::Instant,
        f: impl for<'scope> FnOnce(
            registry::Access<'scope, C, DOMAIN, B, A::Send, A::Session, false>,
            &'scope mut output::Storage,
        ) -> (R, bool),
    ) -> R {
        let (result, ready) = {
            let mut slot = slots.access::<false>(key, brand.reborrow());
            slot.conn.events().mark(conn::Effects::TRANSMIT);
            f(slot, outgoing)
        };
        Self::reconcile(brand, slots, key, binding, now, Some(ready));
        result
    }

    pub(in crate::runtime::mux) fn output_group<'storage, 'id, R>(
        brand: brand::Token<'_>,
        slots: &mut registry::Scope<'storage, 'id, C, DOMAIN, B, A::Send, A::Session>,
        keys: &[registry::Key<'id>],
        binding: &mut Binding<A, DOMAIN>,
        outgoing: &mut output::Storage,
        now: time::Instant,
        f: impl for<'scope> FnOnce(
            brand::Token<'scope>,
            &'scope mut registry::Scope<'storage, 'id, C, DOMAIN, B, A::Send, A::Session>,
            &'scope mut output::Storage,
        ) -> R,
    ) -> R {
        for &key in keys {
            slots
                .access::<false>(key, brand.reborrow())
                .conn
                .events()
                .mark(conn::Effects::TRANSMIT);
        }
        let result = f(brand.reborrow(), slots, outgoing);
        for &key in keys {
            Self::reconcile(brand.reborrow(), slots, key, binding, now, None);
        }
        result
    }

    pub(in crate::runtime) fn with<R>(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
        now: time::Instant,
        f: impl for<'scope> FnOnce(scope::Access<'scope, DOMAIN, B, true, A::Send>) -> R,
    ) -> Result<R, errors::Access> {
        self.external(handle, now, (), |slot, ()| f(slot.conn))
            .map_err(|(error, ())| error)
    }

    /// Settles handshake admission, then projects connection deadlines and readiness.
    pub(in crate::runtime::mux) fn reconcile<'id>(
        brand: brand::Token<'_>,
        slots: &mut registry::Scope<'_, 'id, C, DOMAIN, B, A::Send, A::Session>,
        key: registry::Key<'id>,
        binding: &mut Binding<A, DOMAIN>,
        now: time::Instant,
        output: Option<bool>,
    ) {
        let (dirty, notify, flush, app, retry) = {
            let mut slot = slots.access::<false>(key, brand.reborrow());
            let retry = slot.conn.events().retry(now);
            if slot.conn.view().lifecycle().is_closing()
                || !slot.conn.view().lifecycle().is_opening()
            {
                *slot.tls = None;
            }
            let dirty = slot.conn.events().take();
            if dirty.is_empty() {
                return;
            }
            let app = if slot.conn.view().lifecycle().is_closing() {
                Some(false)
            } else {
                dirty.ready()
            };
            let active = if dirty.contains(conn::Effects::ROUTING) {
                slot.conn.routing().peer()
            } else {
                None
            };
            let notify = dirty.contains(conn::Effects::NOTIFY).then(|| {
                let notify = {
                    let events = slot.conn.events();
                    events.has_datagram() || events.has_stream()
                };
                notify || (slot.conn.view().lifecycle().is_ready() && !*slot.notified_established)
            });
            let flush = dirty.contains(conn::Effects::OUTPUT).then(|| {
                if slot.conn.view().lifecycle().is_closed() {
                    false
                } else {
                    match output {
                        Some(output) => output,
                        None => slot
                            .conn
                            .view()
                            .permit()
                            .deadline(now)
                            .is_some_and(|deadline| deadline <= now),
                    }
                }
            });
            if dirty.contains(conn::Effects::ROUTING)
                && let Some(active) = active
            {
                *slot.peer_addr = active;
            }
            (dirty, notify, flush, app, retry)
        };

        if dirty.contains(conn::Effects::ROUTING)
            && let Some(routing) = slots.routing(brand.reborrow(), key, |slot, resets, tokens| {
                Self::sync_tokens(slot, resets, tokens)
            })
        {
            cids::sync(routing, binding);
        }
        Self::sync_queue::<{ mux::NOTIFY_QUEUE }>(slots, key, notify);
        Self::sync_queue::<{ mux::FLUSH_QUEUE }>(slots, key, flush);
        Self::sync_queue::<{ mux::APPLICATION_QUEUE }>(slots, key, app);
        if let Some(update) = dirty.deadline() {
            slots.refresh(key, now, update, retry);
        }
        if dirty.contains(conn::Effects::EARLY_DATA_REJECTED) {
            slots
                .access::<false>(key, brand.reborrow())
                .conn
                .events()
                .mark(conn::Effects::EARLY_DATA_REJECTED | conn::Effects::NOTIFY);
            Self::sync_queue::<{ mux::NOTIFY_QUEUE }>(slots, key, Some(true));
        }
    }

    fn sync_tokens(
        mut slot: registry::Access<'_, C, DOMAIN, B, A::Send, A::Session, false>,
        resets: Group<
            '_,
            Token,
            Rows<capacity::Limit<{ mux::MAX_CONNECTIONS }>, 2>,
            Buckets<capacity::Limit<{ mux::MAX_CONNECTIONS }>, 4>,
            List,
            2,
        >,
        tokens: &reset::Reset,
    ) {
        if !slot.conn.view().path().is_dirty() {
            return;
        }
        let mut current = [None; 2];
        for token in slot.conn.view().path().reset_tokens() {
            if current.iter().flatten().any(|known| token.matches(*known)) {
                continue;
            }
            if let Some(vacant) = current.iter_mut().find(|entry| entry.is_none()) {
                *vacant = Some(token);
            }
        }
        tokens.replace(resets, current);
        slot.conn.routing().sync_tokens();
    }

    fn sync_queue<'id, const PLANE: usize>(
        slots: &mut registry::Scope<'_, 'id, C, DOMAIN, B, A::Send, A::Session>,
        key: registry::Key<'id>,
        pending: Option<bool>,
    ) {
        let Some(pending) = pending else { return };
        let mut entry = slots.entry(key);
        if pending {
            entry.link_back::<PLANE>();
        } else {
            entry.unlink::<PLANE>();
        }
    }

    pub(in crate::runtime::mux) fn run_selected<'id, R, const QUEUED: bool>(
        brand: brand::Token<'_>,
        slots: &mut registry::Scope<'_, 'id, C, DOMAIN, B, A::Send, A::Session>,
        key: registry::Key<'id>,
        binding: &mut Binding<A, DOMAIN>,
        now: time::Instant,
        op: impl for<'scope> FnOnce(app::Connection<'scope, C, DOMAIN, B, A::Send, A::Identity>) -> R,
    ) -> R {
        let handle = slots.handle(binding.domain, key);
        let result = {
            let mut entry = slots.entry(key);
            if QUEUED {
                entry.unlink::<{ mux::APPLICATION_QUEUE }>();
            }
            let slot = entry.access::<true>(brand.reborrow());
            op(app::Connection::new(
                handle,
                handler::Slot::new(slot.connection, slot.conn),
            ))
        };
        Self::reconcile(brand, slots, key, binding, now, None);
        result
    }
}
