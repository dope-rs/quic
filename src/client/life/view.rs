use crate::runtime::{brand, routing};
use o3::mem::rc;

use std::time;

use crate::client::{self, auth, life};
use crate::conn::id;
use life::{due, endpoint};

#[repr(transparent)]
pub(in crate::client) struct View<'a, 'd, const DOMAIN: u8, A, B, R: routing::PeerRoute>(
    &'a life::Lifecycle<'d, DOMAIN, A, B, R>,
);

impl<'d, const DOMAIN: u8, A, B: client::Backoff, R: routing::PeerRoute>
    View<'_, 'd, DOMAIN, A, B, R>
{
    pub(super) fn new<'a>(
        life: &'a life::Lifecycle<'d, DOMAIN, A, B, R>,
    ) -> View<'a, 'd, DOMAIN, A, B, R> {
        View(life)
    }

    pub(in crate::client) fn len(&self) -> usize {
        self.0.endpoints.capacity()
    }

    pub(in crate::client) fn live(&self) -> usize {
        self.0.endpoints.active()
    }

    /// Returns a due endpoint without removing its resident retry entry.
    pub(in crate::client) fn next_due(
        &self,
        now: time::Instant,
    ) -> Option<due::Due<Result<A, rc::Error>, R>>
    where
        A: auth::Mode,
    {
        let (index, deadline, endpoint, ready) = self.0.endpoints.peek()?;
        if *deadline > now {
            return None;
        }
        ready?;
        let peer = self.0.topology.peer(index)?;
        Some(due::Due {
            slot: client::SlotId::from_index(index as u32),
            attempt: endpoint.attempt,
            addr: peer.addr,
            auth: peer.auth,
            route: peer.route,
        })
    }

    pub(in crate::client) fn handle(
        &self,
        slot: client::SlotId,
    ) -> Option<id::Handle<id::Driver<'d>, DOMAIN>> {
        self.0
            .endpoints
            .get(slot.index() as usize)
            .and_then(|(_, value)| endpoint::handle(value))
    }

    pub(in crate::client) fn current(
        &self,
        slot: client::SlotId,
    ) -> Option<(client::AttemptId, id::Handle<id::Driver<'d>, DOMAIN>)> {
        let (endpoint, value) = self.0.endpoints.get(slot.index() as usize)?;
        let handle = endpoint::handle(value)?;
        Some((endpoint.attempt.id(slot), handle))
    }

    pub(in crate::client) fn handle_at(
        &self,
        index: usize,
    ) -> Option<id::Handle<id::Driver<'d>, DOMAIN>> {
        self.0
            .endpoints
            .get(index)
            .and_then(|(_, value)| endpoint::handle(value))
    }

    pub(in crate::client) fn bind<'scope>(
        &self,
        brand: brand::Token<'scope>,
        handle: id::Handle<id::Driver<'d>, DOMAIN>,
    ) -> Option<client::SlotScope<'scope>> {
        let bound = self.0.index(handle)?;
        let attempt = bound.attempt.id(bound.slot);
        Some(client::SlotScope::new(brand, attempt))
    }

    pub(in crate::client) fn has_events(&self) -> bool {
        self.0.endpoints.has_events()
    }

    pub(in crate::client) fn next_retry(&self) -> Option<time::Instant> {
        self.0.endpoints.peek().map(|entry| *entry.1)
    }
}
