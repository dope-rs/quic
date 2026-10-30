use crate::runtime::mux;
use crate::runtime::{brand, routing};
use indexed::resident::{self, phase};
use o3::alloc::BoxSliceExt as _;
use o3::depot::{capacity, heap::indexed};
use std::time;

use crate::client;
use crate::conn::{id, life};
use client::build;

mod due;
mod endpoint;
mod retry;
pub(super) mod topology;
pub(super) mod view;

pub(super) use due::Due;
use retry::Retry;

type Capacity = capacity::Limit<{ mux::MAX_CONNECTIONS }>;

#[derive(Clone, Copy)]
struct Bound {
    slot: client::SlotId,
    attempt: client::AttemptState,
}

/// The heap and event owner retain each endpoint's exact resident phase.
/// Live cardinality belongs to consumed Active transitions in that same domain.
pub(super) struct Lifecycle<'d, const DOMAIN: u8, A, B, R: routing::PeerRoute> {
    topology: topology::Topology<A, R>,
    endpoints: resident::Min<time::Instant, endpoint::Types<'d, DOMAIN>, Capacity>,
    handle_to_endpoint: Box<[Option<client::SlotId>]>,
    backoff: B,
    reconnect: bool,
}

impl<'d, const DOMAIN: u8, A, B: client::Backoff, R: routing::PeerRoute>
    Lifecycle<'d, DOMAIN, A, B, R>
{
    pub(super) fn try_new(
        topology: topology::Topology<A, R>,
        backoff: B,
        capacity: Capacity,
        now: time::Instant,
    ) -> Result<Self, build::Error> {
        let entries =
            resident::Min::try_repeat(capacity, now, |_| (endpoint::Endpoint::default(), ()))
                .map_err(build::Error::Storage)?;
        let reverse = Box::try_repeat(capacity.get(), None).map_err(build::Error::Reverse)?;
        Ok(Self {
            topology,
            endpoints: entries,
            handle_to_endpoint: reverse,
            backoff,
            reconnect: true,
        })
    }

    pub(super) fn view(&self) -> view::View<'_, 'd, DOMAIN, A, B, R> {
        view::View::new(self)
    }

    /// The retained Scheduled entry owns both the deadline and this endpoint.
    pub(super) fn bind_due(
        &mut self,
        due: due::Due<A, R>,
        handle: id::Handle<id::Driver<'d>, DOMAIN>,
    ) {
        let due::Due {
            slot,
            attempt,
            addr,
            ..
        } = due;
        let index = slot.index() as usize;
        let Some(resident::Entry::Scheduled(endpoint)) = self.endpoints.entry(index) else {
            return;
        };
        let Some(expected) = self.topology.address(index) else {
            return;
        };
        if endpoint.get().0.attempt != attempt || expected != addr {
            return;
        }
        let Some(reverse) = self.handle_to_endpoint.get_mut(handle.index() as usize) else {
            return;
        };
        if reverse.is_some() {
            return;
        }
        endpoint.retire(endpoint::Idle::Handshaking(handle));
        *reverse = Some(slot);
    }

    pub(super) fn defer_due<T>(
        &mut self,
        scope: brand::Token<'_>,
        due: due::Due<T, R>,
        seen: time::Instant,
    ) {
        let due::Due {
            slot,
            attempt,
            addr,
            ..
        } = due;
        let index = slot.index() as usize;
        let expected = self.topology.address(index);
        let Some(resident::Entry::Scheduled(endpoint)) = self.endpoints.entry(index) else {
            return;
        };
        if endpoint.get().0.attempt != attempt || expected != Some(addr) {
            return;
        }
        match Retry::new(
            &self.backoff,
            self.reconnect,
            scope,
            slot,
            attempt,
            false,
            seen,
        ) {
            Retry::Scheduled { next, at } => {
                let (mut endpoint, _) = endpoint.replace(at);
                endpoint.get_mut().0.attempt = next;
            }
            Retry::Dormant(next) => {
                let (mut endpoint, _, _) = endpoint.retire(endpoint::Idle::Dormant);
                if let Some(next) = next {
                    endpoint.get_mut().0.attempt = next;
                }
            }
        }
    }

    pub(super) fn establish(&mut self, handle: id::Handle<id::Driver<'d>, DOMAIN>) {
        let Some(slot) = self
            .handle_to_endpoint
            .get(handle.index() as usize)
            .copied()
            .flatten()
        else {
            return;
        };
        let Some(resident::Entry::Idle(endpoint)) = self.endpoints.entry(slot.index() as usize)
        else {
            return;
        };
        let endpoint::Idle::Handshaking(current) = *endpoint.get().1 else {
            return;
        };
        if current != handle {
            return;
        }
        endpoint.change::<phase::Data>(handle);
    }

    pub(super) fn reconnect(
        &mut self,
        handle: id::Handle<id::Driver<'d>, DOMAIN>,
        again: Option<life::Reconnect>,
    ) {
        let Some(bound) = self.index(handle) else {
            return;
        };
        let index = bound.slot.index() as usize;
        let Some(route) = self.topology.route(index) else {
            return;
        };
        let Some(endpoint) = self.endpoints.common_mut(index) else {
            return;
        };
        endpoint.reconnect = again.filter(|again| again.matches_path(route));
    }

    pub(super) fn take_again(&mut self, due: &due::Due<A, R>) -> Option<life::Reconnect> {
        let resident::Entry::Scheduled(mut endpoint) =
            self.endpoints.entry(due.slot.index() as usize)?
        else {
            return None;
        };
        endpoint.get_mut().0.reconnect.take()
    }

    pub(super) fn put_again(&mut self, due: &due::Due<A, R>, again: life::Reconnect) {
        let Some(resident::Entry::Scheduled(mut endpoint)) =
            self.endpoints.entry(due.slot.index() as usize)
        else {
            return;
        };
        let endpoint = endpoint.get_mut().0;
        if endpoint.reconnect.is_some() {
            return;
        }
        endpoint.reconnect = Some(again);
    }

    pub(super) fn close_at(
        &mut self,
        scope: brand::Token<'_>,
        handle: id::Handle<id::Driver<'d>, DOMAIN>,
        seen: time::Instant,
    ) {
        let Some(reverse) = self.handle_to_endpoint.get_mut(handle.index() as usize) else {
            return;
        };
        let Some(slot) = *reverse else {
            return;
        };
        let Some(endpoint) = self.endpoints.entry(slot.index() as usize) else {
            return;
        };
        match endpoint {
            resident::Entry::Idle(endpoint) => {
                let endpoint::Idle::Handshaking(current) = *endpoint.get().1 else {
                    return;
                };
                if current != handle {
                    return;
                }
                close(
                    endpoint,
                    reverse,
                    &self.backoff,
                    self.reconnect,
                    scope,
                    false,
                    seen,
                );
            }
            resident::Entry::Data(endpoint) => {
                if *endpoint.get().1 != handle {
                    return;
                }
                close(
                    endpoint,
                    reverse,
                    &self.backoff,
                    self.reconnect,
                    scope,
                    true,
                    seen,
                );
            }
            resident::Entry::Active(endpoint) => {
                if *endpoint.get().1 != handle {
                    return;
                }
                close(
                    endpoint,
                    reverse,
                    &self.backoff,
                    self.reconnect,
                    scope,
                    true,
                    seen,
                );
            }
            resident::Entry::Scheduled(_) | resident::Entry::Control(_) => {}
        }
    }

    /// Consumes the exact close field before executing its external callback.
    pub(super) fn settle_close<'scope>(
        &mut self,
        scope: brand::Token<'scope>,
    ) -> Option<client::SlotScope<'scope>> {
        let attempt = match self.endpoints.control()? {
            resident::Control::Full(endpoint) => endpoint.change::<phase::Scheduled>(()).1,
            resident::Control::Empty(endpoint) => {
                endpoint.change::<phase::Idle>(endpoint::Idle::Dormant).1
            }
        };
        Some(client::SlotScope::new(scope, attempt))
    }

    /// The Data owner supplies both the handle and its unused Active slot.
    pub(super) fn settle_ready<'scope>(
        &mut self,
        scope: brand::Token<'scope>,
    ) -> Option<client::SlotScope<'scope>> {
        let endpoint = self.endpoints.data()?;
        let slot = client::SlotId::from_index(endpoint.index() as u32);
        let (common, handle) = endpoint.get();
        let attempt = common.attempt.id(slot);
        let handle = *handle;
        endpoint.change::<phase::Active>(handle);
        Some(client::SlotScope::new(scope, attempt))
    }

    pub(super) fn seal(&mut self) {
        self.reconnect = false;
        self.endpoints.clear(|_, ()| endpoint::Idle::Dormant);
    }

    fn index(&self, handle: id::Handle<id::Driver<'d>, DOMAIN>) -> Option<Bound> {
        let slot = self
            .handle_to_endpoint
            .get(handle.index() as usize)
            .copied()
            .flatten()?;
        let (common, value) = self.endpoints.get(slot.index() as usize)?;
        if endpoint::handle(value)? != handle {
            return None;
        }
        Some(Bound {
            slot,
            attempt: common.attempt,
        })
    }
}

fn close<
    'd,
    const DOMAIN: u8,
    B: client::Backoff,
    F: resident::Phase<endpoint::Types<'d, DOMAIN>>,
>(
    mut endpoint: resident::Slot<
        '_,
        endpoint::Types<'d, DOMAIN>,
        indexed::Vacant<'_, time::Instant, Capacity>,
        F,
    >,
    reverse: &mut Option<client::SlotId>,
    backoff: &B,
    again: bool,
    scope: brand::Token<'_>,
    restart: bool,
    seen: time::Instant,
) {
    let slot = client::SlotId::from_index(endpoint.index() as u32);
    let previous = endpoint.get().0.attempt;
    let plan = Retry::new(backoff, again, scope, slot, previous, restart, seen);
    *reverse = None;
    let attempt = previous.id(slot);
    match plan {
        Retry::Scheduled { next, at } => {
            endpoint.get_mut().0.attempt = next;
            endpoint.schedule(at, attempt);
        }
        Retry::Dormant(next) => {
            if let Some(next) = next {
                endpoint.get_mut().0.attempt = next;
            }
            endpoint.change::<phase::Control>(attempt);
        }
    }
}
