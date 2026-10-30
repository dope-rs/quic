use crate::runtime::brand;

use std::time;

use crate::conn::id;
use crate::runtime::mux::app;
use crate::runtime::mux::{auth, handler, router};
use crate::runtime::routing::registry;
use crate::{errors, runtime::mux, stream};

pub(in crate::runtime::mux) struct Set<
    'a,
    'id,
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
> {
    brand: brand::Token<'a>,
    slots: registry::Scope<'a, 'id, H::Connection, DOMAIN, B, A::Send, A::Session>,
    binding: &'a mut router::Binding<A, DOMAIN>,
    shutdown: bool,
    now: time::Instant,
}

pub(in crate::runtime::mux) struct Selected<
    'a,
    'id,
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
    const QUEUED: bool,
> {
    set: Set<'a, 'id, A, H, DOMAIN, B>,
    key: registry::Key<'id>,
}

impl<'a, 'id, A, H, const DOMAIN: u8, B> Set<'a, 'id, A, H, DOMAIN, B>
where
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
{
    pub(super) fn new(
        brand: brand::Token<'a>,
        slots: registry::Scope<'a, 'id, H::Connection, DOMAIN, B, A::Send, A::Session>,
        binding: &'a mut router::Binding<A, DOMAIN>,
        shutdown: bool,
        now: time::Instant,
    ) -> Self {
        Self {
            brand,
            slots,
            binding,
            shutdown,
            now,
        }
    }
}

impl<'a, 'id, A, H, const DOMAIN: u8, B> app::Set<H, DOMAIN, B, A::Send, A::Identity>
    for Set<'a, 'id, A, H, DOMAIN, B>
where
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
{
    type Ready = Selected<'a, 'id, A, H, DOMAIN, B, true>;
    type Exact = Selected<'a, 'id, A, H, DOMAIN, B, false>;

    fn has_ready(&self) -> bool {
        !self.slots.is_empty_in::<{ mux::APPLICATION_QUEUE }>()
    }

    fn next(self) -> Option<Self::Ready> {
        let key = self.slots.front::<{ mux::APPLICATION_QUEUE }>()?;
        if self.slots.get(key).conn.view().lifecycle().is_closing() {
            return None;
        }
        Some(Selected { set: self, key })
    }

    fn try_select(
        self,
        handle: id::Handle<A::Identity, DOMAIN>,
    ) -> Result<Self::Exact, app::Rejected<Self>> {
        if self.shutdown {
            return Err(app::Rejected::new(self, errors::Access::Closed));
        }
        let Some(key) = self.slots.bind(self.binding.domain, handle) else {
            return Err(app::Rejected::new(self, errors::Access::InvalidHandle));
        };
        if self.slots.get(key).conn.view().lifecycle().is_closing() {
            return Err(app::Rejected::new(self, errors::Access::Closed));
        }
        Ok(Selected { set: self, key })
    }
}

impl<'a, 'id, A, H, const DOMAIN: u8, B, const QUEUED: bool>
    app::Selected<H, DOMAIN, B, A::Send, A::Identity> for Selected<'a, 'id, A, H, DOMAIN, B, QUEUED>
where
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
{
    fn run<R>(
        mut self,
        op: impl for<'scope> FnOnce(
            app::Connection<'scope, H::Connection, DOMAIN, B, A::Send, A::Identity>,
        ) -> R,
    ) -> R {
        router::State::<A, H::Connection, DOMAIN, B>::run_selected::<_, QUEUED>(
            self.set.brand,
            &mut self.set.slots,
            self.key,
            self.set.binding,
            self.set.now,
            op,
        )
    }
}
