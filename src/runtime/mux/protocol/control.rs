use std::time;

use crate::{conn, errors, runtime::mux, stream};
use conn::{id, scope};
use mux::{auth, handler, protocol, router};

pub(crate) type Result<T> = std::result::Result<T, errors::Access>;

pub(crate) trait Control<
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
>
{
    fn with<R>(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
        now: time::Instant,
        f: impl for<'scope> FnOnce(scope::Turn<'scope, DOMAIN, B, A::Send>) -> R,
    ) -> Result<R>;

    fn close_at(&mut self, handle: id::Handle<A::Identity, DOMAIN>, now: time::Instant);

    fn try_close_at(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
        now: time::Instant,
    ) -> Result<()>;
}

impl<'a, 'tls, H, const DOMAIN: u8, B, A> Control<A, H, DOMAIN, B>
    for protocol::Io<'a, 'tls, H, DOMAIN, B, A>
where
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
{
    fn with<R>(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
        now: time::Instant,
        f: impl for<'scope> FnOnce(scope::Turn<'scope, DOMAIN, B, A::Send>) -> R,
    ) -> Result<R> {
        self.mux
            .as_mut()
            .project()
            .state
            .with(handle, now, |scope| f(scope::Turn::new(scope, now)))
    }

    fn close_at(&mut self, handle: id::Handle<A::Identity, DOMAIN>, now: time::Instant) {
        let _ = router::Turn::new(self.mux.as_mut()).try_remove(handle, now);
    }

    fn try_close_at(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
        now: time::Instant,
    ) -> Result<()> {
        router::Turn::new(self.mux.as_mut()).try_remove(handle, now)
    }
}
