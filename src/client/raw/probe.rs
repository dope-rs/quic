use crate::client::{self, auth, protocol};
use crate::runtime::{endpoint::owner, routing};
use dope::core::driver::{route, schedule};
use dope::manifold::app::dispatch;
use dope::manifold::app::dispatch::event;

// SAFETY: unit selection represents the client-owned event and retry work;
// the inner plan is selected only after that work permits an inner query.
unsafe impl<'pool, 'd, const ID: u8, P, B, A, C, R> dispatch::raw::Probe<'d, Self>
    for client::Dialer<'pool, 'd, ID, P, B, A, C, R>
where
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    A: auth::Mode,
    A::Binding: owner::Binding<'d, ID>,
    C: client::ConfigSource,
    R: routing::PeerRoute,
    Self: dispatch::raw::Projection<'d>,
    <Self as dispatch::raw::Projection<'d>>::Inner: dispatch::raw::Manifold<
            'd,
            Route = route::KeyTag<ID>,
            PrePark = dispatch::raw::Retained,
            Shutdown = dispatch::raw::Plain,
        > + event::Drive<'d, Access = dispatch::raw::Plain>,
{
    type Plan = ();

    fn select() -> Option<Self::Plan> {
        Some(())
    }

    fn run(call: dispatch::raw::Call<'_, '_, '_, 'd, Self, Self::Plan>) -> schedule::Progress<'d> {
        let owner = call.owner();
        let core = owner.project_ref().inner.project_ref();
        if core.endpoint.handler().lifecycle().has_events() {
            return schedule::Progress::Runnable;
        }
        let retry = core.endpoint.handler().lifecycle().next_retry();
        let clock = call.clock();
        let progress =
            <<<Self as dispatch::raw::Projection<'d>>::Inner as dispatch::raw::Manifold<'d>>::Probe as dispatch::raw::Probe<
                'd,
                <Self as dispatch::raw::Projection<'d>>::Inner,
            >>::progress(
                dispatch::raw::Projection::inner(owner),
                call.tokens(),
                clock,
            );
        match retry {
            Some(retry_at) => {
                progress.reduce(schedule::Progress::until(clock.deadline_at(retry_at)))
            }
            None => progress,
        }
    }
}
