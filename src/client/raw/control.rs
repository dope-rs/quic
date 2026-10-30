use crate::client::control;
use crate::client::{self, auth, protocol};
use crate::runtime::{endpoint::owner, routing};
use dope::manifold::app::dispatch;

// SAFETY: the control contains exactly one exclusive pinned borrow of this
// installed owner. Its auth parameter retains the same TLS lifetime.
unsafe impl<'pool, 'd, const ID: u8, P, B, A, C, R> dispatch::raw::Control<'d>
    for client::Dialer<'pool, 'd, ID, P, B, A, C, R>
where
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    A: auth::Mode,
    A::Binding: owner::Binding<'d, ID>,
    C: client::ConfigSource,
    R: routing::PeerRoute,
{
    type View<'step>
        = control::Control<'step, 'pool, 'd, ID, P, B, A, C, R>
    where
        Self: 'step,
        'd: 'step;

    fn view<'step>(owner: dispatch::raw::Installed<'step, 'd, Self>) -> Self::View<'step>
    where
        'd: 'step,
    {
        control::Control::new(owner)
    }
}
