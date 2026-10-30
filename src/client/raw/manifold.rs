use crate::client::{self, auth, protocol};
use crate::runtime::{brand, endpoint::owner, routing};
use dope::core::driver::{route, schedule};
use dope::manifold::app::dispatch;
use dope::manifold::app::dispatch::event;
use std::pin;

// SAFETY: all retained addresses belong to the structurally pinned endpoint.
unsafe impl<'pool, 'd, const ID: u8, P, B, A, C, R> dispatch::raw::Manifold<'d>
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
    type Route = route::KeyTag<ID>;
    type Dispatch = event::Driven<dispatch::raw::Plain>;
    type Install = dispatch::raw::Projected<Self>;
    type Finish = dispatch::raw::Projected<Self>;
    type Activate = dispatch::raw::Projected<Self>;
    type Probe = Self;
    type PrePark = dispatch::raw::Retained;
    type Shutdown = dispatch::raw::Plain;

    const COORDS: usize =
        <<Self as dispatch::raw::Projection<'d>>::Inner as dispatch::raw::Manifold<'d>>::COORDS;

    unsafe fn pre_park<'a, 'turn, 'root>(
        mut self: pin::Pin<&'a mut Self>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut dispatch::raw::Context<'_, 'root, 'd, Self::PrePark>,
    ) -> pin::Pin<&'a mut Self>
    where
        Self: 'root,
    {
        // SAFETY: inherited from this forwarding method's installed-root contract.
        unsafe {
            dispatch::raw::Manifold::pre_park(
                self.as_mut().project().inner.project().endpoint,
                turn.reborrow(),
                driver,
            )
        };
        let budget = self.as_ref().get_ref().limits.events.get();
        self.as_mut().project().inner.drain_events(budget);
        let mut changed = false;
        let mut left = self.as_ref().get_ref().limits.retries.get();
        let now = driver.driver_ref().clock().now();
        while left != 0 {
            let Some(did) =
                brand::Token::with(|scope| self.as_mut().project().inner.try_due(scope, now))
            else {
                break;
            };
            left -= 1;
            changed |= did;
        }
        if changed {
            // SAFETY: the same installed endpoint remains structurally pinned.
            unsafe {
                dispatch::raw::Manifold::pre_park(
                    self.as_mut().project().inner.project().endpoint,
                    turn,
                    driver,
                )
            };
        }
        self
    }

    fn shutdown<'a, 'turn, 'root>(
        mut self: pin::Pin<&'a mut Self>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut dispatch::raw::Context<'_, 'root, 'd, Self::Shutdown>,
    ) -> pin::Pin<&'a mut Self>
    where
        Self: 'root,
    {
        {
            let this = self.as_mut().project();
            dispatch::raw::Manifold::shutdown(this.inner.project().endpoint, turn, driver);
        }
        self.as_mut().close_all(driver.driver_ref().clock().now());
        self
    }
}
