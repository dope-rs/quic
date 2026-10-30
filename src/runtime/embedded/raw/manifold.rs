use crate::conn::id;
use crate::runtime::embedded::{Drives, link::Link};
use crate::runtime::{embedded, mux::handler};
use crate::stream;
use dope::core::driver::{route, schedule};
use dope::manifold::app::dispatch;
use o3::buffer::resident;
use std::pin;

// SAFETY: the generated dispatcher pins the endpoint through shutdown and
// finish; the ready slot and every identity are branded to that exact driver.
unsafe impl<'d, const ID: u8, H, B, S> dispatch::raw::Manifold<'d>
    for embedded::Endpoint<'d, ID, H, B, S>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv,
    S: Drives<'d, ID, H, B>,
{
    type Route = route::KeyTag<ID>;
    const COORDS: usize = 0;
    type Dispatch = dispatch::raw::Omit;
    type Install = Self;
    type Finish = Self;
    type Activate = dispatch::raw::Omit;
    type Probe = Self;
    type PrePark = dispatch::raw::Retained;
    type Shutdown = dispatch::raw::Plain;

    unsafe fn pre_park<'a, 'turn, 'root>(
        self: pin::Pin<&'a mut Self>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut dispatch::raw::Context<'_, 'root, 'd, Self::PrePark>,
    ) -> pin::Pin<&'a mut Self>
    where
        Self: 'root,
    {
        S::pre_park(self, turn, driver)
    }

    fn shutdown<'a, 'turn, 'root>(
        mut self: pin::Pin<&'a mut Self>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut dispatch::raw::Context<'_, 'root, 'd, Self::Shutdown>,
    ) -> pin::Pin<&'a mut Self>
    where
        Self: 'root,
    {
        self.as_mut()
            .shutdown_at(turn.app(), driver.driver_ref().clock().now());
        self
    }
}

// SAFETY: the link and provided owners are branded by the same driver; the
// enclosing generation retains and reclaims every issued owner after dispatch.
unsafe impl<'d, const ROUTE: u8, const FROM: u8, const TO: u8> dispatch::raw::Manifold<'d>
    for Link<'d, ROUTE, FROM, TO>
{
    type Route = route::KeyTag<ROUTE>;
    const COORDS: usize = 0;
    type Dispatch = dispatch::raw::Omit;
    type Install = dispatch::raw::Omit;
    type Finish = dispatch::raw::Omit;
    type Activate = dispatch::raw::Omit;
    type Probe = dispatch::raw::Omit;
    type PrePark = dispatch::raw::Plain;
    type Shutdown = dispatch::raw::Plain;

    unsafe fn pre_park<'a, 'turn, 'root>(
        self: pin::Pin<&'a mut Self>,
        _: schedule::Turn<'turn, 'd>,
        _: &mut dispatch::raw::Context<'_, 'root, 'd, Self::PrePark>,
    ) -> pin::Pin<&'a mut Self>
    where
        Self: 'root,
    {
        self.as_ref().get_ref().wake();
        self
    }

    fn shutdown<'a, 'turn, 'root>(
        self: pin::Pin<&'a mut Self>,
        _: schedule::Turn<'turn, 'd>,
        _: &mut dispatch::raw::Context<'_, 'root, 'd, Self::Shutdown>,
    ) -> pin::Pin<&'a mut Self>
    where
        Self: 'root,
    {
        self
    }
}
