use std::{ops, pin};

use dope::{
    core::{
        driver::{lifecycle, schedule},
        io,
    },
    manifold::dispatch,
};
use o3::cell::region;

use crate::{conn::server, endpoint, mux};

impl<'step, 'd, 'tls, const ID: u8, H, P, B> endpoint::ControlInner<'step, 'd, 'tls, ID, H, P, B>
where
    'd: 'step,
    H: endpoint::raw::ControlHandler<'d, ID, B>,
    P: server::Policy,
    B: endpoint::EndpointBuffer<'d>,
{
    pub fn handler_control(
        &mut self,
    ) -> <H as endpoint::raw::ControlHandler<'d, ID, B>>::Control<'_> {
        let handler = self.inner.as_mut().handler_mut();
        // SAFETY: this is the exact handler installed beneath the endpoint and
        // the returned control cannot outlive this exclusive step borrow.
        unsafe { H::control(handler) }
    }
}

// SAFETY: `Control` exposes only handler/connection commands borrowed inside
// one step. It cannot move, replace, or drop the endpoint or retained UDP mux.
unsafe impl<'d, 'tls, const ID: u8, H, P, B> dispatch::raw::Controlled<'d>
    for endpoint::EndpointInner<'d, 'tls, ID, H, P, B>
where
    H: mux::Handler<ID, B>,
    P: server::Policy,
    B: endpoint::EndpointBuffer<'d>,
{
    type Control<'step>
        = endpoint::PooledControl<'step, 'd, 'tls, ID, H, P, B>
    where
        Self: 'step,
        'd: 'step;

    unsafe fn control<'step>(self: pin::Pin<&'step mut Self>) -> Self::Control<'step>
    where
        'd: 'step,
    {
        endpoint::ControlInner { inner: self }
    }
}

// SAFETY: `Endpoint` owns the UDP and mux lifecycle through finish.
unsafe impl<'d, 'tls, const ID: u8, H, P, B> dispatch::raw::Manifold<'d>
    for endpoint::EndpointInner<'d, 'tls, ID, H, P, B>
where
    H: mux::Handler<ID, B>,
    P: server::Policy,
    B: endpoint::EndpointBuffer<'d>,
{
    const ID: u8 = ID;
    type Dispatch = dispatch::raw::Plain;
    type Activate = dispatch::raw::Plain;
    type PrePark = dispatch::raw::Retained;
    type Shutdown = dispatch::raw::Plain;

    fn install(self: pin::Pin<&mut Self>, install: &mut lifecycle::Install<'_, 'd>) {
        dispatch::raw::Manifold::install(self.project().udp, install);
    }

    unsafe fn dispatch<'turn>(
        self: pin::Pin<&mut Self>,
        event: io::Event<'d>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut dispatch::raw::Context<'_, '_, 'd, Self::Dispatch>,
    ) -> ops::ControlFlow<io::Event<'d>> {
        unsafe { dispatch::raw::Manifold::dispatch(self.project().udp, event, turn, driver) }
    }

    unsafe fn pre_park<'turn>(
        self: pin::Pin<&mut Self>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut dispatch::raw::Context<'_, '_, 'd, Self::PrePark>,
    ) {
        unsafe { dispatch::raw::Manifold::pre_park(self.project().udp, turn, driver) };
    }

    fn progress(self: pin::Pin<&Self>, region: &region::Token<'d>) -> schedule::Progress<'d> {
        dispatch::raw::Manifold::progress(self.project_ref().udp, region)
    }

    fn shutdown<'turn>(
        self: pin::Pin<&mut Self>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut dispatch::raw::Context<'_, '_, 'd, Self::Shutdown>,
    ) {
        dispatch::raw::Manifold::shutdown(self.project().udp, turn, driver);
    }

    fn finish(self: pin::Pin<&mut Self>, finish: &mut lifecycle::Finalize<'_, 'd>) {
        dispatch::raw::Manifold::finish(self.project().udp, finish);
    }
}
