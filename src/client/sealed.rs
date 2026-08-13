use std::{ops, pin, time};

use dope::{
    core::{
        driver::{lifecycle, schedule},
        io,
    },
    manifold::dispatch,
};
use o3::cell::region;

use crate::client;

impl<'step, 'd, 'tls, const ID: u8, P, B, A, C>
    client::ControlInner<'step, 'd, 'tls, ID, P, B, A, C>
where
    'd: 'step,
    P: client::raw::ControlProtocol,
    B: client::BackoffPolicy,
    A: client::EndpointAuthority<'tls>,
    C: client::ConfigProvider,
{
    pub fn protocol_control(&mut self) -> <P as client::raw::ControlProtocol>::Control<'_> {
        let protocol = self.inner.as_mut().protocol_mut();
        // SAFETY: this is the exact protocol installed beneath the client and
        // the returned control cannot outlive this exclusive step borrow.
        unsafe { P::control(protocol) }
    }
}

// SAFETY: `Control` exposes only protocol borrows and slot commands inside one
// step. It cannot move, replace, or drop the client or its retained endpoint.
unsafe impl<'d, 'tls, const ID: u8, P, B, A, C> dispatch::raw::Controlled<'d>
    for client::Dialer<'d, 'tls, ID, P, B, A, C>
where
    P: client::Protocol,
    B: client::BackoffPolicy,
    A: client::EndpointAuthority<'tls>,
    C: client::ConfigProvider,
{
    type Control<'step>
        = client::ControlInner<'step, 'd, 'tls, ID, P, B, A, C>
    where
        Self: 'step,
        'd: 'step;

    unsafe fn control<'step>(self: pin::Pin<&'step mut Self>) -> Self::Control<'step>
    where
        'd: 'step,
    {
        client::ControlInner { inner: self }
    }
}

// SAFETY: `Client` delegates every retained address to its pinned endpoint.
unsafe impl<'d, 'tls, const ID: u8, P, B, A, C> dispatch::raw::Manifold<'d>
    for client::Dialer<'d, 'tls, ID, P, B, A, C>
where
    P: client::Protocol,
    B: client::BackoffPolicy,
    A: client::EndpointAuthority<'tls>,
    C: client::ConfigProvider,
{
    const ID: u8 = ID;
    type Dispatch = dispatch::raw::Plain;
    type Activate = dispatch::raw::Plain;
    type PrePark = dispatch::raw::Retained;
    type Shutdown = dispatch::raw::Plain;

    fn install(self: pin::Pin<&mut Self>, install: &mut lifecycle::Install<'_, 'd>) {
        dispatch::raw::Manifold::install(self.project().inner, install);
    }

    unsafe fn dispatch<'turn>(
        mut self: pin::Pin<&mut Self>,
        ev: io::Event<'d>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut dispatch::raw::Context<'_, '_, 'd, Self::Dispatch>,
    ) -> ops::ControlFlow<io::Event<'d>> {
        // SAFETY: inherited from this forwarding method's installed-owner contract.
        unsafe {
            dispatch::raw::Manifold::dispatch(self.as_mut().project().inner, ev, turn, driver)
        }
    }

    unsafe fn pre_park<'turn>(
        mut self: pin::Pin<&mut Self>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut dispatch::raw::Context<'_, '_, 'd, Self::PrePark>,
    ) {
        let mut this_client = self.as_mut();
        // SAFETY: inherited from this forwarding method's installed-owner contract.
        unsafe {
            dispatch::raw::Manifold::pre_park(
                this_client.as_mut().project().inner,
                turn.reborrow(),
                driver,
            )
        };
        let now = time::Instant::now();
        {
            let mut this = this_client.as_mut().project();
            let mut remaining = *this.event_budget;
            while remaining != 0 {
                let Some(binding) = this.inner.as_mut().handler_mut().pending_close.pop_front()
                else {
                    break;
                };
                remaining -= 1;
                let index = binding.slot.index() as usize;
                if let Some(endpoint) = this.endpoints.get_mut(index)
                    && endpoint.handle == Some(binding.handle)
                {
                    endpoint.handle = None;
                    endpoint.attempt = endpoint.attempt.saturating_add(1);
                    let retry_at = this.backoff.next_retry_at(endpoint.attempt, now);
                    this.retries.remove(index);
                    let _ = this.retries.insert(index, retry_at);
                }
            }
            while remaining != 0 {
                let Some(binding) = this
                    .inner
                    .as_mut()
                    .handler_mut()
                    .pending_established
                    .pop_front()
                else {
                    break;
                };
                remaining -= 1;
                let established = if let Some(endpoint) =
                    this.endpoints.get_mut(binding.slot.index() as usize)
                    && endpoint.handle == Some(binding.handle)
                {
                    endpoint.attempt = 0;
                    true
                } else {
                    false
                };
                if established {
                    this.inner
                        .as_mut()
                        .handler_mut()
                        .protocol
                        .connect(binding.slot);
                }
            }
        }
        let mut connected = false;
        let mut remaining = *this_client.as_ref().project_ref().retry_budget;
        while remaining != 0 {
            let due = {
                let this = this_client.as_mut().project();
                match this.retries.peek() {
                    Some((_, retry_at)) if *retry_at <= now => this.retries.pop().map(|(i, _)| i),
                    _ => None,
                }
            };
            let Some(index) = due else { break };
            remaining -= 1;
            connected |= this_client
                .as_mut()
                .try_connect(client::SlotId::from_index(index as u32));
        }
        if connected {
            // SAFETY: inherited from this forwarding method's installed-owner contract.
            unsafe { dispatch::raw::Manifold::pre_park(this_client.project().inner, turn, driver) };
        }
    }

    fn progress(self: pin::Pin<&Self>, region: &region::Token<'d>) -> schedule::Progress<'d> {
        let this = self.as_ref().project_ref();
        if !this.inner.handler().pending_close.is_empty()
            || !this.inner.handler().pending_established.is_empty()
        {
            return schedule::Progress::Runnable;
        }
        let progress = dispatch::raw::Manifold::progress(this.inner, region);
        match this.retries.peek().map(|(_, retry)| *retry) {
            Some(deadline) => progress.reduce(schedule::Progress::until(region, deadline)),
            None => progress,
        }
    }

    fn shutdown<'turn>(
        mut self: pin::Pin<&mut Self>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut dispatch::raw::Context<'_, '_, 'd, Self::Shutdown>,
    ) {
        let mut this = self.as_mut().project();
        dispatch::raw::Manifold::shutdown(this.inner.as_mut(), turn, driver);

        this.retries.clear();
        let handler = this.inner.as_mut().handler_mut();
        for endpoint in this.endpoints {
            let Some(handle) = endpoint.handle.take() else {
                continue;
            };
            if let Some(slot) = handler.unbind(handle) {
                handler.protocol.close(slot);
            }
        }
        handler.pending_close.clear();
        handler.pending_established.clear();
    }

    fn finish(self: pin::Pin<&mut Self>, finish: &mut lifecycle::Finalize<'_, 'd>) {
        dispatch::raw::Manifold::finish(self.project().inner, finish);
    }
}
