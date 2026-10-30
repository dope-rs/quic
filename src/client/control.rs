use core::driver;
use dope::core;
use dope::manifold::app::dispatch;
use driver::schedule::clock;
use o3::{buffer::resident, mem::Rejected};

use crate::client;
use crate::client::auth;
use crate::client::dialer;
use crate::client::protocol;
use crate::conn::scope;
use crate::errors;
use crate::proto::datagram;
use crate::runtime::endpoint::{control, control::actions, owner};
use crate::runtime::mux::handler::hook::writable;
use crate::runtime::routing;

/// One-pointer coordination view retaining the owner and TLS lifetimes.
#[repr(transparent)]
pub struct Control<
    'step,
    'pool,
    'd,
    const ID: u8,
    P,
    B,
    A = auth::Owned,
    C = client::StaticConfig,
    R = routing::Plain,
> where
    'd: 'step,
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    A: auth::Mode,
    A::Binding: owner::Binding<'d, ID>,
    C: client::ConfigSource,
    R: routing::PeerRoute,
{
    inner: dispatch::raw::Installed<'step, 'd, client::Dialer<'pool, 'd, ID, P, B, A, C, R>>,
}

/// One admitted pooled-output position with logical client slot routing.
#[repr(transparent)]
#[must_use = "a sender retains one vacant endpoint output position"]
pub struct Sender<S>(S);

impl<S> Sender<S> {
    pub(super) fn new(inner: S) -> Self {
        Self(inner)
    }
}

type Pooled<'a, 'pool, 'd, const ID: u8, P, B, A, R> = Sender<
    control::Sender<
        'a,
        'd,
        ID,
        client::Bridge<'d, ID, P, A, B, R>,
        <P as protocol::Protocol<'d>>::Receive,
        <A as auth::Mode>::Binding,
        datagram::Sealed<'pool>,
    >,
>;

impl<'pool, 'd, const ID: u8, P, B, A, R> Pooled<'_, 'pool, 'd, ID, P, B, A, R>
where
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    A: auth::Mode,
    A::Binding: owner::Binding<'d, ID>,
    R: routing::PeerRoute,
{
    pub fn try_send(
        self,
        slot: client::SlotId,
        packet: datagram::Packet<'pool>,
    ) -> Result<(), Rejected<Self, errors::SendFailure<datagram::Packet<'pool>>>> {
        let Some(handle) = self.0.handler().lifecycle().handle(slot) else {
            return Err(Rejected::new(self, errors::SendFailure::Closed(packet)));
        };
        match self.0.try_send(handle, packet) {
            Ok(()) => Ok(()),
            Err(rejected) => {
                let (mut sender, cause) = rejected.into_parts();
                if matches!(cause, errors::SendFailure::Closed(_)) {
                    sender.close(handle);
                }
                Err(Rejected::new(Self::new(sender), cause))
            }
        }
    }
}

/// Client mutations bound to one sampled driver turn.
#[repr(transparent)]
pub struct Turn<'turn, 'd, C: ?Sized>(clock::At<'d, &'turn mut C>);

impl<'step, 'pool, 'd, const ID: u8, P, B, A, C, R> Control<'step, 'pool, 'd, ID, P, B, A, C, R>
where
    'd: 'step,
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    A: auth::Mode,
    A::Binding: owner::Binding<'d, ID>,
    C: client::ConfigSource,
    R: routing::PeerRoute,
{
    pub(super) fn new(
        inner: dispatch::raw::Installed<'step, 'd, client::Dialer<'pool, 'd, ID, P, B, A, C, R>>,
    ) -> Self {
        Self { inner }
    }

    pub fn protocol(&self) -> &P {
        self.inner.as_ref().get_ref().protocol()
    }

    /// Consumes the coalesced retry hint without granting send capacity.
    pub fn take(&mut self) -> writable::Receipt {
        self.inner
            .as_mut()
            .project()
            .inner
            .project()
            .endpoint
            .handler_mut()
            .take()
    }

    pub fn path_stats(&self, slot: client::SlotId) -> Option<client::PathStats> {
        self.inner.as_ref().get_ref().path_stats(slot)
    }

    pub fn active(&self) -> usize {
        self.inner.as_ref().get_ref().active_len()
    }

    pub fn total(&self) -> usize {
        self.inner.as_ref().get_ref().len()
    }

    pub fn live(&self) -> usize {
        self.inner.as_ref().get_ref().live_len()
    }

    /// Prevents every future connection attempt while retaining live
    /// connections and their protocol owners.
    pub fn seal(&mut self) {
        self.inner.as_mut().seal();
    }

    /// Binds mutations to the exact clock sample installed for this driver turn.
    pub fn at<'turn>(&'turn mut self, clock: clock::Clock<'turn, 'd>) -> Turn<'turn, 'd, Self> {
        Turn(clock.at(self))
    }
}

impl<'turn, 'step, 'pool, 'd, const ID: u8, P, B, A, C, R>
    Turn<'turn, 'd, Control<'step, 'pool, 'd, ID, P, B, A, C, R>>
where
    'd: 'step,
    'step: 'turn,
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    A: auth::Mode,
    A::Binding: owner::Binding<'d, ID>,
    C: client::ConfigSource,
    R: routing::PeerRoute,
{
    pub fn close_all(&mut self) {
        self.0
            .apply_mut(|ctl, now| ctl.inner.as_mut().close_all(now));
    }

    pub fn restart_all(&mut self) {
        self.0
            .apply_mut(|ctl, now| ctl.inner.as_mut().restart_all(now));
    }

    pub fn try_datagram(
        &mut self,
        slot: client::SlotId,
        data: Vec<u8>,
    ) -> Result<(), errors::SendFailure<Vec<u8>>> {
        self.0
            .apply_mut(|ctl, now| ctl.inner.as_mut().try_send(slot, data, now))
    }

    pub fn with_conn<T>(
        &mut self,
        slot: client::SlotId,
        op: impl for<'scope> FnOnce(
            scope::Temporal<'scope, 'd, ID, P::Receive, resident::Shared<'d>>,
        ) -> T,
    ) -> Result<T, errors::Access> {
        self.0.apply_mut(|ctl, now| {
            ctl.inner
                .as_mut()
                .with_conn(dialer::Connection::Current(slot), now, op)
        })
    }

    pub fn with_attempt<T>(
        &mut self,
        try_id: client::AttemptId,
        op: impl for<'scope> FnOnce(
            scope::Temporal<'scope, 'd, ID, P::Receive, resident::Shared<'d>>,
        ) -> T,
    ) -> Result<T, errors::Access> {
        self.0.apply_mut(|ctl, now| {
            ctl.inner
                .as_mut()
                .with_conn(dialer::Connection::Attempt(try_id), now, op)
        })
    }

    /// Acquires one output position before selecting a logical client slot.
    pub fn try_sender(
        self,
    ) -> Result<Pooled<'turn, 'pool, 'd, ID, P, B, A, R>, control::SendError> {
        self.0.apply(|ctl, now| {
            let inner =
                actions::try_sender(ctl.inner.as_mut().project().inner.project().endpoint, now)?;
            Ok(Sender::new(inner))
        })
    }

    pub fn try_pooled(
        &mut self,
        slot: client::SlotId,
        packet: datagram::Packet<'pool>,
    ) -> Result<(), errors::SendFailure<datagram::Packet<'pool>>> {
        self.0
            .apply_mut(|ctl, now| ctl.inner.as_mut().try_packet(slot, packet, now))
    }
}

impl<'step, 'pool, 'd, const ID: u8, P, B, A, C, R> Control<'step, 'pool, 'd, ID, P, B, A, C, R>
where
    'd: 'step,
    P: protocol::Control<'d>,
    B: client::Backoff,
    A: auth::Mode,
    A::Binding: owner::Binding<'d, ID>,
    C: client::ConfigSource,
    R: routing::PeerRoute,
{
    pub fn protocol_mut(&mut self) -> <P as protocol::Control<'d>>::View<'_> {
        let proto = self.inner.project(|dialer| dialer.protocol_mut());
        <P as protocol::Control<'d>>::view(proto)
    }
}
