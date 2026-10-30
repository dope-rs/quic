use crate::runtime::endpoint::control::actions;
use std::{pin, time};

use dope::core::driver::schedule::clock;
use o3::mem::Rejected;

use crate::client::{self, auth, control::Sender, life, protocol};
use crate::errors;
use crate::proto::datagram;
use crate::runtime::brand;
use crate::runtime::endpoint::{self, control::SendError, owner};
use crate::runtime::routing;

/// The dialer binds its protocol bridge and receive storage to the same endpoint.
type Connection<'pool, 'd, const ID: u8, P, B, A, R> = endpoint::Endpoint<
    'd,
    ID,
    client::Bridge<'d, ID, P, A, B, R>,
    <P as protocol::Protocol<'d>>::Receive,
    endpoint::Idle,
    <A as auth::Mode>::Binding,
    datagram::Sealed<'pool>,
>;

#[pin_project::pin_project]
pub(in crate::client) struct Engine<
    'pool,
    'd,
    const ID: u8,
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    A: auth::Mode,
    C: client::ConfigSource,
    R: routing::PeerRoute,
> where
    A::Binding: owner::Binding<'d, ID>,
{
    #[pin]
    pub(in crate::client) endpoint: Connection<'pool, 'd, ID, P, B, A, R>,
    config: C,
}

impl<'pool, 'd, const ID: u8, P, B, A, C, R> Engine<'pool, 'd, ID, P, B, A, C, R>
where
    P: protocol::Protocol<'d>,
    B: client::Backoff,
    A: auth::Mode,
    A::Binding: owner::Binding<'d, ID>,
    C: client::ConfigSource,
    R: routing::PeerRoute,
{
    pub(in crate::client) fn new(
        endpoint: Connection<'pool, 'd, ID, P, B, A, R>,
        config: C,
    ) -> Self {
        Self { endpoint, config }
    }

    pub(in crate::client) fn try_due(
        mut self: pin::Pin<&mut Self>,
        scope: brand::Token<'_>,
        now: clock::Moment<'d>,
    ) -> Option<bool> {
        let due = now
            .at(self.as_ref())
            .apply(|core, raw| core.get_ref().endpoint.handler().lifecycle().next_due(raw))?;
        let due = match due.transpose() {
            Ok(due) => due,
            Err(failure) => {
                let (due, error) = failure.into_parts();
                return self.failed(scope, due, now, error.into());
            }
        };
        enum Failure {
            Fresh(errors::Connect),
            Reconnect(errors::Reconnect),
        }
        let auth = due.auth();
        let config = self
            .as_mut()
            .project()
            .config
            .config(due.scope(scope.reborrow(), now));
        let Some(config) = config else {
            now.at(self.as_mut()).apply(|core, raw| {
                core.project().endpoint.handler_mut().life_mut().defer_due(
                    scope.reborrow(),
                    due,
                    raw,
                );
            });
            return Some(false);
        };
        let again = self
            .as_mut()
            .project()
            .endpoint
            .handler_mut()
            .life_mut()
            .take_again(&due);
        let result = now.at(self.as_mut()).apply(|core, raw| {
            let mut this = core.project();
            match again {
                Some(again) => auth
                    .reconnect(
                        scope.reborrow(),
                        this.endpoint.as_mut(),
                        config,
                        again,
                        due.route(),
                        raw,
                    )
                    .map_err(Failure::Reconnect),
                None => auth
                    .connect(
                        scope.reborrow(),
                        this.endpoint.as_mut(),
                        due.address(),
                        config,
                        due.route(),
                        raw,
                    )
                    .map_err(Failure::Fresh),
            }
        });
        match result {
            Ok(handle) => {
                self.project()
                    .endpoint
                    .handler_mut()
                    .life_mut()
                    .bind_due(due, handle);
                Some(true)
            }
            Err(failure) => {
                let error = match failure {
                    Failure::Fresh(error) => error,
                    Failure::Reconnect(failure) => {
                        let (error, again) = failure.into_parts();
                        if let Some(again) = again {
                            self.as_mut()
                                .project()
                                .endpoint
                                .handler_mut()
                                .life_mut()
                                .put_again(&due, again);
                        }
                        error
                    }
                };
                self.failed(scope, due, now, error)
            }
        }
    }

    fn failed<T>(
        self: pin::Pin<&mut Self>,
        scope: brand::Token<'_>,
        due: life::Due<T, R>,
        now: clock::Moment<'d>,
        error: errors::Connect,
    ) -> Option<bool> {
        let mut this = self.project();
        this.endpoint
            .as_mut()
            .handler_mut()
            .protocol_pin()
            .failed(due.scope(scope.reborrow(), now), &error);
        let life = this.endpoint.handler_mut().life_mut();
        now.at(life)
            .apply(|life, raw| life.defer_due(scope, due, raw));
        Some(false)
    }

    pub(in crate::client) fn drain_events(self: pin::Pin<&mut Self>, budget: usize) -> usize {
        self.project().endpoint.handler_mut().drain_events(budget)
    }

    pub(super) fn close_at(mut self: pin::Pin<&mut Self>, now: time::Instant) {
        self.as_mut()
            .project()
            .endpoint
            .handler_mut()
            .life_mut()
            .seal();
        let capacity = self.as_ref().get_ref().endpoint.handler().lifecycle().len();
        for index in 0..capacity {
            let handle = self
                .as_ref()
                .get_ref()
                .endpoint
                .handler()
                .lifecycle()
                .handle_at(index);
            if let Some(handle) = handle {
                actions::close(self.as_mut().project().endpoint, handle, now);
            }
        }
        self.as_mut().drain_events(usize::MAX);
    }

    pub(super) fn restart_at(mut self: pin::Pin<&mut Self>, now: time::Instant) {
        let capacity = self.as_ref().get_ref().endpoint.handler().lifecycle().len();
        for index in 0..capacity {
            let handle = self
                .as_ref()
                .get_ref()
                .endpoint
                .handler()
                .lifecycle()
                .handle_at(index);
            if let Some(handle) = handle {
                actions::close(self.as_mut().project().endpoint, handle, now);
            }
        }
        self.as_mut().drain_events(usize::MAX);
    }

    pub(super) fn try_send_at(
        mut self: pin::Pin<&mut Self>,
        slot: client::SlotId,
        data: Vec<u8>,
        now: time::Instant,
    ) -> Result<(), errors::SendFailure<Vec<u8>>> {
        let Some(handle) = self
            .as_ref()
            .get_ref()
            .endpoint
            .handler()
            .lifecycle()
            .handle(slot)
        else {
            return Err(errors::SendFailure::Closed(data));
        };
        match actions::try_send_datagram(self.as_mut().project().endpoint, handle, data, now) {
            Err(errors::SendFailure::Closed(data)) => {
                actions::close(self.project().endpoint, handle, now);
                Err(errors::SendFailure::Closed(data))
            }
            result => result,
        }
    }

    pub(super) fn try_pool_at(
        mut self: pin::Pin<&mut Self>,
        slot: client::SlotId,
        packet: datagram::Packet<'pool>,
        now: time::Instant,
    ) -> Result<(), errors::SendFailure<datagram::Packet<'pool>>> {
        let Some(handle) = self
            .as_ref()
            .get_ref()
            .endpoint
            .handler()
            .lifecycle()
            .handle(slot)
        else {
            return Err(errors::SendFailure::Closed(packet));
        };
        let sender = match actions::try_sender(self.as_mut().project().endpoint, now) {
            Ok(sender) => Sender::new(sender),
            Err(SendError::Full) => {
                return Err(errors::SendFailure::Full(packet));
            }
            Err(SendError::Closed) => {
                actions::close(self.project().endpoint, handle, now);
                return Err(errors::SendFailure::Closed(packet));
            }
        };
        sender.try_send(slot, packet).map_err(Rejected::discard)
    }
}
