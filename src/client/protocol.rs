use crate::runtime::mux::handler::hook::wire::packet;
use crate::runtime::mux::handler::hook::writable;
use std::net;
use std::pin;

use dope::manifold::app::dispatch;
use o3::buffer::resident;

use crate::conn::{id, stream::Event};
use crate::runtime::receive::Storage;
use crate::wire::stream::Id;
use crate::{client, errors};

pub trait Protocol<'d> {
    type Receive: Storage<'d, resident::Shared<'d>>;
    type Writable: writable::Interest;

    fn connect<'scope>(self: pin::Pin<&'scope mut Self>, slot: client::SlotScope<'scope>);

    fn failed(
        self: pin::Pin<&mut Self>,
        attempt: client::AttemptScope<'_, 'd>,
        error: &errors::Connect,
    );

    fn datagram<'scope>(
        self: pin::Pin<&'scope mut Self>,
        slot: client::SlotScope<'scope>,
        data: Self::Receive,
    );

    /// Delivers bytes and clean receive EOF status for the currently bound attempt.
    /// Process present bytes before `end`; absent data is delivered only at EOF.
    /// Retained receive credit can allow a duplicate FIN to repeat the end status.
    fn stream<'scope>(
        self: pin::Pin<&'scope mut Self>,
        slot: client::SlotScope<'scope>,
        id: Id,
        data: Option<Self::Receive>,
        end: bool,
    );

    /// Delivers peer Reset and Stopped events for the currently bound attempt.
    fn stream_event<'scope>(
        self: pin::Pin<&'scope mut Self>,
        slot: client::SlotScope<'scope>,
        event: Event,
    );

    fn close<'scope>(self: pin::Pin<&'scope mut Self>, slot: client::SlotScope<'scope>);

    fn packet(
        self: pin::Pin<&mut Self>,
        from: net::SocketAddr,
        error: packet::Failure<'_>,
        len: usize,
    );

    fn certificate<const DOMAIN: u8>(
        self: pin::Pin<&mut Self>,
        handle: id::Handle<id::Driver<'d>, DOMAIN>,
        from: net::SocketAddr,
        failure: &rustls::Error,
    );
}

/// Custom control construction from the exact installed protocol loan.
pub trait Control<'d>: Protocol<'d> + Sized {
    type View<'step>
    where
        Self: 'step,
        'd: 'step;

    fn view<'step>(protocol: dispatch::raw::Loan<'step, 'd, Self>) -> Self::View<'step>
    where
        'd: 'step;
}
