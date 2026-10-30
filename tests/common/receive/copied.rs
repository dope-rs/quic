use dope_quic::conn::id;
use dope_quic::conn::stream::Event;
use dope_quic::errors;
use dope_quic::proto::epoch;
use dope_quic::runtime::mux::handler;
use dope_quic::runtime::mux::handler::hook::data::{release, stream};
use dope_quic::runtime::mux::handler::hook::life::{create, ready};
use dope_quic::runtime::mux::handler::hook::set;
use dope_quic::runtime::mux::handler::hook::wire::cert;
use dope_quic::runtime::mux::output::Flight;
use dope_quic::runtime::mux::router::Router;
use dope_quic::runtime::mux::{self, app};
use dope_quic::stream::RecvBuffer;
use dope_quic::wire::stream::Id;
use o3::buffer::storage;
use std::{net::SocketAddr, pin::Pin, time::Instant};

pub struct Capture<F> {
    pub ready: Option<id::Handle>,
    pub readable: Option<Id>,
    pub released: usize,
    pub certificate: F,
}

impl<F: for<'a> FnMut(&'a rustls::Error) + Unpin>
    handler::Handler<0, RecvBuffer<'_>, storage::Shared> for Capture<F>
{
    type Connection = ();
    type Create = create::Unit;
    type Events = set::Set<set::On, set::Off, set::On, set::Off, set::On>;
}

impl<F: for<'a> FnMut(&'a rustls::Error) + Unpin>
    release::Sink<0, RecvBuffer<'_>, storage::Shared, id::Static> for Capture<F>
{
    fn release(event: release::Event<'_, Self, 0, id::Static>) -> app::Readiness {
        let (this, _, _) = event.into_parts();
        this.get_mut().released += 1;
        app::Readiness::Preserve
    }
}

impl<'buffer, F: for<'a> FnMut(&'a rustls::Error) + Unpin>
    ready::Sink<0, RecvBuffer<'buffer>, storage::Shared, id::Static> for Capture<F>
{
    fn established(
        event: ready::Event<'_, Self, 0, RecvBuffer<'buffer>, storage::Shared, id::Static>,
    ) {
        let (this, _, handle, _) = event.into();
        this.get_mut().ready = Some(handle);
    }
}

impl<'buffer, F: for<'a> FnMut(&'a rustls::Error) + Unpin>
    stream::Sink<0, RecvBuffer<'buffer>, storage::Shared, id::Static> for Capture<F>
{
    fn stream(
        event: stream::Event<'_, Self, 0, RecvBuffer<'buffer>, storage::Shared, id::Static>,
    ) -> mux::Disposition {
        let (this, _, _, event, _) = event.into();
        if let Event::Readable { id } = event.event() {
            this.get_mut().readable = Some(id);
        }
        mux::Disposition::Accept
    }
}

impl<F: for<'a> FnMut(&'a rustls::Error) + Unpin> cert::Sink<0, id::Static> for Capture<F> {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (this, _, _, cause) = event.into_parts();
        (this.get_mut().certificate)(cause);
    }
}

impl<F: for<'a> FnMut(&'a rustls::Error) + Unpin> Capture<F> {
    pub fn deliver(
        router: &mut Router<Self, 0, RecvBuffer<'_>>,
        from: SocketAddr,
        flights: Vec<Flight>,
        now: Instant,
    ) -> Result<(), errors::Receive> {
        for mut flight in flights {
            for packet in flight.segments_mut() {
                Pin::new(&mut *router).observe(now, |mut turn| {
                    turn.protocol().recv(from, packet, epoch::WALL_CLOCK)
                })?;
            }
        }
        Ok(())
    }

    pub fn output(
        router: &mut Router<Self, 0, RecvBuffer<'_>>,
        now: Instant,
    ) -> Result<Vec<Flight>, errors::Transmit> {
        Pin::new(router).observe(now, |mut turn| {
            let mut output = turn.output();
            output.drive()?;
            Ok(output.drain().collect())
        })
    }
}
