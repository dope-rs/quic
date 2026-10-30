use dope_quic::conn::id;
use dope_quic::conn::stream::Event;
use dope_quic::conn::wire::ingress::events;
use dope_quic::errors;
use dope_quic::errors::detail::Diagnostic;
use dope_quic::proto::epoch;
use dope_quic::runtime::mux::handler::hook::data::stream;
use dope_quic::runtime::mux::handler::hook::life::{create, ready};
use dope_quic::runtime::mux::handler::hook::set;
use dope_quic::runtime::mux::handler::hook::wire::{cert, ingress, packet};
use dope_quic::runtime::mux::output::Flight;
use dope_quic::runtime::mux::{self, handler, router};
use dope_quic::stream::{Recv, release, send::admit};
use dope_quic::wire::stream::Id;
use o3::buffer::hold::evidence;
use o3::buffer::storage;
use std::{net::SocketAddr, pin::Pin, time::Instant};

pub struct Capture<F> {
    pub ready: Option<id::Handle>,
    pub readable: Vec<Id>,
    pub fault: Option<Diagnostic>,
    pub packet_error: Option<errors::Receive>,
    pub certificate: F,
}

impl<B: Recv, F: for<'a> FnMut(&'a rustls::Error) + Unpin> handler::Handler<0, B, storage::Shared>
    for Capture<F>
{
    type Connection = ();
    type Create = create::Unit;
    type Events = set::Set<
        set::On,
        set::Off,
        set::On,
        set::Off,
        set::Off,
        set::Off,
        ingress::Off,
        packet::On,
    >;
}

impl<B: Recv, F: for<'a> FnMut(&'a rustls::Error) + Unpin>
    ready::Sink<0, B, storage::Shared, id::Static> for Capture<F>
{
    fn established(event: ready::Event<'_, Self, 0, B, storage::Shared, id::Static>) {
        let (this, _, handle, _) = event.into();
        this.get_mut().ready = Some(handle);
    }
}

impl<B: Recv, F: for<'a> FnMut(&'a rustls::Error) + Unpin>
    stream::Sink<0, B, storage::Shared, id::Static> for Capture<F>
{
    fn stream(
        event: stream::Event<'_, Self, 0, B, storage::Shared, id::Static>,
    ) -> mux::Disposition {
        let (this, _, _, event, _) = event.into();
        if let Event::Readable { id } = event.event() {
            this.get_mut().readable.push(id);
        }
        mux::Disposition::Accept
    }
}

impl<B: Recv, F: for<'a> FnMut(&'a rustls::Error) + Unpin>
    packet::Sink<0, B, storage::Shared, id::Static> for Capture<F>
{
    fn packet(event: packet::Event<'_, Self>) {
        let (this, _, error, _) = event.into_parts();
        match error {
            packet::Failure::Diagnostic(error) => this.get_mut().fault = Some(error.clone()),
            packet::Failure::Receive(error) => this.get_mut().packet_error = Some(error),
        }
    }
}

impl<F: for<'a> FnMut(&'a rustls::Error) + Unpin> cert::Sink<0, id::Static> for Capture<F> {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (this, _, _, cause) = event.into_parts();
        (this.get_mut().certificate)(cause);
    }
}

impl<F: for<'a> FnMut(&'a rustls::Error) + Unpin> Capture<F> {
    pub fn receive<B: Recv>(
        router: &mut router::Router<Self, 0, B>,
        address: SocketAddr,
        packet: &mut [u8],
        now: Instant,
    ) -> Result<(), errors::Receive> {
        Pin::new(router).observe(now, |mut turn| {
            turn.protocol().recv(address, packet, epoch::WALL_CLOCK)
        })
    }

    pub fn deliver<B: Recv>(
        router: &mut router::Router<Self, 0, B>,
        address: SocketAddr,
        flights: Vec<Flight>,
        now: Instant,
    ) -> Result<(), errors::Receive> {
        for mut flight in flights {
            for packet in flight.segments_mut() {
                Self::receive(router, address, packet, now)?;
            }
            Pin::new(&mut *router).output().recycle(flight);
        }
        Ok(())
    }

    pub fn output<B: Recv>(
        router: &mut router::Router<Self, 0, B>,
        now: Instant,
    ) -> Result<Vec<Flight>, errors::Transmit> {
        Pin::new(router).observe(now, |mut turn| {
            let mut output = turn.output();
            output.drive()?;
            Ok(output.drain().collect())
        })
    }
}

pub struct Proof<F>(pub Option<Diagnostic>, pub F);

impl<F> release::Sink for Proof<F> {
    type Mode = evidence::Off;

    fn release(&mut self, proof: evidence::Off, _: admit::Source, _: release::Cause) {
        let evidence::Off = proof;
    }
}

impl<F: for<'a> FnMut(&'a rustls::Error)> events::Sink for Proof<F> {
    type Observer<'a>
        = &'a mut Self
    where
        Self: 'a;

    fn certificate(&mut self, error: &rustls::Error) {
        (self.1)(error);
    }

    fn observer(&mut self) -> Option<Self::Observer<'_>> {
        Some(self)
    }
}

impl<F> events::Observe for &mut Proof<F> {
    fn observe(self, error: &Diagnostic) {
        self.0 = Some(error.clone());
    }
}
