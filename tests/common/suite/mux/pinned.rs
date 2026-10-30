use crate::common::runtime::Error;
use dope_quic::conn::id;
use dope_quic::errors;
use dope_quic::proto::epoch;
use dope_quic::runtime::mux::handler::hook::data::datagram;
use dope_quic::runtime::mux::handler::hook::life::{close, closing, create, ready};
use dope_quic::runtime::mux::handler::hook::set;
use dope_quic::runtime::mux::handler::hook::wire::{cert, endpoint, ingress, packet};
use dope_quic::runtime::mux::{handler, router};
use dope_test::harness::observe::VecCellExt as _;
use o3::buffer::storage;
use std::{cell::Cell, marker::PhantomPinned, net::SocketAddr, pin::Pin, ptr, time::Instant};

#[derive(Default)]
pub struct Counts {
    pub sites: Cell<Vec<*const ()>>,
    pub ready: Cell<Vec<u8>>,
    pub shutting: Cell<Vec<(u8, usize)>>,
    pub retired: Cell<Vec<(u8, usize)>>,
    pub bytes: Cell<Vec<Vec<u8>>>,
    pub created: Cell<usize>,
    pub certificates: Cell<usize>,
}

pub struct Capture<'a> {
    counts: &'a Counts,
    _pin: PhantomPinned,
}

impl<'a> Capture<'a> {
    pub fn new(counts: &'a Counts) -> Self {
        Self {
            counts,
            _pin: PhantomPinned,
        }
    }

    fn observe(self: Pin<&mut Self>) {
        let this = self.as_ref().get_ref();
        this.counts.sites.push(ptr::from_ref(this).cast());
    }
}

impl handler::Handler<0, Vec<u8>, storage::Shared> for Capture<'_> {
    type Connection = Cell<u8>;
    type Create = create::Call;
    type Events = set::Set<
        set::On,
        set::On,
        set::Off,
        set::Off,
        set::Off,
        set::Off,
        ingress::Off,
        packet::Off,
        endpoint::Off,
        closing::On,
        close::On,
    >;
}

impl create::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture<'_> {
    fn create(event: create::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) -> Cell<u8> {
        let (this, _, _) = event.into_parts();
        let counts = this.as_ref().get_ref().counts;
        this.observe();
        counts.created.set(counts.created.get() + 1);
        Cell::new(0)
    }
}

impl closing::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture<'_> {
    fn closing(event: closing::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, mut slot, _) = event.into();
        let counts = this.as_ref().get_ref().counts;
        this.observe();
        counts
            .shutting
            .push((slot.application().replace(2), counts.retired.len()));
    }
}

impl close::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture<'_> {
    fn close(event: close::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, _, app, _) = event.into_parts();
        let counts = this.as_ref().get_ref().counts;
        this.observe();
        counts
            .retired
            .push((app.into_inner(), counts.shutting.len()));
    }
}

impl ready::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture<'_> {
    fn established(event: ready::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, mut slot, _, _) = event.into();
        let counts = this.as_ref().get_ref().counts;
        this.observe();
        counts.ready.push(slot.application().replace(1));
    }
}

impl datagram::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture<'_> {
    fn datagram(event: datagram::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, _, _, data, _) = event.into();
        let counts = this.as_ref().get_ref().counts;
        counts.bytes.push(data);
        this.observe();
    }
}

pub fn relay<'a>(
    mut source: Pin<&mut router::Router<Capture<'a>>>,
    mut dst: Pin<&mut router::Router<Capture<'a>>>,
    addr: SocketAddr,
    now: Instant,
) -> Result<(), Error> {
    let packets = source.as_mut().observe(now, |mut turn| {
        turn.output().drive()?;
        Ok::<_, errors::Transmit<id::Static, 0>>(turn.output().drain().collect::<Vec<_>>())
    });
    let packets = packets.map_err(Error::Output)?;
    for mut packet in packets {
        for segment in packet.segments_mut() {
            let received = dst.as_mut().observe(now, |mut turn| {
                turn.protocol().recv(addr, segment, epoch::WALL_CLOCK)
            });
            received.map_err(Error::Receive)?;
        }
    }
    let driven = dst.as_mut().observe(now, |mut turn| turn.output().drive());
    driven.map_err(Error::Output)?;
    Ok(())
}

impl cert::Sink<0, id::Static> for Capture<'_> {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (this, _, _, _) = event.into_parts();
        let counts = this.as_ref().get_ref().counts;
        this.observe();
        counts.certificates.set(counts.certificates.get() + 1);
    }
}
