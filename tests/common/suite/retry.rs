use crate::common::runtime::Error;
use dope_quic::conn::id;
use dope_quic::runtime::mux::handler::{
    self,
    hook::{life::create, set, wire::cert},
};
use dope_quic::runtime::mux::{output, router};
use dope_quic::{errors, proto::epoch};
use o3::buffer::storage;
use std::{net::SocketAddr, pin::Pin, time::Instant};

pub struct Capture {
    pub certificates: usize,
}

impl handler::Handler<0, Vec<u8>, storage::Shared> for Capture {
    type Connection = ();
    type Create = create::Unit;
    type Events = set::Set;
}

impl cert::Sink<0, id::Static> for Capture {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (mut this, _, _, _) = event.into_parts();
        this.certificates += 1;
    }
}

impl Capture {
    pub fn receive(
        mux: &mut router::Router<Self>,
        from: SocketAddr,
        packet: &mut [u8],
        now: Instant,
    ) -> Result<(), Error> {
        let received = Pin::new(&mut *mux).observe(now, |mut turn| {
            turn.protocol().recv(from, packet, epoch::WALL_CLOCK)
        });
        if mux.handler().certificates != 0 {
            return Err(Error::Certificates(mux.handler().certificates));
        }
        received.map_err(Error::Receive)
    }

    pub fn take(
        mux: &mut router::Router<Self>,
        now: Instant,
    ) -> Result<Option<output::Flight>, errors::Transmit> {
        Pin::new(mux).observe(now, |mut turn| {
            turn.output().drive()?;
            Ok(turn.output().drain().next())
        })
    }
}
