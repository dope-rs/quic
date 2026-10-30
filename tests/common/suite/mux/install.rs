use crate::common::peer;
use crate::common::{
    peer::Setup,
    runtime,
    suite::{mux::dispatch, peers::tls, retry::Capture},
};
use dope_quic::conn::life::options::Options;
use dope_quic::proto::epoch;
use dope_quic::runtime::mux::builder::{Builder, Plan};
use dope_quic::runtime::mux::handler::hook::life::close;
use dope_quic::runtime::mux::handler::hook::life::closing;
use dope_quic::runtime::mux::handler::hook::life::create;
use dope_quic::runtime::mux::handler::hook::set;
use dope_quic::runtime::mux::handler::hook::wire::cert;
use dope_quic::runtime::mux::handler::hook::wire::endpoint;
use dope_quic::runtime::mux::handler::hook::wire::ingress;
use dope_quic::runtime::mux::handler::hook::wire::packet;
use dope_quic::wire::packet::{decode, encode, long::initial};
use dope_quic::{
    conn::{self, id},
    errors,
    runtime::mux::{
        handler::{self, hook},
        router,
    },
    security::crypto,
    wire::packet::QUIC_V1,
};
use hook::life::close::On;
use hook::life::create::Call;
use o3::buffer::storage;
use std::{net::SocketAddr, pin::Pin, time::Instant};

#[derive(Debug)]
pub enum Error {
    Header(encode::Error),
    Admission(Result<(), runtime::Error>),
    Runtime(runtime::Error),
    MissingFlight,
    Prefix(decode::Error),
}

#[derive(Default)]
pub struct Counter {
    pub created: usize,
    certificates: usize,
    pub handles: Vec<id::Handle>,
    pub closed: Vec<id::Handle>,
}

impl handler::Handler<0, Vec<u8>, storage::Shared> for Counter {
    type Connection = ();
    type Create = Call;
    type Events = set::Set<
        set::Off,
        set::Off,
        set::Off,
        set::Off,
        set::Off,
        set::Off,
        ingress::Off,
        packet::Off,
        endpoint::Off,
        closing::Off,
        On,
    >;
}

impl create::Sink<0, Vec<u8>, storage::Shared, id::Static> for Counter {
    fn create(event: create::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, _, handle) = event.into_parts();
        let this = this.get_mut();
        this.created += 1;
        this.handles.push(handle);
    }
}

impl close::Sink<0, Vec<u8>, storage::Shared, id::Static> for Counter {
    fn close(event: close::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, _, _, handle) = event.into_parts();
        this.get_mut().closed.push(handle);
    }
}

pub fn initial(dcid: &[u8], scid: &[u8]) -> Result<Vec<u8>, encode::Error> {
    let payload = vec![0_u8; 1200];
    let header = initial::Header {
        version: QUIC_V1,
        dcid: dcid.to_vec(),
        scid: scid.to_vec(),
        token: Vec::new(),
        packet_number: 0,
        pn_len: 4,
    };
    let mut wire = header.encode(payload.len() - 16)?.as_bytes().to_vec();
    wire.extend_from_slice(&payload);
    Ok(wire)
}

pub fn server() -> Result<router::Router<Counter>, Setup> {
    let (key, _) = peer::raw(0x7a).map_err(Setup::Identity)?;
    dispatch::Capture::server(
        Counter::default(),
        key.server().map_err(Setup::Tls)?,
        Options::default(),
        Plan::standard(),
    )
}

pub fn receive(
    mux: &mut router::Router<Counter>,
    peer: SocketAddr,
    packet: &mut [u8],
    now: Instant,
) -> Result<(), runtime::Error> {
    let result = Pin::new(&mut *mux).observe(now, |mut turn| {
        turn.protocol().recv(peer, packet, epoch::WALL_CLOCK)
    });
    if mux.handler().certificates != 0 {
        return Err(runtime::Error::Certificates(mux.handler().certificates));
    }
    result.map_err(runtime::Error::Receive)
}

pub fn admit(
    mux: &mut router::Router<Counter>,
    peer: SocketAddr,
    dcid: &[u8],
    scid: &[u8],
    now: Instant,
) -> Result<(), Error> {
    admitted(receive(
        mux,
        peer,
        &mut initial(dcid, scid).map_err(Error::Header)?,
        now,
    ))
}

fn admitted(result: Result<(), runtime::Error>) -> Result<(), Error> {
    if matches!(
        result,
        Err(runtime::Error::Receive(errors::Receive::Packet(
            conn::Error::Crypto(crypto::Error::Decrypt(rustls::Error::DecryptError))
        )))
    ) {
        Ok(())
    } else {
        Err(Error::Admission(result))
    }
}

pub fn close(
    mux: &mut router::Router<Counter>,
    handle: id::Handle,
    now: Instant,
) -> Result<(), errors::Access> {
    Pin::new(mux).observe(now, |mut turn| turn.protocol().try_close(handle))
}

pub fn transfer(
    source: &mut router::Router<Counter>,
    dst: &mut router::Router<Counter>,
    from: SocketAddr,
    now: Instant,
) -> Result<(), runtime::Error> {
    Pin::new(source).observe(now, |mut turn| {
        turn.output().drive().map_err(runtime::Error::Output)?;
        for mut outgoing in turn.output().drain() {
            for segment in outgoing.segments_mut() {
                receive(dst, from, segment, now)?;
            }
        }
        Ok(())
    })
}

pub fn relay(
    source: &mut router::Router<Counter>,
    dst: &mut router::Router<Counter>,
    from: SocketAddr,
    now: Instant,
) -> Result<Vec<Vec<u8>>, runtime::Error> {
    let mut wires = Vec::new();
    Pin::new(source).observe(now, |mut turn| {
        turn.output().drive().map_err(runtime::Error::Output)?;
        for mut outgoing in turn.output().drain() {
            for segment in outgoing.segments_mut() {
                wires.push(segment.to_vec());
                receive(dst, from, segment, now)?;
            }
        }
        Ok::<(), runtime::Error>(())
    })?;
    Ok(wires)
}

impl cert::Sink<0, id::Static> for Counter {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (mut this, _, _, _) = event.into_parts();
        this.certificates += 1;
    }
}

pub fn alias() -> Result<router::Router<Capture>, Setup> {
    let (key, _) = peer::raw(0x11).map_err(Setup::Identity)?;
    dispatch::Capture::server(
        Capture { certificates: 0 },
        key.server().map_err(Setup::Tls)?,
        Options::default(),
        Plan::standard(),
    )
}

pub fn alias_admit(
    mux: &mut router::Router<Capture>,
    from: SocketAddr,
    dcid: &[u8],
    scid: &[u8],
    now: Instant,
) -> Result<(), Error> {
    admitted(Capture::receive(
        mux,
        from,
        &mut initial(dcid, scid).map_err(Error::Header)?,
        now,
    ))
}

pub fn unsupported(dcid: &[u8], scid: &[u8], len: usize) -> Vec<u8> {
    let mut wire = vec![0xc0];
    wire.extend_from_slice(&0xface_b00c_u32.to_be_bytes());
    wire.push(dcid.len() as u8);
    wire.extend_from_slice(dcid);
    wire.push(scid.len() as u8);
    wire.extend_from_slice(scid);
    wire.resize(len, 0);
    wire
}

pub fn negotiation(dcid: &[u8], scid: &[u8], versions: &[u32]) -> Vec<u8> {
    let mut wire = vec![0x80];
    wire.extend_from_slice(&0_u32.to_be_bytes());
    wire.push(dcid.len() as u8);
    wire.extend_from_slice(dcid);
    wire.push(scid.len() as u8);
    wire.extend_from_slice(scid);
    for version in versions {
        wire.extend_from_slice(&version.to_be_bytes());
    }
    wire
}

type Attempt = (
    router::Router<Capture>,
    id::Handle,
    SocketAddr,
    Vec<u8>,
    Vec<u8>,
);

pub fn attempt(seed: u8) -> Result<Attempt, Error> {
    let (_, key) = peer::raw(seed)
        .map_err(runtime::Error::Identity)
        .map_err(Error::Runtime)?;
    let mut client = Builder::client(Capture { certificates: 0 })
        .build()
        .map_err(runtime::Error::Storage)
        .map_err(Error::Runtime)?;
    let server = SocketAddr::from(([192, 0, 2, 20], 443));
    let now = Instant::now();
    let auth = tls::client(key)
        .map_err(runtime::Error::Tls)
        .map_err(Error::Runtime)?;
    let handle = Pin::new(&mut client)
        .observe(now, |mut turn| {
            turn.protocol()
                .connect(server, &auth, Default::default(), vec![0x55; 8])
        })
        .map_err(runtime::Error::Connect)
        .map_err(Error::Runtime)?;
    let initial = Capture::take(&mut client, Instant::now())
        .map_err(runtime::Error::Output)
        .map_err(Error::Runtime)?
        .ok_or(Error::MissingFlight)?;
    let prefix = initial::Prefix::decode(initial.payload()).map_err(Error::Prefix)?;
    Ok((
        client,
        handle,
        server,
        prefix.scid.as_ref().to_vec(),
        prefix.dcid.as_ref().to_vec(),
    ))
}

pub fn forward(
    source: &mut router::Router<Capture>,
    dst: &mut router::Router<Capture>,
    addr: SocketAddr,
    now: Instant,
) -> Result<(), runtime::Error> {
    Pin::new(&mut *source).observe(now, |mut turn| {
        turn.output().drive().map_err(runtime::Error::Output)?;
        for mut outgoing in turn.output().drain() {
            for packet in outgoing.segments_mut() {
                Capture::receive(dst, addr, packet, now)?;
            }
        }
        Ok(())
    })
}
