use crate::common::peer;
use crate::common::suite::peers::{packet, tls};
use crate::common::{runtime::Error, suite::mux::dispatch};
use dope_quic::conn::id::Static;
use dope_quic::conn::stream::Event;
use dope_quic::errors;
use dope_quic::runtime::mux::handler;
use dope_quic::runtime::mux::handler::hook::data::{datagram, stream};
use dope_quic::runtime::mux::handler::hook::life::{create, ready};
use dope_quic::runtime::mux::handler::hook::set;
use dope_quic::runtime::mux::handler::hook::wire::cert;

use dope_quic::conn::life::accept;
use dope_quic::conn::life::options::Options;
use dope_quic::proto::epoch;
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::runtime::routing;
use dope_quic::wire::frame;
use dope_tls::config;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::time::{Duration, Instant};

use dope_quic::conn::id::Handle;
use dope_quic::conn::scope;
use dope_quic::proto::param;
use dope_quic::runtime::mux;
use dope_quic::runtime::mux::output::Flight;
use dope_quic::runtime::mux::router::Router;
use dope_quic::stream::Capacity;
use o3::buffer::storage;
use peer::Setup;

pub const SERVER: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 443));
pub const CLIENT: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 50_000));

#[derive(Debug)]
pub enum WireError {
    Setup(Setup),
    Packet(packet::Error),
    Runtime(Error),
    Established(usize),
}

pub fn try_wire() -> Result<(packet::Session, Router<Capture>, Handle, Instant), WireError> {
    let options = Pending::options().map_err(WireError::Setup)?;
    let (signing, key) = peer::raw(0x39)
        .map_err(Setup::Identity)
        .map_err(WireError::Setup)?;
    let client = config::raw::Identity::client(key)
        .map_err(Setup::Tls)
        .map_err(WireError::Setup)?;
    let mut peer = packet::Session::try_new(client, options.params()).map_err(WireError::Packet)?;
    let config = signing
        .server()
        .map_err(Setup::Tls)
        .map_err(WireError::Setup)?;
    let auth = accept::Authority::new(config, options)
        .map_err(Setup::Authority)
        .map_err(WireError::Setup)?;
    let mut server = Builder::server(Capture::default(), auth)
        .build()
        .map_err(Setup::ServerBuild)
        .map_err(WireError::Setup)?;
    let start = Instant::now();
    let mut initial = peer.initial().map_err(WireError::Packet)?;
    Pair::receive(&mut server, CLIENT, &mut initial, start).map_err(WireError::Runtime)?;
    let flight = dispatch::Capture::output(&mut server, start)
        .map_err(Error::Output)
        .map_err(WireError::Runtime)?;
    for mut packet in flight {
        for segment in packet.segments_mut() {
            if let Some(mut wire) = peer.receive(segment).map_err(WireError::Packet)? {
                peer.open(&mut wire).map_err(WireError::Packet)?;
            }
        }
    }
    let mut finish = peer.finish(None).map_err(WireError::Packet)?;
    Pair::receive(&mut server, CLIENT, &mut finish, start).map_err(WireError::Runtime)?;
    dispatch::Capture::drive(&mut server, start)
        .map_err(Error::Output)
        .map_err(WireError::Runtime)?;
    let [handle] = server.handler().established.as_slice() else {
        return Err(WireError::Established(server.handler().established.len()));
    };
    let handle = *handle;
    Ok((peer, server, handle, start))
}

pub fn try_response(
    peer: &mut packet::Session,
    packets: Vec<Flight>,
    source: SocketAddr,
) -> Result<Vec<u8>, WireError> {
    let mut token = None;
    for mut packet in packets {
        let selected = packet.addr() == source;
        for segment in packet.segments_mut() {
            let Some(mut wire) = peer.receive(segment).map_err(WireError::Packet)? else {
                continue;
            };
            let (_, body) = peer.open(&mut wire).map_err(WireError::Packet)?;
            if !selected || token.is_some() {
                continue;
            }
            for frame in frame::Frame::decode_all(&body)
                .map_err(packet::Error::Frame)
                .map_err(WireError::Packet)?
            {
                if let frame::View::PathChallenge { data } = frame.view() {
                    token = Some(*data);
                    break;
                }
            }
        }
    }
    let token = token.ok_or(WireError::Runtime(Error::EmptyReply))?;
    let mut response = [0; 1_200];
    response[0] = frame::TYPE_PATH_RESPONSE;
    response[1..9].copy_from_slice(&token);
    peer.packet(&response).map_err(WireError::Packet)
}

pub struct Pending {
    pub server: Router<Capture>,
    pub client: Router<Capture>,
    pub client_id: Handle,
    pub start: Instant,
}

impl Pending {
    pub fn options() -> Result<Options, Setup> {
        let params = param::Set::builder()
            .idle_ms(30_000)
            .datagram(Some(65_535))
            .cid_limit(4)
            .initial_data(65_535)
            .stream_uni(65_535)
            .uni_count(1)
            .try_build()
            .map_err(Setup::Params)?;
        Options::builder()
            .transport(|net| net.params(params))
            .security(|security| security.reset(Some([0x51; 32])))
            .try_build()
            .map_err(Setup::Options)
    }
    pub fn try_new(seed: u8, cid: u8) -> Result<Self, Setup> {
        let (signing, key) = peer::raw(seed).map_err(Setup::Identity)?;
        let auth =
            accept::Authority::new(signing.server().map_err(Setup::Tls)?, Pending::options()?)
                .map_err(Setup::Authority)?;
        let server = Builder::server(Capture::default(), auth)
            .build()
            .map_err(Setup::ServerBuild)?;
        let mut client = Builder::client(Capture::default())
            .build()
            .map_err(Setup::ClientBuild)?;
        let start = Instant::now();
        let options = Pending::options()?;
        let auth = tls::client(key).map_err(Setup::Tls)?;
        let handle = Pin::new(&mut client)
            .observe(start, |mut turn| {
                turn.protocol()
                    .connect(SERVER, &auth, options, vec![cid; 8])
            })
            .map_err(Setup::Connect)?;
        Ok(Self {
            server,
            client,
            client_id: handle,
            start,
        })
    }

    pub fn establish(mut self) -> Result<Pair, Error> {
        for step in 0..8 {
            let at = self
                .start
                .checked_add(Duration::from_millis(step))
                .ok_or(Error::Deadline(self.start))?;
            let mut packets =
                dispatch::Capture::output(&mut self.client, at).map_err(Error::Output)?;
            Pair::deliver(&mut packets, CLIENT, &mut self.server, at)?;
            let mut packets =
                dispatch::Capture::output(&mut self.server, at).map_err(Error::Output)?;
            Pair::deliver(&mut packets, SERVER, &mut self.client, at)?;
            if !self.client.handler().established.is_empty()
                && !self.server.handler().established.is_empty()
            {
                break;
            }
        }
        let error = Error::Established {
            client: self.client.handler().established.len(),
            server: self.server.handler().established.len(),
        };
        if self.client.handler().established != [self.client_id] {
            return Err(error);
        }
        let id = self
            .server
            .handler()
            .established
            .first()
            .copied()
            .ok_or(error)?;
        Ok(Pair {
            server: self.server,
            client: self.client,
            client_id: self.client_id,
            server_id: id,
            start: self.start,
        })
    }
}

pub struct Pair {
    pub server: Router<Capture>,
    pub client: Router<Capture>,
    pub client_id: Handle,
    pub server_id: Handle,
    pub start: Instant,
}

impl Pair {
    pub fn observe(
        &mut self,
        peer: SocketAddr,
        data: Vec<u8>,
        sent: Instant,
        at: Instant,
    ) -> Result<usize, Error> {
        dispatch::Capture::send(&mut self.client, self.client_id, data, sent)
            .map_err(Error::Send)?;
        let mut input = dispatch::Capture::output(&mut self.client, at).map_err(Error::Output)?;
        let size = input.iter().map(|packet| packet.payload().len()).sum();
        Self::deliver(&mut input, peer, &mut self.server, at)?;
        Ok(size)
    }
    pub fn answer(
        &mut self,
        flight: &mut [Flight],
        peer: SocketAddr,
        at: Instant,
    ) -> Result<Instant, Error> {
        Self::relay(flight, peer, SERVER, &mut self.client, at)?;
        let at = at
            .checked_add(Duration::from_millis(1))
            .ok_or(Error::Deadline(at))?;
        let mut reply = dispatch::Capture::output(&mut self.client, at).map_err(Error::Output)?;
        if reply.is_empty() {
            return Err(Error::EmptyReply);
        }
        Self::deliver(&mut reply, peer, &mut self.server, at)?;
        Ok(at)
    }
    pub fn send_server(
        &mut self,
        data: Vec<u8>,
        at: Instant,
    ) -> Result<(), errors::SendFailure<Vec<u8>>> {
        dispatch::Capture::send(&mut self.server, self.server_id, data, at)
    }
    pub fn challenge(&mut self, token: [u8; 8], at: Instant) -> Result<(), Error> {
        Self::access(&mut self.client, self.client_id, at, |mut conn| {
            conn.path().try_probe(token)
        })
        .map_err(Error::Access)?
        .map_err(Error::Probe)
    }
    pub fn receive(
        router: &mut Router<Capture>,
        from: SocketAddr,
        packet: &mut [u8],
        at: Instant,
    ) -> Result<(), Error> {
        let result = Pin::new(&mut *router).observe(at, |mut turn| {
            turn.protocol().recv(from, packet, epoch::WALL_CLOCK)
        });
        if router.handler().certificates != 0 {
            return Err(Error::Certificates(router.handler().certificates));
        }
        result.map_err(Error::Receive)
    }
    pub fn access<R>(
        router: &mut Router<Capture>,
        handle: Handle,
        at: Instant,
        op: impl for<'a> FnOnce(scope::Turn<'a, 0, Vec<u8>, storage::Shared>) -> R,
    ) -> Result<R, errors::Access> {
        Pin::new(router).observe(at, |mut turn| turn.protocol().with_conn(handle, op))
    }
    pub fn peer(
        router: &mut Router<Capture>,
        handle: Handle,
        at: Instant,
    ) -> Result<Option<SocketAddr>, errors::Access> {
        Self::access(router, handle, at, |conn| conn.view().path().peer_address())
    }
    pub fn credit(
        router: &mut Router<Capture>,
        handle: Handle,
        at: Instant,
    ) -> Result<u64, errors::Access> {
        Self::access(router, handle, at, |conn| conn.view().path().received())
    }
    pub fn discard(router: &mut Router<Capture>, at: Instant) -> Result<(), errors::Transmit> {
        Pin::new(router).observe(at, |mut turn| {
            turn.output().drive()?;
            while turn.output().drain().next().is_some() {}
            Ok(())
        })
    }
    pub fn deliver(
        packets: &mut [Flight],
        source: SocketAddr,
        into: &mut Router<Capture>,
        at: Instant,
    ) -> Result<(), Error> {
        for packet in packets {
            for segment in packet.segments_mut() {
                Self::receive(into, source, segment, at)?;
            }
        }
        Ok(())
    }
    pub fn relay(
        packets: &mut [Flight],
        target: SocketAddr,
        source: SocketAddr,
        into: &mut Router<Capture>,
        at: Instant,
    ) -> Result<(), Error> {
        for packet in packets.iter_mut().filter(|packet| packet.addr() == target) {
            for segment in packet.segments_mut() {
                Self::receive(into, source, segment, at)?;
            }
        }
        Ok(())
    }
    pub fn path(packets: &[Flight], target: SocketAddr) -> impl Iterator<Item = &Flight> {
        packets.iter().filter(move |packet| packet.addr() == target)
    }
    pub fn retry(
        router: &mut Router<Capture>,
        start: Instant,
        turns: usize,
        target: Option<SocketAddr>,
    ) -> Result<(Instant, Vec<Flight>), Error> {
        let mut at = start;
        for _ in 0..turns {
            let deadline = Pin::new(&mut *router)
                .observe(at, |turn| turn.deadline())
                .ok_or(Error::Deadline(at))?;
            at = deadline
                .checked_add(Duration::from_micros(1))
                .ok_or(Error::Deadline(deadline))?;
            let packets = dispatch::Capture::output(router, at).map_err(Error::Output)?;
            if target.is_none_or(|target| Self::path(&packets, target).next().is_some()) {
                return Ok((at, packets));
            }
        }
        Ok((at, Vec::new()))
    }
    pub fn short_cid(packet: &Flight) -> Option<&[u8]> {
        let payload = packet.payload();
        let end = 1usize.checked_add(routing::ENTROPY_LEN)?;
        (payload.first().is_some_and(|first| first & 0x80 == 0) && payload.len() >= end)
            .then(|| &payload[1..end])
    }
}

#[derive(Default)]
pub struct Capture {
    pub certificates: usize,
    pub errors: Vec<Capacity>,
    pub created: Vec<Handle>,
    pub established: Vec<Handle>,
    pub datagrams: Vec<Vec<u8>>,
    pub streams: Vec<(u64, Vec<u8>)>,
}

impl handler::Handler<0, Vec<u8>, storage::Shared> for Capture {
    type Connection = ();
    type Create = create::Call;
    type Events = set::Set<set::On, set::On, set::On>;
}

impl create::Sink<0, Vec<u8>, storage::Shared, Static> for Capture {
    fn create(event: create::Event<'_, Self, 0, Vec<u8>, storage::Shared, Static>) {
        let (mut this, _, handle) = event.into_parts();
        this.created.push(handle);
    }
}

impl ready::Sink<0, Vec<u8>, storage::Shared, Static> for Capture {
    fn established(event: ready::Event<'_, Self, 0, Vec<u8>, storage::Shared, Static>) {
        let (mut this, _, handle, _) = event.into();
        this.established.push(handle);
    }
}

impl datagram::Sink<0, Vec<u8>, storage::Shared, Static> for Capture {
    fn datagram(event: datagram::Event<'_, Self, 0, Vec<u8>, storage::Shared, Static>) {
        let (mut this, _, _, data, _) = event.into();
        this.datagrams.push(data);
    }
}

impl stream::Sink<0, Vec<u8>, storage::Shared, Static> for Capture {
    fn stream(
        event: stream::Event<'_, Self, 0, Vec<u8>, storage::Shared, Static>,
    ) -> mux::Disposition {
        let (mut this, mut slot, _, event, _) = event.into();
        if let Event::Readable { id } = event.event() {
            let mut streams = slot.transport().streams();
            if let Ok(stream) = streams.view().resolve_recv(id) {
                match streams.receive().recv_owned(stream) {
                    Ok(Some(bytes)) => this.streams.push((id.get(), bytes)),
                    Ok(None) => {}
                    Err(error) => this.errors.push(error),
                }
            }
        }
        mux::Disposition::Accept
    }
}

impl cert::Sink<0, Static> for Capture {
    fn certificate(event: cert::Event<'_, '_, Self, 0, Static>) {
        let (mut this, _, _, _) = event.into_parts();
        this.certificates += 1;
    }
}
