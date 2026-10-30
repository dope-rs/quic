pub mod flight;
mod poll;
pub mod receive;
mod scope;
pub mod sealer;
mod send;
mod view;
pub mod warm;

pub use poll::Poll;
use receive::Receive;
pub use scope::Scope;
pub use send::Send;
pub use view::View;

use dope_quic::config;
use dope_quic::conn::life::tls::clients;
use dope_quic::conn::life::{accept, options};
use dope_quic::conn::output::transmit;
use dope_quic::conn::stream;
use dope_quic::conn::wire::packet::Batch;
use dope_quic::errors::{Code, Connect};
use dope_quic::runtime::{mux, routing};
use dope_quic::stream::Recv;
use dope_quic::wire::packet::{self, QUIC_V1};
use dope_quic::wire::stream::Id;
use dope_quic::{conn, conn::Connection, proto::param};
use long::initial;
use mux::builder::Failure;
use o3::alloc;
use o3::buffer::storage::Shared;
use o3::buffer::write::consume;
use options::builder;
use packet::{cid, encode, long};
use rustls::pki_types::ServerName;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use stream::event;

pub fn raw(seed: u8) -> Result<(config::raw::Identity, [u8; 32]), dope_tls::Error> {
    let identity = config::raw::Identity::from_seed(&[seed; 32])?;
    let pin = identity.public_key();
    Ok((identity, pin))
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SendId(Id);

impl SendId {
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub const fn id(self) -> Id {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReceiveId(Id);

impl ReceiveId {
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub const fn id(self) -> Id {
        self.0
    }
}

impl From<Id> for ReceiveId {
    fn from(id: Id) -> Self {
        Self(id)
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BidiId(Id);

impl BidiId {
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub const fn id(self) -> Id {
        self.0
    }

    pub const fn receive(self) -> ReceiveId {
        ReceiveId(self.0)
    }
}

impl From<BidiId> for SendId {
    fn from(id: BidiId) -> Self {
        Self(id.0)
    }
}

impl From<BidiId> for ReceiveId {
    fn from(id: BidiId) -> Self {
        Self(id.0)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Event {
    Writable,
    Readable {
        stream_id: ReceiveId,
    },
    Reset {
        stream_id: ReceiveId,
        error_code: Code,
    },
    Stopped {
        stream_id: SendId,
        error_code: Code,
    },
}

impl Event {
    fn from_item(event: event::Item<'_>) -> Self {
        use event::Item;

        match event {
            Item::Writable => Self::Writable,
            Item::Readable { id } => Self::Readable {
                stream_id: ReceiveId(id.id()),
            },
            Item::Reset {
                id,
                error_code: code,
            } => Self::Reset {
                stream_id: ReceiveId(id.id()),
                error_code: code,
            },
            Item::Stopped {
                id,
                error_code: code,
            } => Self::Stopped {
                stream_id: SendId(id.id()),
                error_code: code,
            },
        }
    }
}

pub struct Config {
    stream: u64,
    conn: u64,
    bidi: u64,
    uni: u64,
    pub local: Option<[usize; 2]>,
}

impl Config {
    pub const fn new(stream: u64, conn: u64, bidi: u64, uni: u64) -> Self {
        Self {
            stream,
            conn,
            bidi,
            uni,
            local: None,
        }
    }

    pub fn try_build(&self) -> Result<options::Options, Setup> {
        use param::Set;

        let params = Set::builder()
            .idle_ms(30_000)
            .datagram(Some(65_535))
            .cid_limit(8)
            .initial_data(self.conn)
            .local_bidi(self.stream)
            .remote_bidi(self.stream)
            .stream_uni(self.stream)
            .bidi_count(self.bidi)
            .uni_count(self.uni)
            .try_build()
            .map_err(Setup::Params)?;
        let draft = options::Options::builder().transport(|path| path.params(params));
        match self.local {
            Some([bidi, uni]) => draft.streams(|streams| streams.local_bidi(bidi).local_uni(uni)),
            None => draft,
        }
        .try_build()
        .map_err(Setup::Options)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new(1 << 20, 1 << 20, 8, 8)
    }
}

pub trait Bind {
    type Peer;

    fn bind<const DOMAIN: u8, B: Recv>(
        self,
        peer: &Connection<DOMAIN, B>,
    ) -> Result<Self::Peer, stream::Error>;
}

impl Bind for SendId {
    type Peer = ReceiveId;

    fn bind<const DOMAIN: u8, B: Recv>(
        self,
        peer: &Connection<DOMAIN, B>,
    ) -> Result<Self::Peer, stream::Error> {
        peer.view().with_streams(|view| {
            view.resolve_recv(self.id())
                .map(|stream| ReceiveId(stream.id()))
        })
    }
}

impl Bind for ReceiveId {
    type Peer = SendId;

    fn bind<const DOMAIN: u8, B: Recv>(
        self,
        peer: &Connection<DOMAIN, B>,
    ) -> Result<Self::Peer, stream::Error> {
        peer.view().with_streams(|view| {
            view.resolve_send(self.id())
                .map(|stream| SendId(stream.id()))
        })
    }
}

impl Bind for BidiId {
    type Peer = BidiId;

    fn bind<const DOMAIN: u8, B: Recv>(
        self,
        peer: &Connection<DOMAIN, B>,
    ) -> Result<Self::Peer, stream::Error> {
        peer.view().with_streams(|view| {
            view.resolve_bidi(self.id())
                .map(|stream| BidiId(stream.id()))
        })
    }
}

#[derive(Debug)]
pub enum Transfer {
    Output(transmit::Error),
    Input(conn::Error),
}

pub trait Receiver {
    fn receive(
        &mut self,
        work: &mut conn::Workspace,
        packet: &mut [u8],
        now: Instant,
    ) -> Result<(), Transfer>;

    fn receive_all(
        &mut self,
        work: &mut conn::Workspace,
        batch: &mut Batch,
        now: Instant,
    ) -> Result<(), Transfer> {
        for packet in batch.iter_mut() {
            self.receive(work, packet, now)?;
        }
        Ok(())
    }

    fn receive_from(
        &mut self,
        work: &mut conn::Workspace,
        from: &mut Connection,
        now: Instant,
    ) -> Result<(), Transfer> {
        let (packets, result) = from.with_scope(|mut scope| scope.output().send(now));
        result.map_err(Transfer::Output)?;
        for mut packet in packets {
            self.receive(work, &mut packet, now)?;
        }
        Ok(())
    }
}

impl Receiver for Connection {
    fn receive(
        &mut self,
        work: &mut conn::Workspace,
        packet: &mut [u8],
        now: Instant,
    ) -> Result<(), Transfer> {
        self.with_scope(|mut scope| scope.input(work).recv_packet(packet, now, |_| {}))
            .map_err(Transfer::Input)
    }
}

#[derive(Debug)]
pub enum Setup {
    Deadline(Instant, Duration),
    Params(param::Error),
    Options(builder::Invalid),
    Workspace(alloc::Error),
    Identity(dope_tls::Error),
    Tls(dope_tls::Error),
    Id(consume::Error),
    Authority(Connect),
    ServerBuild(Failure),
    ClientBuild(Failure),
    ServerPool(Connect),
    ClientPool(Connect),
    Accept(Connect),
    Connect(Connect),
    Server(Transfer),
    Client(Transfer),
    Handshake {
        client: conn::State,
        server: conn::State,
    },
}

pub struct Pair {
    pub server: Connection,
    pub client: Connection,
    pub work: conn::Workspace,
}

impl Pair {
    pub fn try_default() -> Result<Self, Setup> {
        Self::try_new(
            Config::default().try_build()?,
            Config::default().try_build()?,
        )
    }

    pub fn try_open(server: options::Options, client: options::Options) -> Result<Self, Setup> {
        let cid = cid::Id::try_from([0x71; 8]).map_err(Setup::Id)?;
        Self::try_with(server, client, cid)
    }

    pub fn try_with(
        server: options::Options,
        client: options::Options,
        cid: cid::Id,
    ) -> Result<Self, Setup> {
        Self::try_config(server, client, cid, |_, _| {})
    }

    pub fn try_config(
        server: options::Options,
        client: options::Options,
        cid: cid::Id,
        amend: impl FnOnce(&mut rustls::ServerConfig, &mut rustls::ClientConfig),
    ) -> Result<Self, Setup> {
        let (signing, key) = raw(0x39).map_err(Setup::Identity)?;
        let mut config = signing.server().map_err(Setup::Tls)?;
        let mut peer = config::raw::Identity::client(key).map_err(Setup::Tls)?;
        amend(&mut config, &mut peer);
        let server = {
            use accept::{Authority, Ids};

            Authority::new(config, server)
                .map_err(Setup::Authority)?
                .accept::<Shared>(Ids::initial(cid, cid, cid))
                .map_err(Setup::Accept)?
        };
        let client = {
            use clients::Authority;

            let name = ServerName::IpAddress(Ipv4Addr::LOCALHOST.into());
            Authority::try_new(peer, name)
                .map_err(|cause| Setup::Authority(cause.into()))?
                .connect::<0, Vec<u8>, Shared>(cid, cid, client, routing::Plain)
                .map_err(Setup::Connect)?
        };
        Ok(Self {
            server,
            client,
            work: conn::Workspace::try_new().map_err(Setup::Workspace)?,
        })
    }

    pub fn try_new(server: options::Options, client: options::Options) -> Result<Self, Setup> {
        let mut pair = Self::try_open(server, client)?;
        pair.exchange(Instant::now(), 6)?;
        pair.try_ready()?;
        Ok(pair)
    }

    pub fn try_ready(&self) -> Result<(), Setup> {
        if self.client.view().lifecycle().is_ready() && self.server.view().lifecycle().is_ready() {
            Ok(())
        } else {
            Err(Setup::Handshake {
                client: self.client.view().lifecycle().state(),
                server: self.server.view().lifecycle().state(),
            })
        }
    }

    pub fn exchange(&mut self, now: Instant, rounds: usize) -> Result<(), Setup> {
        for _ in 0..rounds {
            self.server
                .receive_from(&mut self.work, &mut self.client, now)
                .map_err(Setup::Server)?;
            self.client
                .receive_from(&mut self.work, &mut self.server, now)
                .map_err(Setup::Client)?;
        }
        Ok(())
    }

    pub fn into_parts(self) -> (Connection, Connection, conn::Workspace) {
        (self.server, self.client, self.work)
    }
}

#[derive(Debug)]
pub enum Wire {
    Key(sealer::NewError),
    Header(encode::Error),
    Seal(sealer::SealError),
}

pub struct Initial<'a> {
    dcid: &'a [u8],
    scid: &'a [u8],
    token: &'a [u8],
    pn: u64,
}

impl<'a> Initial<'a> {
    pub const fn new(dcid: &'a [u8], scid: &'a [u8], pn: u64) -> Self {
        Self {
            dcid,
            scid,
            token: &[],
            pn,
        }
    }

    pub const fn token(mut self, token: &'a [u8]) -> Self {
        self.token = token;
        self
    }

    pub fn seal(self, frames: &[u8]) -> Result<Vec<u8>, Wire> {
        let mut seal =
            sealer::Raw::initial(self.dcid, rustls::Side::Client, self.pn).map_err(Wire::Key)?;
        self.seal_with(frames, &mut seal)
    }

    pub fn seal_with(self, frames: &[u8], seal: &mut sealer::Raw) -> Result<Vec<u8>, Wire> {
        let mut payload = frames.to_vec();
        loop {
            let header = initial::Header {
                version: QUIC_V1,
                dcid: self.dcid.to_vec(),
                scid: self.scid.to_vec(),
                token: self.token.to_vec(),
                packet_number: self.pn,
                pn_len: 4,
            };
            let encoded = header.encode(payload.len()).map_err(Wire::Header)?;
            let total = encoded.as_bytes().len() + payload.len() + 16;
            if total >= 1200 {
                let header = encoded.as_bytes();
                return seal
                    .seal(header, &payload, self.pn, header.len() - 4, 4)
                    .map_err(Wire::Seal);
            }
            payload.resize(payload.len() + 1200 - total, 0);
        }
    }
}
