use crate::common::peer;
pub mod bounds;
pub mod config;
pub mod life;
pub mod mutual;
pub mod packet;
pub mod path;
pub mod receive;
pub mod tls;
use dope_quic::conn::life::options::{Options, builder::Invalid};
use dope_quic::conn::life::tls::clients;
use o3::buffer::storage;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::time::Instant;

use dope_quic::conn::life::accept;
use dope_quic::proto::{early::ReplayCap, param};
use dope_quic::runtime::routing;
use dope_quic::wire::packet::cid;
use dope_quic::{conn, errors};
use peer::{Pair, Setup};
use rustls::{client::Resumption, pki_types::ServerName};

pub const CID: [u8; 8] = [0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7];

pub enum Error {
    Setup(Setup),
    Params(param::Error),
    Options(Invalid),
    Replay((usize, usize)),
    Reconnect(errors::Reconnect),
}

pub struct Authority {
    pub server: accept::Authority,
    pub client: clients::Authority,
}

impl Authority {
    pub fn params() -> Result<param::Set, Error> {
        param::Set::builder()
            .idle_ms(30_000)
            .datagram(Some(65_535))
            .cid_limit(8)
            .initial_data(1 << 20)
            .local_bidi(1 << 20)
            .remote_bidi(1 << 20)
            .stream_uni(1 << 20)
            .bidi_count(8)
            .try_build()
            .map_err(Error::Params)
    }

    pub fn options(params: param::Set) -> Result<Options, Error> {
        Options::builder()
            .transport(|wire| wire.params(params))
            .try_build()
            .map_err(Error::Options)
    }

    pub fn try_new(options: Options) -> Result<Self, Error> {
        use dope_tls::config;

        let (signing, key) = peer::raw(0x77)
            .map_err(Setup::Identity)
            .map_err(Error::Setup)?;
        let mut config = config::raw::Identity::client(key)
            .map_err(Setup::Tls)
            .map_err(Error::Setup)?;
        config.resumption = Resumption::in_memory_sessions(16);
        config.enable_early_data = true;
        let name = ServerName::IpAddress(Ipv4Addr::LOCALHOST.into());
        let client = clients::Authority::try_new(config, name)
            .map_err(|cause| Setup::Authority(cause.into()))
            .map_err(Error::Setup)?;
        let mut config = signing.server().map_err(Setup::Tls).map_err(Error::Setup)?;
        config.send_tls13_tickets = 2;
        let capacity = ReplayCap::new(64).ok_or(Error::Replay((64, ReplayCap::MAX)))?;
        let server = accept::Authority::with_early(config, options, capacity)
            .map_err(Setup::Authority)
            .map_err(Error::Setup)?;
        Ok(Self { server, client })
    }

    pub fn first(&self, local: &[u8]) -> Result<(), Error> {
        let initial = if local.len() == routing::CONNECTION_ID_LEN {
            local
        } else {
            &CID
        };
        let initial = cid::Id::try_from(initial)
            .map_err(Setup::Id)
            .map_err(Error::Setup)?;
        let local = cid::Id::try_from(local)
            .map_err(Setup::Id)
            .map_err(Error::Setup)?;
        let peer = cid::Id::try_from(CID)
            .map_err(Setup::Id)
            .map_err(Error::Setup)?;
        let server = self
            .server
            .accept::<storage::Shared>(accept::Ids::initial(initial, local, peer))
            .map_err(Setup::Accept)
            .map_err(Error::Setup)?;
        let options = Self::options(Self::params()?)?;
        let client = if local.len() == routing::CONNECTION_ID_LEN {
            self.client.connect::<0, Vec<u8>, storage::Shared>(
                initial,
                peer,
                options,
                routing::Shard::from_index(local.as_slice()[0]),
            )
        } else {
            self.client.connect::<0, Vec<u8>, storage::Shared>(
                initial,
                peer,
                options,
                routing::Plain,
            )
        };
        let mut pair = Pair {
            server,
            client: client.map_err(Setup::Connect).map_err(Error::Setup)?,
            work: conn::Workspace::try_new()
                .map_err(Setup::Workspace)
                .map_err(Error::Setup)?,
        };
        pair.exchange(Instant::now(), 4).map_err(Error::Setup)?;
        pair.try_ready().map_err(Error::Setup)
    }

    pub fn resume(
        &self,
        initial: cid::Id,
        local: cid::Id,
        route: impl routing::PeerRoute,
    ) -> Result<conn::Connection, Error> {
        let options = Self::options(Self::params()?)?;
        self.client
            .connect::<0, Vec<u8>, storage::Shared>(initial, local, options, route)
            .map_err(Setup::Connect)
            .map_err(Error::Setup)
    }

    pub fn resumed(&self, server: [u8; 8], client: [u8; 8]) -> Result<Pair, Error> {
        self.pair_to(&self.server, server, client)
    }

    pub fn pair_to(
        &self,
        target: &accept::Authority,
        server: [u8; 8],
        client: [u8; 8],
    ) -> Result<Pair, Error> {
        let initial = cid::Id::try_from([0x61; routing::ENTROPY_LEN])
            .map_err(Setup::Id)
            .map_err(Error::Setup)?;
        let server = cid::Id::try_from(server)
            .map_err(Setup::Id)
            .map_err(Error::Setup)?;
        let client = cid::Id::try_from(client)
            .map_err(Setup::Id)
            .map_err(Error::Setup)?;
        let server = target
            .accept::<storage::Shared>(accept::Ids::initial(initial, server, client))
            .map_err(Setup::Accept)
            .map_err(Error::Setup)?;
        let client = self.resume(initial, client, routing::Plain)?;
        Ok(Pair {
            server,
            client,
            work: conn::Workspace::try_new()
                .map_err(Setup::Workspace)
                .map_err(Error::Setup)?,
        })
    }
}

impl Error {
    pub fn cause(&self) -> &dyn Debug {
        match self {
            Self::Setup(cause) => cause,
            Self::Params(cause) => cause,
            Self::Options(cause) => cause,
            Self::Replay(cause) => cause,
            Self::Reconnect(cause) => cause.error(),
        }
    }
}
