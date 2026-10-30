use crate::common::peer::{Setup, Transfer};
use crate::common::suite::peers::tls::Capture;
use dope_quic::conn::life::accept;
use dope_quic::conn::life::options::Options;
use dope_quic::conn::life::tls::clients;
use dope_quic::runtime::routing;
use dope_quic::wire::packet::cid;
use dope_quic::{conn, proto::param};
use dope_tls::config;
use o3::buffer::storage;
use rustls::pki_types::ServerName;
use std::net::Ipv4Addr;
use std::time::Instant;

pub struct Pair {
    pub server: conn::Connection,
    pub client: conn::Connection,
    pub work: conn::Workspace,
}

pub struct Run {
    pub cli: bool,
    pub srv: bool,
    pub cli_err: Vec<conn::Error>,
    pub srv_err: Vec<conn::Error>,
}

impl Pair {
    pub fn try_new(identity: Option<config::raw::Identity>, permit: bool) -> Result<Self, Setup> {
        let (identity, key) = match identity {
            Some(identity) if permit => {
                let key = identity.public_key();
                (Some(identity), key)
            }
            Some(identity) => (
                Some(identity),
                config::raw::Identity::from_seed(&[0x53; 32])
                    .map_err(Setup::Tls)?
                    .public_key(),
            ),
            None => (
                None,
                config::raw::Identity::from_seed(&[0x52; 32])
                    .map_err(Setup::Tls)?
                    .public_key(),
            ),
        };
        Self::build(
            0x51,
            identity,
            key,
            Capture::options()?,
            Capture::options()?,
        )
    }

    pub fn try_datagram() -> Result<Self, Setup> {
        let params = param::Set::builder()
            .idle_ms(30_000)
            .datagram(Some(65_535))
            .try_build()
            .map_err(Setup::Params)?;
        let identity = config::raw::Identity::from_seed(&[0x62; 32]).map_err(Setup::Tls)?;
        let key = identity.public_key();
        Self::build(
            0x61,
            Some(identity),
            key,
            Options::try_from(params.clone()).map_err(Setup::Options)?,
            Options::try_from(params).map_err(Setup::Options)?,
        )
    }

    fn build(
        seed: u8,
        identity: Option<config::raw::Identity>,
        peer: [u8; 32],
        client: Options,
        server: Options,
    ) -> Result<Self, Setup> {
        let signing = config::raw::Identity::from_seed(&[seed; 32]).map_err(Setup::Tls)?;
        let key = signing.public_key();
        let id = cid::Id::try_from([0x42; 8]).map_err(Setup::Id)?;
        let server = accept::Authority::new(signing.server_auth(peer).map_err(Setup::Tls)?, server)
            .map_err(Setup::Authority)?
            .accept::<storage::Shared>(accept::Ids::initial(id, id, id))
            .map_err(Setup::Accept)?;
        let config = match identity {
            Some(identity) => identity.mutual(key),
            None => config::raw::Identity::client(key),
        }
        .map_err(Setup::Tls)?;
        let client =
            clients::Authority::try_new(config, ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()))
                .map_err(|cause| Setup::Authority(cause.into()))?
                .connect::<0, Vec<u8>, storage::Shared>(id, id, client, routing::Plain)
                .map_err(Setup::Connect)?;
        Ok(Self {
            server,
            client,
            work: conn::Workspace::try_new().map_err(Setup::Workspace)?,
        })
    }

    pub fn try_run(mut self) -> Result<Run, Transfer> {
        let mut cli_err = Vec::new();
        let mut srv_err = Vec::new();
        for _ in 0..6 {
            let now = Instant::now();
            let (packets, result) = self.client.with_scope(|mut scope| scope.output().send(now));
            result.map_err(Transfer::Output)?;
            for mut packet in packets {
                if let Err(error) = self.server.with_scope(|mut scope| {
                    scope.input(&mut self.work).recv_packet(
                        &mut packet,
                        now,
                        |_: &rustls::Error| {},
                    )
                }) {
                    srv_err.push(error);
                }
            }
            let (packets, result) = self.server.with_scope(|mut scope| scope.output().send(now));
            result.map_err(Transfer::Output)?;
            for mut packet in packets {
                if let Err(error) = self.client.with_scope(|mut scope| {
                    scope.input(&mut self.work).recv_packet(
                        &mut packet,
                        now,
                        |_: &rustls::Error| {},
                    )
                }) {
                    cli_err.push(error);
                }
            }
        }
        Ok(Run {
            cli: self.client.view().lifecycle().is_ready(),
            srv: self.server.view().lifecycle().is_ready(),
            cli_err,
            srv_err,
        })
    }
}
