use crate::common::suite::peers::tls;
use crate::common::{peer, runtime};
use dope_quic::conn::life::accept;
use dope_quic::proto::epoch;
use dope_quic::runtime::mux::builder;
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::runtime::mux::builder::Plan;
use options::builder::Invalid;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::time::{Duration, Instant};

use dope_quic::conn::id::{self, Handle};
use dope_quic::conn::life::options;
use dope_quic::proto::param;
use dope_quic::runtime::mux::output::Flight;
use dope_quic::runtime::mux::router::Router;
use dope_quic::runtime::mux::{handler, manage};
use dope_quic::{conn, errors};
use handler::hook::{life::create, set, wire::cert};
use o3::buffer::storage;
use peer::Setup;

pub const SERVER: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 443));
pub const CLIENT: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 50_000));

#[derive(Default)]
pub struct Seen {
    pub created: usize,
    pub certificates: usize,
}

impl handler::Handler<0, Vec<u8>, storage::Shared> for Seen {
    type Connection = ();
    type Create = create::Call;
    type Events = set::Set;
}

impl create::Sink<0, Vec<u8>, storage::Shared, id::Static> for Seen {
    fn create(event: create::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (mut seen, _, _) = event.into_parts();
        seen.created += 1;
    }
}

impl cert::Sink<0, id::Static> for Seen {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (mut seen, _, _, _) = event.into_parts();
        seen.certificates += 1;
    }
}

#[derive(Debug)]
pub enum Error {
    Runtime(runtime::Error),
    Created {
        expected: usize,
        actual: usize,
    },
    Setup(Setup),
    Limits(builder::Error),
    Params(param::Error),
    Options(Invalid),
    Gso(manage::GsoError),
    Output(errors::Transmit),
    Receive {
        from: SocketAddr,
        cause: errors::Receive,
    },
}

pub struct Pair {
    pub client: Router<Seen>,
    pub server: Router<Seen>,
    pub handles: Vec<Handle>,
    pub now: Instant,
}

impl Seen {
    pub fn pump(
        src: &mut Router<Seen>,
        dst: &mut Router<Seen>,
        addr: SocketAddr,
        now: Instant,
    ) -> Result<(), Error> {
        loop {
            let item = Pin::new(&mut *src).observe(now, |mut turn| {
                turn.output().drive().map_err(Error::Output)?;
                Ok::<_, Error>(turn.output().drain().next())
            })?;
            let Some(mut item) = item else {
                return Ok(());
            };
            for packet in item.segments_mut() {
                Pin::new(&mut *dst)
                    .observe(now, |mut turn| {
                        turn.protocol().recv(addr, packet, epoch::WALL_CLOCK)
                    })
                    .map_err(|cause| Error::Receive { from: addr, cause })?;
                if dst.handler().certificates != 0 {
                    return Err(Error::Runtime(runtime::Error::Certificates(
                        dst.handler().certificates,
                    )));
                }
            }
            Pin::new(&mut *src).output().recycle(item);
        }
    }

    pub fn try_pair(gso: bool, count: usize) -> Result<Pair, Error> {
        let (signing, key) = peer::raw(0x81)
            .map_err(Setup::Identity)
            .map_err(Error::Setup)?;
        let options = || {
            let params = param::Set::builder()
                .idle_ms(30_000)
                .datagram(Some(65_535))
                .cid_limit(4)
                .try_build()
                .map_err(Error::Params)?;
            options::Options::builder()
                .transport(|wire| wire.params(params))
                .security(|security| security.reset(Some([0x82; 32])))
                .try_build()
                .map_err(Error::Options)
        };
        let config = signing.server().map_err(Setup::Tls).map_err(Error::Setup)?;
        let auth = accept::Authority::new(config, options()?)
            .map_err(Setup::Authority)
            .map_err(Error::Setup)?;
        let standard = Plan::standard();
        let server =
            Plan::try_new(standard.connections(), 32, standard.bytes()).map_err(Error::Limits)?;
        let client = Plan::try_new(count, 32, 1 << 20).map_err(Error::Limits)?;
        let mut server = Builder::server(Seen::default(), auth)
            .limits(server)
            .build()
            .map_err(Setup::ServerBuild)
            .map_err(Error::Setup)?;
        let mut client = Builder::client(Seen::default())
            .limits(client)
            .build()
            .map_err(Setup::ClientBuild)
            .map_err(Error::Setup)?;
        if gso {
            Pin::new(&mut client)
                .config()
                .enable_gso()
                .map_err(Error::Gso)?;
        }
        let mut now = Instant::now();
        let mut handles = Vec::with_capacity(count);
        let auth = tls::client(key).map_err(Setup::Tls).map_err(Error::Setup)?;
        for index in 0..count {
            let options = options()?;
            let handle = Pin::new(&mut client)
                .observe(now, |mut turn| {
                    turn.protocol().connect(
                        SERVER,
                        &auth,
                        options,
                        (index as u64 + 1).to_be_bytes().to_vec(),
                    )
                })
                .map_err(Setup::Connect)
                .map_err(Error::Setup)?;
            handles.push(handle);
        }
        for _ in 0..16 {
            Self::pump(&mut client, &mut server, CLIENT, now)?;
            now = now
                .checked_add(Duration::from_millis(1))
                .ok_or(Error::Runtime(runtime::Error::Deadline(now)))?;
            Self::pump(&mut server, &mut client, SERVER, now)?;
            now = now
                .checked_add(Duration::from_millis(1))
                .ok_or(Error::Runtime(runtime::Error::Deadline(now)))?;
        }
        if server.handler().created != count {
            return Err(Error::Created {
                expected: count,
                actual: server.handler().created,
            });
        }
        Ok(Pair {
            client,
            server,
            handles,
            now,
        })
    }

    pub fn try_many(
        gso: bool,
        count: usize,
    ) -> Result<(Router<Seen>, Vec<Handle>, Instant), Error> {
        let Pair {
            mut client,
            mut server,
            handles,
            mut now,
        } = Self::try_pair(gso, count)?;
        now = now
            .checked_add(Duration::from_millis(30))
            .ok_or(Error::Runtime(runtime::Error::Deadline(now)))?;
        Self::pump(&mut client, &mut server, CLIENT, now)?;
        Ok((client, handles, now))
    }

    pub fn packet_count(flights: &[Flight]) -> usize {
        flights
            .iter()
            .map(|flight| flight.packet_count().get())
            .sum()
    }

    pub fn enqueue(
        client: &mut Router<Seen>,
        handle: Handle,
        packets: usize,
        bytes: usize,
        now: Instant,
    ) -> Result<(), errors::SendFailure<Vec<u8>>> {
        Pin::new(client).observe(now, |mut turn| {
            for value in 0..packets {
                turn.protocol()
                    .try_datagram(handle, vec![value as u8; bytes])?;
            }
            Ok(())
        })
    }

    pub fn take_one(
        client: &mut Router<Seen>,
        now: Instant,
    ) -> Result<Option<Flight>, errors::Transmit> {
        Pin::new(client).observe(now, |mut turn| {
            turn.output().drive()?;
            Ok(turn.output().drain().next())
        })
    }

    pub fn rotate_cid(
        client: &mut Router<Seen>,
        server: &mut Router<Seen>,
        id: Handle,
        mut now: Instant,
    ) -> Result<Instant, Error> {
        use conn::scope::path::Rotation;

        let rotated = Pin::new(&mut *server)
            .observe(now, |mut turn| turn.protocol().rotate_cid(id))
            .map_err(runtime::Error::Access)
            .map_err(Error::Runtime)?;
        if rotated != Rotation::Queued {
            return Err(Error::Runtime(runtime::Error::RotationUnavailable));
        }
        for _ in 0..16 {
            Self::pump(server, client, SERVER, now)?;
            now = now
                .checked_add(Duration::from_millis(1))
                .ok_or(Error::Runtime(runtime::Error::Deadline(now)))?;
            Self::pump(client, server, CLIENT, now)?;
            now = now
                .checked_add(Duration::from_millis(1))
                .ok_or(Error::Runtime(runtime::Error::Deadline(now)))?;
        }
        Ok(now)
    }
}
