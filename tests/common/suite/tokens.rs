use crate::common::peer;
use std::{
    cell::Cell,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    pin::Pin,
    time::{Duration, Instant},
};

use crate::common::{
    runtime::Error,
    suite::{mux::dispatch, peers},
};
use dope::runtime::civil;
use dope_quic::errors;
use dope_quic::{
    conn::{
        id,
        life::{Reconnect, accept, options::Options, tls::clients},
    },
    proto::epoch,
    runtime::{
        mux::{
            builder::{Builder, Plan},
            handler,
            handler::hook::{life::create, set, wire::cert},
            router,
        },
        routing::Plain,
    },
};
use dope_tls::config;
use o3::{
    base::time::{Nanos, Unix},
    buffer::storage,
};
use peer::Setup;
use rustls::pki_types::ServerName;

pub const FIRST_DCID: [u8; 8] = [0x41; 8];
pub const SERVER: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 443));
pub const CLIENT: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 50_000));
pub const START_MILLIS: u64 = 1_800_000_000_000;
pub const TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Default)]
pub struct Capture {
    pub handles: Vec<id::Handle>,
    pub certificates: usize,
}

impl handler::Handler<0, Vec<u8>, storage::Shared> for Capture {
    type Connection = ();
    type Create = create::Call;
    type Events = set::Set;
}

impl create::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture {
    fn create(event: create::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (mut this, _, handle) = event.into_parts();
        this.handles.push(handle);
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Civil<'a>(pub &'a Cell<Unix<Nanos>>);

impl civil::Source for Civil<'_> {
    fn read(&self) -> Result<Unix<Nanos>, civil::Error> {
        Ok(self.0.get())
    }
}

impl cert::Sink<0, id::Static> for Capture {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (mut this, _, _, _) = event.into_parts();
        this.certificates += 1;
    }
}

impl Civil<'_> {
    pub fn manual() -> Cell<Unix<Nanos>> {
        let nanos = const { START_MILLIS * 1_000_000 };
        Cell::new(Unix::<Nanos>::new(nanos))
    }
}

impl Capture {
    pub fn relay(
        src: &mut router::Router<Capture>,
        dst: &mut router::Router<Capture>,
        source: SocketAddr,
        civil: Civil<'_>,
    ) -> Result<usize, Error> {
        let now = Instant::now();
        let packets = dispatch::Capture::output(src, now).map_err(Error::Output)?;
        let mut count = 0;
        Pin::new(&mut *dst).observe(now, |mut turn| {
            for mut packet in packets {
                count += packet.packet_count().get();
                for segment in packet.segments_mut() {
                    turn.protocol()
                        .recv(source, segment, epoch::Sample::new(civil))
                        .map_err(Error::Receive)?;
                }
            }
            turn.output().drive().map_err(Error::Output)?;
            Ok::<(), Error>(())
        })?;
        if dst.handler().certificates != 0 {
            return Err(Error::Certificates(dst.handler().certificates));
        }
        Ok(count)
    }
    pub fn server() -> Result<(router::Router<Capture>, [u8; 32]), Setup> {
        let (signing, key) = peer::raw(0x39).map_err(Setup::Identity)?;
        let options = (Options::builder()
            .security(|security| security.retry([0x9a; 32]))
            .try_build())
        .map_err(Setup::Options)?;
        let auth = accept::Authority::new(signing.server().map_err(Setup::Tls)?, options)
            .map_err(Setup::Authority)?;
        let server = Builder::server(Capture::default(), auth)
            .build()
            .map_err(Setup::ServerBuild)?;
        Ok((server, key))
    }
    pub fn issue(
        server: &mut router::Router<Capture>,
        key: [u8; 32],
        dcid: [u8; 8],
        peer: SocketAddr,
        civil: Civil<'_>,
    ) -> Result<(router::Router<Capture>, Option<Reconnect>), Error> {
        let mut client = Builder::client(Capture::default())
            .limits(Plan::try_new(1, 1024, 4 * 1024 * 1024).map_err(Error::Limits)?)
            .build()
            .map_err(Error::Storage)?;
        let config = config::raw::Identity::client(key).map_err(Error::Tls)?;
        let name = match ServerName::try_from(String::from("localhost")) {
            Ok(name) => name,
            Err(_) => unreachable!("hostname"),
        };
        let auth = clients::Authority::try_new(config, name)
            .map_err(|cause| Error::Connect(cause.into()))?;
        let handle = Pin::new(&mut client)
            .observe(Instant::now(), |mut turn| {
                turn.protocol()
                    .connect(SERVER, &auth, Options::default(), dcid.to_vec())
            })
            .map_err(Error::Connect)?;
        let mut resume = None;
        for _ in 0..32 {
            Self::relay(&mut client, server, peer, civil)?;
            Self::relay(server, &mut client, SERVER, civil)?;
            resume = Pin::new(&mut client)
                .observe(Instant::now(), |mut turn| {
                    turn.protocol()
                        .with_conn(handle, |mut scope| scope.security().try_saved())
                })
                .map_err(Error::Access)?
                .map_err(errors::Connect::from)
                .map_err(Error::Connect)?
                .or(resume);
            if resume.is_some() {
                break;
            }
        }
        Ok((client, resume))
    }
    pub fn client(resume: Reconnect) -> Result<router::Router<Capture>, peers::Error> {
        let mut client = Builder::client(Capture::default())
            .build()
            .map_err(Setup::ClientBuild)
            .map_err(peers::Error::Setup)?;
        Pin::new(&mut client)
            .observe(Instant::now(), |mut turn| {
                turn.protocol().reconnect(Options::default(), resume, Plain)
            })
            .map_err(peers::Error::Reconnect)?;
        Ok(client)
    }
    pub fn drain(mux: &mut router::Router<Capture>) -> Result<usize, errors::Transmit> {
        let now = Instant::now();
        dispatch::Capture::drive(mux, now)?;
        Ok(Pin::new(mux).observe(now, |mut turn| {
            turn.output()
                .drain()
                .map(|packet| packet.packet_count().get())
                .sum()
        }))
    }
}

pub struct Unavailable;

impl civil::Source for Unavailable {
    fn read(&self) -> Result<Unix<Nanos>, civil::Error> {
        Err(civil::Error::BeforeUnixEpoch {
            delta: Duration::from_nanos(1),
        })
    }
}

pub struct Count {
    pub samples: Cell<usize>,
    pub now: Unix<Nanos>,
}

impl civil::Source for &Count {
    fn read(&self) -> Result<Unix<Nanos>, civil::Error> {
        self.samples.set(self.samples.get() + 1);
        Ok(self.now)
    }
}
