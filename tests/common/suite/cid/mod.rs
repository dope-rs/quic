use crate::common::peer;
use crate::common::suite::peers::tls;
use crate::common::{runtime, suite::mux::dispatch::Capture};
use dope_quic::runtime::mux::builder;
pub mod contract;
mod driver;
use crate::common::e2e::life::driver::Ticket;
use crate::common::e2e::life::error;
use crate::common::e2e::life::identity::{RouteId, TransportId};
use crate::common::e2e::life::{self, Step};
use conn::life::accept::Authority;
use dope_quic::conn;
use dope_quic::conn::id::{self, Handle};
use dope_quic::conn::life::options::Options;
use dope_quic::conn::scope::path::Rotation;
use dope_quic::errors;
use dope_quic::errors::Access;
use dope_quic::errors::SendFailure;
use dope_quic::proto::epoch;
use dope_quic::proto::param;
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::runtime::mux::builder::Failure;
use dope_quic::runtime::mux::builder::Plan;
use dope_quic::runtime::mux::handler::hook::data::datagram;
use dope_quic::runtime::mux::handler::hook::life::{create, ready};
use dope_quic::runtime::mux::handler::hook::set;
use dope_quic::runtime::mux::handler::hook::wire::cert;
use dope_quic::runtime::mux::{handler, router};
use dope_test::quic::wire::ShortHeader;
use o3::buffer::storage;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Instant;
pub const INITIAL: [u8; 8] = [0x42; 8];

#[derive(Default)]
pub struct Count {
    pub certificates: usize,
    pub established: usize,
    pub datagrams: usize,
    pub last_handle: Option<Handle>,
    pub handles: Vec<Handle>,
}
impl handler::Handler<0, Vec<u8>, storage::Shared> for Count {
    type Connection = ();
    type Create = create::Call;
    type Events = set::Set<set::On, set::On>;
}

impl create::Sink<0, Vec<u8>, storage::Shared, id::Static> for Count {
    fn create(event: create::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (mut this, _, handle) = event.into_parts();
        this.handles.push(handle);
    }
}

impl ready::Sink<0, Vec<u8>, storage::Shared, id::Static> for Count {
    fn established(event: ready::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (mut this, _, handle, _) = event.into();
        this.established += 1;
        this.last_handle = Some(handle);
    }
}

impl datagram::Sink<0, Vec<u8>, storage::Shared, id::Static> for Count {
    fn datagram(event: datagram::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (mut this, _, _, _, _) = event.into();
        this.datagrams += 1;
    }
}

impl Count {
    pub fn options() -> Result<Options, runtime::Error> {
        let params = param::Set::builder()
            .idle_ms(30_000)
            .datagram(Some(65535))
            .cid_limit(4)
            .try_build()
            .map_err(runtime::Error::Parameters)?;
        (Options::builder()
            .transport(|tp| tp.params(params))
            .journals(|journals| journals.control::<32>())
            .security(|security| security.reset(Some([0x5c; 32])))
            .try_build())
        .map_err(runtime::Error::Options)
    }

    pub fn try_keys() -> Result<([u8; 32], rustls::ServerConfig), runtime::Error> {
        let (signing, key) = peer::raw(0x39).map_err(runtime::Error::Identity)?;
        Ok((key, signing.server().map_err(runtime::Error::Tls)?))
    }

    pub fn server(
        config: rustls::ServerConfig,
        limits: Plan,
    ) -> Result<router::Router<Count>, runtime::Error> {
        let accept = Authority::new(config, Self::options()?).map_err(runtime::Error::Connect)?;
        Builder::server(Count::default(), accept)
            .limits(limits)
            .build()
            .map_err(runtime::Error::Storage)
    }

    pub fn connect(
        client: &mut router::Router<Count>,
        peer: SocketAddr,
        key: [u8; 32],
        cid: Vec<u8>,
        now: Instant,
    ) -> Result<Handle, runtime::Error> {
        let options = Self::options()?;
        let auth = tls::client(key).map_err(runtime::Error::Tls)?;
        Pin::new(client)
            .observe(now, |mut turn| {
                turn.protocol().connect(peer, &auth, options, cid)
            })
            .map_err(runtime::Error::Connect)
    }

    pub fn send(
        client: &mut router::Router<Count>,
        handle: Handle,
        payload: Vec<u8>,
        now: Instant,
    ) -> Result<(), SendFailure<Vec<u8>>> {
        Pin::new(client).observe(now, |mut turn| {
            turn.protocol().try_datagram(handle, payload)
        })
    }

    pub fn receive(
        dst: &mut router::Router<Count>,
        src_addr: SocketAddr,
        packet: &mut [u8],
        now: Instant,
    ) -> Result<(), runtime::Error> {
        let result = Pin::new(&mut *dst).observe(now, |mut turn| {
            turn.protocol().recv(src_addr, packet, epoch::WALL_CLOCK)
        });
        if dst.handler().certificates != 0 {
            return Err(runtime::Error::Certificates(dst.handler().certificates));
        }
        result.map_err(runtime::Error::Receive)
    }

    pub fn rotate(
        mux: &mut router::Router<Count>,
        handle: Handle,
        now: Instant,
    ) -> Result<Rotation, Access> {
        Pin::new(mux).observe(now, |mut turn| turn.protocol().rotate_cid(handle))
    }

    pub fn relay(
        src: &mut router::Router<Count>,
        dst: &mut router::Router<Count>,
        src_addr: SocketAddr,
    ) -> Result<(), runtime::Error> {
        let now = Instant::now();
        let outgoing = Capture::output(src, now).map_err(runtime::Error::Output)?;
        for mut outgoing in outgoing {
            for segment in outgoing.segments_mut() {
                Self::receive(dst, src_addr, segment, now)?;
            }
            Pin::new(&mut *src).output().recycle(outgoing);
        }
        Ok(())
    }

    pub fn relay_at(
        src: &mut router::Router<Count>,
        dst: &mut router::Router<Count>,
        src_addr: SocketAddr,
        now: Instant,
    ) -> Result<Vec<Vec<u8>>, runtime::Error> {
        let mut wires = Vec::new();
        let outgoing = Capture::output(src, now).map_err(runtime::Error::Output)?;
        for mut outgoing in outgoing {
            for segment in outgoing.segments_mut() {
                wires.push(segment.to_vec());
                Self::receive(dst, src_addr, segment, now)?;
            }
            Pin::new(&mut *src).output().recycle(outgoing);
        }
        Ok(wires)
    }

    pub fn short_cid(wire: &[u8]) -> Option<[u8; 8]> {
        let wire = ShortHeader::new(wire).cid(8)?;
        let mut cid = [0; 8];
        cid.copy_from_slice(wire);
        Some(cid)
    }

    pub fn changed_cid(wires: &[Vec<u8>], previous: [u8; 8]) -> Option<[u8; 8]> {
        wires
            .iter()
            .filter_map(|wire| Self::short_cid(wire))
            .find(|cid| *cid != previous)
    }
}

impl cert::Sink<0, id::Static> for Count {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (mut count, _, _, _) = event.into_parts();
        count.certificates += 1;
    }
}

#[derive(Debug)]
pub enum Error {
    Runtime(runtime::Error),
    Route(RouteId),
    Limits(builder::Error),
    Witness(error::Witness),
    Build(Failure),
    Initial(errors::Connect),
    ProbeSend(errors::SendFailure<Vec<u8>>),
    PathSend(errors::SendFailure<Vec<u8>>),
    Connect(errors::Connect),
    Retire(errors::Access),
    Setup {
        client: usize,
        server: usize,
    },
    Handle {
        established: usize,
    },
    Delivery {
        expected: usize,
        actual: usize,
    },
    Connection {
        handle: Handle,
    },
    Cid {
        handle: Handle,
    },
    Sweep {
        visited: usize,
        started: usize,
        complete: bool,
    },
    ProbeCid,
    Rotation {
        emitted: bool,
        changed: bool,
        retired: bool,
    },
    Path {
        expected: SocketAddr,
        actual: Option<SocketAddr>,
        sent: usize,
        received: usize,
    },
    Generation {
        actual: u32,
    },
    Replacement {
        client: usize,
        server: usize,
        expected: usize,
    },
    Overlap {
        server: usize,
        client: usize,
    },
    Drain {
        retiring: usize,
        server: usize,
    },
    Target {
        target: life::Target,
        route: RouteId,
        transport: TransportId,
    },
    Action(Step),
    Pending {
        ticket: Ticket,
        step: Step,
    },
    Idle {
        ticket: Ticket,
    },
    Ticket {
        expected: Ticket,
        actual: Ticket,
    },
}
