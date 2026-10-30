use crate::common::peer::{self, Receiver as _};
use dope_quic::conn::life::accept::Authority;
use dope_quic::conn::life::options::Options;
use dope_quic::proto::{epoch, param};
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::runtime::mux::builder::Plan;
use std::cell::Cell;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::common::runtime::Error;
use crate::common::suite::peers::tls;
use dope_quic::conn::stream::Event;
use dope_quic::conn::{self, id, output::transmit, scope};
use dope_quic::errors;
use dope_quic::runtime::mux::handler::hook::data::{datagram, stream};
use dope_quic::runtime::mux::handler::hook::life::{create, ready};
use dope_quic::runtime::mux::handler::hook::set;
use dope_quic::runtime::mux::handler::hook::wire::cert;
use dope_quic::runtime::mux::{self, handler, output, router};
use dope_quic::runtime::routing;
use dope_quic::wire::packet::cid;
use dope_test::harness::observe::VecCellExt as _;
use o3::{alloc, buffer::storage};

pub const CID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
pub const CLIENT: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 50_000));
pub const SERVER: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 443));
pub const SERVER_B: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 443));

pub fn options() -> Result<Options, Error> {
    let params = param::Set::builder()
        .idle_ms(30_000)
        .datagram(Some(65_535))
        .try_build()
        .map_err(Error::Parameters)?;
    Options::builder()
        .transport(|net| net.params(params).max_pmtu(1_200))
        .try_build()
        .map_err(Error::Options)
}

#[derive(Debug)]
pub enum ConnectError {
    Runtime(Error),
    Output(transmit::Error),
    Input(peer::Transfer),
    Storage(alloc::Error),
}

#[derive(Default)]
pub struct Events {
    pub certificates: Cell<usize>,
    pub established: Cell<Vec<id::Handle>>,
    pub streams: Cell<Vec<(id::Handle, Event)>>,
    pub datagrams: Cell<Vec<(id::Handle, Vec<u8>)>>,
    pub data: Cell<Vec<(id::Handle, Option<Event>)>>,
    pub defer_readable: Cell<bool>,
    overflow: Cell<bool>,
}

impl Events {
    pub fn clear_stream(&self) {
        let mut streams = self.streams.take();
        streams.clear();
        self.streams.set(streams);
    }
}

#[derive(Clone, Default)]
pub struct Capture {
    pub events: Rc<Events>,
}

impl handler::Handler<0, Vec<u8>, storage::Shared> for Capture {
    type Connection = ();
    type Create = create::Unit;
    type Events = set::Set<set::On, set::On, set::On>;
}

impl ready::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture {
    fn established(event: ready::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, _, handle, _) = event.into();
        this.events.established.push(handle);
    }
}

impl stream::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture {
    fn stream(
        event: stream::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>,
    ) -> mux::Disposition {
        let (this, _, handle, event, _) = event.into();
        let event = event.event();
        let events = &this.events;
        events.streams.push((handle, event));
        let defer = events.defer_readable.get();
        if defer {
            events.data.push((handle, Some(event)));
        }
        if defer && matches!(event, Event::Readable { .. }) {
            mux::Disposition::Defer
        } else {
            mux::Disposition::Accept
        }
    }
}

impl datagram::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture {
    fn datagram(event: datagram::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, _, handle, data, _) = event.into();
        let events = &this.events;
        events.datagrams.push((handle, data));
        if events.defer_readable.get() {
            events.data.push((handle, None));
        }
    }
}

impl cert::Sink<0, id::Static> for Capture {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (this, _, _, _) = event.into_parts();
        let count = this.events.certificates.get();
        if let Some(count) = count.checked_add(1) {
            this.events.certificates.set(count);
        } else {
            this.events.overflow.set(true);
        }
    }
}

impl Capture {
    pub fn server(
        capture: Capture,
        config: rustls::ServerConfig,
        options: Options,
    ) -> Result<router::Router<Capture>, Error> {
        let auth = Authority::new(config, options).map_err(Error::Connect)?;
        let standard = Plan::standard();
        Builder::server(capture, auth)
            .limits(
                Plan::try_new(standard.connections(), 64, standard.bytes())
                    .map_err(Error::Limits)?,
            )
            .build()
            .map_err(Error::Storage)
    }

    pub fn receive(
        mux: &mut router::Router<Capture>,
        from: SocketAddr,
        packet: &mut [u8],
        now: Instant,
    ) -> Result<(), Error> {
        Pin::new(&mut *mux)
            .observe(now, |mut turn| {
                turn.protocol().recv(from, packet, epoch::WALL_CLOCK)
            })
            .map_err(Error::Receive)?;
        let events = &mux.handler().events;
        if events.overflow.get() {
            return Err(Error::CertificateOverflow);
        }
        let count = events.certificates.get();
        if count != 0 {
            return Err(Error::Certificates(count));
        }
        Ok(())
    }

    pub fn connect(
        mux: &mut router::Router<Capture>,
        peer: SocketAddr,
        key: [u8; 32],
        options: Options,
        cid: Vec<u8>,
        now: Instant,
    ) -> Result<id::Handle, Error> {
        let auth = tls::client(key).map_err(Error::Tls)?;
        Pin::new(mux)
            .observe(now, |mut turn| {
                turn.protocol().connect(peer, &auth, options, cid)
            })
            .map_err(Error::Connect)
    }

    pub fn connect_peer(
        mux: &mut router::Router<Capture>,
        key: [u8; 32],
        options: Options,
        initial: cid::Id,
        local: cid::Id,
        now: &mut Instant,
    ) -> Result<conn::Connection, ConnectError> {
        let auth = tls::client(key)
            .map_err(Error::Tls)
            .map_err(ConnectError::Runtime)?;
        let mut client = auth
            .connect::<0, Vec<u8>, storage::Shared>(initial, local, options, routing::Plain)
            .map_err(Error::Connect)
            .map_err(ConnectError::Runtime)?;
        let mut work = conn::Workspace::try_new().map_err(ConnectError::Storage)?;
        for _ in 0..16 {
            *now = now
                .checked_add(Duration::from_millis(30))
                .ok_or(Error::Deadline(*now))
                .map_err(ConnectError::Runtime)?;
            let (packets, result) = client.with_scope(|mut scope| scope.output().send(*now));
            result.map_err(ConnectError::Output)?;
            for mut packet in packets {
                Self::receive(mux, CLIENT, &mut packet, *now).map_err(ConnectError::Runtime)?;
            }
            let flights = Self::output(mux, *now)
                .map_err(Error::Output)
                .map_err(ConnectError::Runtime)?;
            for mut flight in flights {
                for packet in flight.segments_mut() {
                    client
                        .receive(&mut work, packet, *now)
                        .map_err(ConnectError::Input)?;
                }
            }
        }
        Ok(client)
    }

    pub fn send(
        mux: &mut router::Router<Capture>,
        handle: id::Handle,
        payload: Vec<u8>,
        now: Instant,
    ) -> Result<(), errors::SendFailure<Vec<u8>>> {
        Pin::new(mux).observe(now, |mut turn| {
            turn.protocol().try_datagram(handle, payload)
        })
    }

    pub fn output(
        router: &mut router::Router<Capture>,
        now: Instant,
    ) -> Result<Vec<output::Flight>, errors::Transmit> {
        Pin::new(router).observe(now, |mut turn| {
            turn.output().drive()?;
            Ok(turn.output().drain().collect())
        })
    }

    pub fn access<R>(
        mux: &mut router::Router<Capture>,
        handle: id::Handle,
        now: Instant,
        op: impl for<'scope> FnOnce(scope::Turn<'scope, 0, Vec<u8>, storage::Shared>) -> R,
    ) -> Result<R, errors::Access> {
        Pin::new(mux).observe(now, |mut turn| turn.protocol().with_conn(handle, op))
    }

    pub fn deliver(
        dst: &mut router::Router<Capture>,
        from: SocketAddr,
        flights: Vec<output::Flight>,
    ) -> Result<usize, Error> {
        Self::deliver_at(dst, from, flights, Instant::now())
    }

    pub fn deliver_at(
        dst: &mut router::Router<Capture>,
        from: SocketAddr,
        flights: Vec<output::Flight>,
        now: Instant,
    ) -> Result<usize, Error> {
        let mut runs = 0;
        for mut flight in flights {
            runs += usize::from(flight.is_segmented());
            for segment in flight.segments_mut() {
                Self::receive(dst, from, segment, now)?;
            }
        }
        Ok(runs)
    }

    pub fn release_at(
        mux: &router::Router<Capture>,
        handles: &[id::Handle],
        now: Instant,
    ) -> Result<Instant, errors::Access> {
        handles.iter().try_fold(now, |release, handle| {
            let conn = mux.conn(*handle).ok_or(errors::Access::InvalidHandle)?;
            Ok(conn.view().recovery().send_at(release))
        })
    }

    pub fn settle_pair(
        client: &mut router::Router<Capture>,
        server: &mut router::Router<Capture>,
        source: SocketAddr,
        target: SocketAddr,
        now: &mut Instant,
    ) -> Result<(), Error> {
        for step in 0..9 {
            *now = now
                .checked_add(Duration::from_millis(30))
                .ok_or(Error::Deadline(*now))?;
            let (src, dst, from) = if step % 2 == 0 {
                (&mut *client, &mut *server, source)
            } else {
                (&mut *server, &mut *client, target)
            };
            let flights = Self::output(src, *now).map_err(Error::Output)?;
            Self::deliver_at(dst, from, flights, *now)?;
        }
        Ok(())
    }

    pub fn route(
        client: &mut router::Router<Capture>,
        first: &mut router::Router<Capture>,
        second: &mut router::Router<Capture>,
        now: Instant,
    ) -> Result<(), Error> {
        for mut outgoing in Self::output(client, now).map_err(Error::Output)? {
            let addr = outgoing.addr();
            let server = if addr == SERVER {
                &mut *first
            } else if addr == SERVER_B {
                &mut *second
            } else {
                return Err(Error::Route(addr));
            };
            for packet in outgoing.segments_mut() {
                Self::receive(server, CLIENT, packet, now)?;
            }
        }
        Ok(())
    }
}

pub struct Pair {
    pub server: router::Router<Capture>,
    pub client: router::Router<Capture>,
    pub handle: id::Handle,
    pub now: Instant,
}

impl Pair {
    pub fn new(options: impl Fn() -> Options) -> Result<Self, Error> {
        let (signing, key) = peer::raw(0x47).map_err(Error::Identity)?;
        let server = Capture::server(
            Capture::default(),
            signing.server().map_err(Error::Tls)?,
            options(),
        )?;
        let limits = Plan::try_new(1, 64, 1 << 20).map_err(Error::Limits)?;
        let mut client = Builder::client(Capture::default())
            .limits(limits)
            .build()
            .map_err(Error::Storage)?;
        let now = Instant::now();
        let handle = Capture::connect(&mut client, SERVER, key, options(), CID.to_vec(), now)?;
        let mut pair = Self {
            server,
            client,
            handle,
            now,
        };
        for _ in 0..16 {
            pair.now = pair
                .now
                .checked_add(Duration::from_millis(1))
                .ok_or(Error::Deadline(pair.now))?;
            Capture::deliver_at(
                &mut pair.server,
                CLIENT,
                Capture::output(&mut pair.client, pair.now).map_err(Error::Output)?,
                pair.now,
            )?;
            Capture::deliver_at(
                &mut pair.client,
                SERVER,
                Capture::output(&mut pair.server, pair.now).map_err(Error::Output)?,
                pair.now,
            )?;
        }
        let client = pair.client.handler().events.established.len();
        let server = pair.server.handler().events.established.len();
        if client != 1 || server != 1 {
            return Err(Error::Established { client, server });
        }
        Capture::settle_pair(
            &mut pair.client,
            &mut pair.server,
            CLIENT,
            SERVER,
            &mut pair.now,
        )?;
        Ok(pair)
    }
}
