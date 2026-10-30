use crate::common::suite::peers::tls;
use crate::common::{peer::Setup, runtime::Error};
use conn::life::accept::Authority;
use dope_quic::conn::life::options::Options;
use dope_quic::conn::stream::resident::Key;
use dope_quic::errors;
use dope_quic::proto::epoch;
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::runtime::mux::builder::Plan;
use dope_quic::runtime::mux::handler::hook::life::closing;
use dope_quic::runtime::mux::handler::hook::wire::endpoint;
use dope_quic::runtime::mux::handler::hook::wire::ingress;
use dope_quic::runtime::mux::handler::hook::wire::packet;
use dope_test::harness::observe::VecCellExt as _;
use mux::output::Flight;
use std::cell::{Cell, RefCell};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::rc::Rc;
use std::time::Instant;

use dope_quic::conn::stream::Event;
use dope_quic::conn::{self, id};
use dope_quic::runtime::mux::handler::hook::data::{datagram, stream};
use dope_quic::runtime::mux::handler::hook::life::{close, create, early, ready};
use dope_quic::runtime::mux::handler::hook::{set, wire::cert};
use dope_quic::runtime::mux::{self, handler, router};
use o3::buffer::storage;

pub const CID: [u8; 8] = [0x42; 8];
pub const SERVER: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 443));
pub const CLIENT: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 50_000));

#[derive(Default)]
pub struct Events {
    pub owners: Vec<(id::Handle, id::Handle)>,
    pub certificates: usize,
    pub established: Vec<id::Handle>,
    pub datagrams: Vec<(id::Handle, Vec<u8>)>,
    pub streams: Vec<(id::Handle, Event)>,
    pub closed: Vec<id::Handle>,
}

#[derive(Clone, Default)]
pub struct Capture {
    pub events: Rc<RefCell<Events>>,
}

#[derive(Clone)]
pub struct Count {
    pub created: Rc<Cell<usize>>,
    pub certificates: usize,
}

impl handler::Handler<0, Vec<u8>, storage::Shared> for Count {
    type Connection = ();
    type Create = create::Call;
    type Events = set::Set;
}

impl create::Sink<0, Vec<u8>, storage::Shared, id::Static> for Count {
    fn create(event: create::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, _, _) = event.into_parts();
        this.created.set(this.created.get() + 1);
    }
}

impl handler::Handler<0, Vec<u8>, storage::Shared> for Capture {
    type Connection = id::Handle;
    type Create = create::Call;
    type Events = set::Set<
        set::On,
        set::On,
        set::On,
        set::Off,
        set::Off,
        set::Off,
        ingress::Off,
        packet::Off,
        endpoint::Off,
        closing::Off,
        close::On,
    >;
}

impl create::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture {
    fn create(
        event: create::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>,
    ) -> id::Handle {
        let (_, _, handle) = event.into_parts();
        handle
    }
}

impl ready::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture {
    fn established(event: ready::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, mut slot, handle, _) = event.into();
        let mut events = this.events.borrow_mut();
        events.owners.push((*slot.application(), handle));
        events.established.push(handle);
    }
}

impl datagram::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture {
    fn datagram(event: datagram::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, mut slot, handle, data, _) = event.into();
        let mut events = this.events.borrow_mut();
        events.owners.push((*slot.application(), handle));
        events.datagrams.push((handle, data));
    }
}

impl stream::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture {
    fn stream(
        event: stream::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>,
    ) -> mux::Disposition {
        let (this, mut slot, handle, event, _) = event.into();
        let mut events = this.events.borrow_mut();
        events.owners.push((*slot.application(), handle));
        events.streams.push((handle, event.event()));
        mux::Disposition::Accept
    }
}

impl close::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture {
    fn close(event: close::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, _, conn, handle) = event.into_parts();
        let mut events = this.events.borrow_mut();
        events.owners.push((conn, handle));
        events.closed.push(handle);
    }
}

impl cert::Sink<0, id::Static> for Count {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (mut this, _, _, _) = event.into_parts();
        this.certificates += 1;
    }
}

impl cert::Sink<0, id::Static> for Capture {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (this, _, _, _) = event.into_parts();
        this.events.borrow_mut().certificates += 1;
    }
}

impl Capture {
    pub fn server<H: handler::Handler<0, Vec<u8>, storage::Shared>>(
        handler: H,
        config: rustls::ServerConfig,
        options: Options,
        limits: Plan,
    ) -> Result<router::Router<H>, Setup> {
        let auth = Authority::new(config, options).map_err(Setup::Authority)?;
        Builder::server(handler, auth)
            .limits(limits)
            .build()
            .map_err(Setup::ServerBuild)
    }
    pub fn connect<H: handler::Handler<0, Vec<u8>, storage::Shared> + Unpin>(
        mux: &mut router::Router<H>,
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
    pub fn recv<H>(
        mux: &mut router::Router<H>,
        from: SocketAddr,
        packet: &mut [u8],
        now: Instant,
    ) -> Result<(), errors::Receive>
    where
        H: handler::Handler<0, Vec<u8>, storage::Shared> + Unpin + cert::Sink<0, id::Static>,
        H::Events: set::Dispatch<H, 0, Vec<u8>, storage::Shared, id::Static, Release = set::Off>,
    {
        Pin::new(mux).observe(now, |mut turn| {
            turn.protocol().recv(from, packet, epoch::WALL_CLOCK)
        })
    }
    pub fn send<H: handler::Handler<0, Vec<u8>, storage::Shared> + Unpin>(
        mux: &mut router::Router<H>,
        handle: id::Handle,
        payload: Vec<u8>,
        now: Instant,
    ) -> Result<(), errors::SendFailure<Vec<u8>>> {
        Pin::new(mux).observe(now, |mut turn| {
            turn.protocol().try_datagram(handle, payload)
        })
    }
    pub fn drive<H: handler::Handler<0, Vec<u8>, storage::Shared> + Unpin>(
        mux: &mut router::Router<H>,
        now: Instant,
    ) -> Result<usize, errors::Transmit> {
        Pin::new(mux).observe(now, |mut turn| turn.output().drive())
    }
    pub fn output<H: handler::Handler<0, Vec<u8>, storage::Shared> + Unpin>(
        mux: &mut router::Router<H>,
        now: Instant,
    ) -> Result<Vec<Flight>, errors::Transmit> {
        Self::drive(mux, now)?;
        Ok(Pin::new(mux).observe(now, |mut turn| turn.output().drain().collect()))
    }
    pub fn relay<S: handler::Handler<0, Vec<u8>, storage::Shared> + Unpin, D>(
        source: &mut router::Router<S>,
        dst: &mut router::Router<D>,
        from: SocketAddr,
        now: Instant,
    ) -> Result<usize, Error>
    where
        D: handler::Handler<0, Vec<u8>, storage::Shared> + Unpin + cert::Sink<0, id::Static>,
        D::Events: set::Dispatch<D, 0, Vec<u8>, storage::Shared, id::Static, Release = set::Off>,
    {
        let packets = Self::output(source, now).map_err(Error::Output)?;
        let count = packets
            .iter()
            .map(|packet| packet.packet_count().get())
            .sum();
        for mut packet in packets {
            for segment in packet.segments_mut() {
                Self::recv(dst, from, segment, now).map_err(Error::Receive)?;
            }
        }
        Self::drive(dst, now).map_err(Error::Output)?;
        Ok(count)
    }
}

#[derive(Default)]
pub struct Deferrals {
    pub established: Cell<Vec<id::Handle>>,
    pub certificates: Cell<bool>,
    pub attempts: Cell<Vec<(id::Handle, Event, Option<Key>)>>,
    pub reset_deferred: Cell<bool>,
}

#[derive(Clone, Default)]
pub struct Defer {
    pub state: Rc<Deferrals>,
}

impl handler::Handler<0, Vec<u8>, storage::Shared> for Defer {
    type Connection = ();
    type Create = create::Unit;
    type Events = set::Set<set::On, set::Off, set::On>;
}

impl ready::Sink<0, Vec<u8>, storage::Shared, id::Static> for Defer {
    fn established(event: ready::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, _, handle, _) = event.into();
        this.state.established.push(handle);
    }
}

impl stream::Sink<0, Vec<u8>, storage::Shared, id::Static> for Defer {
    fn early(
        event: stream::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>,
    ) -> mux::Disposition {
        let (this, _, handle, event, _) = event.into();
        this.state
            .attempts
            .push((handle, event.event(), event.key()));
        mux::Disposition::Defer
    }

    fn stream(
        event: stream::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>,
    ) -> mux::Disposition {
        let (this, _, handle, event, _) = event.into();
        let key = event.key();
        let event = event.event();
        this.state.attempts.push((handle, event, key));
        if matches!(event, Event::Reset { .. }) && !this.state.reset_deferred.get() {
            this.state.reset_deferred.set(true);
            mux::Disposition::Defer
        } else {
            mux::Disposition::Accept
        }
    }
}

impl cert::Sink<0, id::Static> for Defer {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (this, _, _, _) = event.into_parts();
        this.state.certificates.set(true);
    }
}

#[derive(Default)]
pub struct Reject {
    pub ready: Vec<id::Handle>,
    pub rejected: Vec<(id::Handle, usize)>,
    pub certificates: usize,
}

impl handler::Handler<0, Vec<u8>, storage::Shared> for Reject {
    type Connection = ();
    type Create = create::Unit;
    type Events = set::Set<set::On, set::Off, set::Off, set::On>;
}

impl ready::Sink<0, Vec<u8>, storage::Shared, id::Static> for Reject {
    fn established(event: ready::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (mut this, _, handle, _) = event.into();
        this.ready.push(handle);
    }
}

impl early::Sink<0, Vec<u8>, storage::Shared, id::Static> for Reject {
    fn rejected(event: early::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (mut this, _, handle) = event.into_parts();
        let ready = this.ready.len();
        this.rejected.push((handle, ready));
    }
}

impl cert::Sink<0, id::Static> for Reject {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (mut this, _, _, _) = event.into_parts();
        this.certificates += 1;
    }
}
