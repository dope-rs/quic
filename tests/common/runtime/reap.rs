use crate::common::peer;
use dope_quic::conn::life::accept::Authority;
use dope_quic::conn::life::options::Options;
use dope_quic::proto::epoch;
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::runtime::mux::handler::hook::data::{datagram, release};
use dope_quic::runtime::mux::handler::hook::life::close;
use dope_quic::runtime::mux::handler::hook::life::closing;
use dope_quic::runtime::mux::handler::hook::life::create;
use dope_quic::runtime::mux::handler::hook::life::ready;
use dope_quic::runtime::mux::handler::hook::set;
use dope_quic::runtime::mux::handler::hook::wire::cert;
use dope_quic::runtime::mux::handler::hook::wire::endpoint;
use dope_quic::runtime::mux::handler::hook::wire::ingress;
use dope_quic::runtime::mux::handler::hook::wire::packet;
use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::common::runtime::Error;
use crate::common::suite::peers::tls;
use dope_quic::conn::{Epoch, id, scope};
use dope_quic::errors::{self, SendFailure};
use dope_quic::proto::param;
use dope_quic::runtime::mux::{app, handler, output, router};
use dope_quic::stream::release::Event;
use id::Handle;
use o3::buffer::storage;

pub const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];
pub const SERVER: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 443));
pub const CLIENT: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 50000));

#[derive(Default)]
pub struct Events {
    pub certificates: usize,
    pub established: Vec<Handle>,
    pub datagrams: Vec<(Handle, Vec<u8>)>,
    pub closed: Vec<Handle>,
    pub released: Vec<(Handle, Event)>,
    pub release_after_close: bool,
}

#[derive(Clone, Default)]
pub struct Capture {
    pub events: Rc<RefCell<Events>>,
}

impl handler::Handler<0, Vec<u8>, storage::Shared> for Capture {
    type Connection = ();
    type Create = create::Unit;
    type Events = set::Set<
        set::On,
        set::On,
        set::Off,
        set::Off,
        set::On,
        set::Off,
        ingress::Off,
        packet::Off,
        endpoint::Off,
        closing::Off,
        close::On,
    >;
}

impl ready::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture {
    fn established(event: ready::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, _, handle, _) = event.into();
        this.events.borrow_mut().established.push(handle);
    }
}

impl datagram::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture {
    fn datagram(event: datagram::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, _, handle, data, _) = event.into();
        this.events.borrow_mut().datagrams.push((handle, data));
    }
}

impl close::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture {
    fn close(event: close::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (this, _, _, handle) = event.into_parts();
        this.events.borrow_mut().closed.push(handle);
    }
}

impl release::Sink<0, Vec<u8>, storage::Shared, id::Static> for Capture {
    fn release(event: release::Event<'_, Self, 0, id::Static>) -> app::Readiness {
        let (this, handle, release) = event.into_parts();
        let mut events = this.events.borrow_mut();
        events.release_after_close |= events.closed.contains(&handle);
        events.released.push((handle, release));
        app::Readiness::Preserve
    }
}

pub struct Pair {
    pub server: router::Router<Capture>,
    pub srv_log: Rc<RefCell<Events>>,
    pub client: router::Router<Capture>,
    pub cli_log: Rc<RefCell<Events>>,
    pub key: [u8; 32],
    pub params: param::Set,
}

#[derive(Debug)]
pub enum CreditError {
    Runtime(Error),
    Missing,
    Budget { received: u64, sent: u64 },
    Journal { before: usize, after: usize },
    Size(usize),
}

pub struct Credit {
    pub now: Instant,
    pub received: u64,
    pub sent: u64,
    pub blocked: usize,
    pub deadline: Option<Instant>,
    pub probes: [usize; 2],
}

impl Credit {
    pub fn exhaust(
        mux: &mut router::Router<Capture>,
        handle: Handle,
        raw: &mut [u8; 1200],
        now: Instant,
    ) -> Result<Self, CreditError> {
        let mut credit = Self {
            now,
            received: mux
                .conn(handle)
                .ok_or(CreditError::Missing)?
                .view()
                .path()
                .received(),
            sent: 0,
            blocked: 0,
            deadline: None,
            probes: [0; 2],
        };
        for _ in 0..16 {
            credit.drain(mux, handle)?;
            let due = mux
                .conn(handle)
                .ok_or(CreditError::Missing)?
                .view()
                .recovery()
                .next_timer();
            let Some(due) = due else { break };
            credit.advance(due)?;
        }
        credit.deadline = mux
            .conn(handle)
            .ok_or(CreditError::Missing)?
            .view()
            .recovery()
            .next_timer();
        credit.blocked = credit.left()?;
        let added = raw
            .len()
            .checked_sub(credit.blocked)
            .ok_or(CreditError::Size(credit.blocked))?
            .div_ceil(3)
            .max(9);
        credit.grant(mux, raw, added)?;
        let due = mux
            .conn(handle)
            .ok_or(CreditError::Missing)?
            .view()
            .recovery()
            .next_timer()
            .ok_or(CreditError::Runtime(Error::Deadline(credit.now)))?;
        credit.advance(due)?;
        credit.probes[0] = credit.drain(mux, handle)?;
        if credit.probes[0] == 1 {
            let left = credit.left()?;
            let added = raw
                .len()
                .checked_sub(left)
                .ok_or(CreditError::Size(left))?
                .div_ceil(3)
                .max(9);
            credit.grant(mux, raw, added)?;
            credit.probes[1] = credit.drain(mux, handle)?;
        }
        if credit.left()? == 0 {
            credit.grant(mux, raw, 9)?;
        }
        Ok(credit)
    }

    fn left(&self) -> Result<usize, CreditError> {
        self.received
            .checked_mul(3)
            .and_then(|credit| credit.checked_sub(self.sent))
            .and_then(|left| usize::try_from(left).ok())
            .ok_or(CreditError::Budget {
                received: self.received,
                sent: self.sent,
            })
    }

    fn advance(&mut self, due: Instant) -> Result<(), CreditError> {
        self.now = self
            .now
            .max(due)
            .checked_add(Duration::from_millis(1))
            .ok_or(CreditError::Runtime(Error::Deadline(due)))?;
        Ok(())
    }

    fn grant(
        &mut self,
        mux: &mut router::Router<Capture>,
        raw: &mut [u8; 1200],
        added: usize,
    ) -> Result<(), CreditError> {
        let packet = raw.get_mut(..added).ok_or(CreditError::Size(added))?;
        Capture::receive(mux, CLIENT, packet, self.now).map_err(CreditError::Runtime)?;
        self.received += added as u64;
        Ok(())
    }

    fn drain(
        &mut self,
        mux: &mut router::Router<Capture>,
        handle: Handle,
    ) -> Result<usize, CreditError> {
        let before = Self::long(mux, handle)?;
        for flight in Capture::output(mux, self.now)
            .map_err(Error::Output)
            .map_err(CreditError::Runtime)?
        {
            self.sent += flight.payload().len() as u64;
            Pin::new(&mut *mux).output().recycle(flight);
        }
        let after = Self::long(mux, handle)?;
        after
            .checked_sub(before)
            .ok_or(CreditError::Journal { before, after })
    }

    fn long(mux: &router::Router<Capture>, handle: Handle) -> Result<usize, CreditError> {
        let conn = mux.conn(handle).ok_or(CreditError::Missing)?;
        let view = conn.view().recovery();
        Ok(view.unacked(Epoch::Initial) + view.unacked(Epoch::Handshake))
    }
}

impl cert::Sink<0, id::Static> for Capture {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (this, _, _, _) = event.into_parts();
        this.events.borrow_mut().certificates += 1;
    }
}

impl Capture {
    pub fn receive(
        mux: &mut router::Router<Capture>,
        from: SocketAddr,
        packet: &mut [u8],
        now: Instant,
    ) -> Result<(), Error> {
        let result = Pin::new(&mut *mux).observe(now, |mut turn| {
            turn.protocol().recv(from, packet, epoch::WALL_CLOCK)
        });
        let count = mux.handler().events.borrow().certificates;
        if count != 0 {
            return Err(Error::Certificates(count));
        }
        result.map_err(Error::Receive)
    }

    pub fn connect(
        mux: &mut router::Router<Capture>,
        peer: SocketAddr,
        key: [u8; 32],
        options: Options,
        cid: Vec<u8>,
        now: Instant,
    ) -> Result<Handle, Error> {
        let auth = tls::client(key).map_err(Error::Tls)?;
        Pin::new(mux)
            .observe(now, |mut turn| {
                turn.protocol().connect(peer, &auth, options, cid)
            })
            .map_err(Error::Connect)
    }

    pub fn send(
        mux: &mut router::Router<Capture>,
        handle: Handle,
        payload: Vec<u8>,
        now: Instant,
    ) -> Result<(), SendFailure<Vec<u8>>> {
        Pin::new(mux).observe(now, |mut turn| {
            turn.protocol().try_datagram(handle, payload)
        })
    }

    pub fn with_conn<R>(
        mux: &mut router::Router<Capture>,
        handle: Handle,
        now: Instant,
        op: impl for<'scope> FnOnce(scope::Turn<'scope, 0, Vec<u8>, storage::Shared>) -> R,
    ) -> Result<R, errors::Access> {
        Pin::new(mux).observe(now, |mut turn| turn.protocol().with_conn(handle, op))
    }

    pub fn close(
        mux: &mut router::Router<Capture>,
        handle: Handle,
        now: Instant,
    ) -> Result<(), errors::Access> {
        Pin::new(mux).observe(now, |mut turn| turn.protocol().try_close(handle))
    }

    pub fn drive(
        mux: &mut router::Router<Capture>,
        now: Instant,
    ) -> Result<usize, errors::Transmit> {
        Pin::new(mux).observe(now, |mut turn| turn.output().drive())
    }

    pub fn output(
        mux: &mut router::Router<Capture>,
        now: Instant,
    ) -> Result<Vec<output::Flight>, errors::Transmit> {
        Self::drive(mux, now)?;
        Ok(Pin::new(mux).observe(now, |mut turn| turn.output().drain().collect()))
    }

    pub fn relay_once(
        src: &mut router::Router<Capture>,
        dst: &mut router::Router<Capture>,
        src_addr: SocketAddr,
        now: Instant,
    ) -> Result<usize, Error> {
        let pkts = Self::output(src, now).map_err(Error::Output)?;
        let n = pkts.iter().map(|flight| flight.packet_count().get()).sum();
        for mut out in pkts {
            for segment in out.segments_mut() {
                Self::receive(dst, src_addr, segment, now)?;
            }
            Pin::new(&mut *src).output().recycle(out);
        }
        Ok(n)
    }

    pub fn build_pair(idle_ms: u64) -> Result<Pair, Error> {
        let (signing, key) = peer::raw(0x39).map_err(Error::Identity)?;
        let config = signing.server().map_err(Error::Tls)?;

        let tp = param::Set::builder()
            .idle_ms(idle_ms)
            .datagram(Some(65535))
            .initial_data(1024)
            .local_bidi(1024)
            .remote_bidi(1024)
            .bidi_count(1)
            .try_build()
            .map_err(Error::Parameters)?;

        let server_h = Capture::default();
        let srv_log = server_h.events.clone();
        let auth = Authority::new(
            config,
            Options::try_from(tp.clone()).map_err(Error::Options)?,
        )
        .map_err(Error::Connect)?;

        let server = Builder::server(server_h, auth)
            .build()
            .map_err(Error::Storage)?;

        let client_h = Capture::default();
        let cli_log = client_h.events.clone();
        let client = Builder::client(client_h).build().map_err(Error::Storage)?;

        Ok(Pair {
            server,
            srv_log,
            client,
            cli_log,
            key,
            params: tp,
        })
    }

    pub fn handshake(
        server: &mut router::Router<Capture>,
        client: &mut router::Router<Capture>,
        key: [u8; 32],
        tp: param::Set,
        srv_addr: SocketAddr,
        cli_addr: SocketAddr,
        now: Instant,
    ) -> Result<Handle, Error> {
        let handle = Self::connect(
            client,
            srv_addr,
            key,
            Options::try_from(tp).map_err(Error::Options)?,
            CID.to_vec(),
            now,
        )?;

        Self::relay_once(client, server, cli_addr, now)?;
        Self::relay_once(server, client, srv_addr, now)?;
        Self::relay_once(client, server, cli_addr, now)?;
        Self::drive(server, now).map_err(Error::Output)?;
        Self::drive(client, now).map_err(Error::Output)?;
        Ok(handle)
    }
}
