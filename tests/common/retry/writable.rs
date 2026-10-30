use crate::common::peer;
use crate::common::retry::{Finish, traces::Immediate};
use crate::common::suite::mux::dispatch::{self, Capture};
use dope::core::driver::schedule::clock;
use dope::runtime::control;
use dope_quic::client::{self, auth, protocol};
use dope_quic::conn::{id, life::options::Options, stream::Event};
use dope_quic::errors::{self, SendFailure};
use dope_quic::proto::datagram::{self, Arena, Packet};
use dope_quic::runtime::mux::{
    builder,
    handler::hook::{wire::packet, writable},
    output::Flight,
    router,
};
use dope_quic::wire::stream::Id;
use std::{
    cell::{Ref, RefCell},
    io, mem,
    net::SocketAddr,
    net::UdpSocket,
    num::NonZero,
    pin::Pin,
    rc::Rc,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub enum Callback<'a> {
    Failed(&'a errors::Connect),
    Datagram(Vec<u8>),
    Stream(Id, Option<Vec<u8>>, bool),
    Reset(client::AttemptId, Id, errors::Code),
    Stopped(client::AttemptId, Id, errors::Code),
    Close,
    Packet(packet::Failure<'a>),
    Certificate(&'a rustls::Error),
}

pub struct Connected<F> {
    active: usize,
    observe: F,
}

impl<F: for<'a> FnMut(Result<client::SlotId, Callback<'a>>) + Unpin> Connected<F> {
    pub fn new(observe: F) -> Self {
        Self { active: 0, observe }
    }

    pub fn len(&self) -> usize {
        self.active
    }

    pub fn is_empty(&self) -> bool {
        self.active == 0
    }
}

impl<'d, F: for<'a> FnMut(Result<client::SlotId, Callback<'a>>) + Unpin> protocol::Protocol<'d>
    for Connected<F>
{
    type Receive = Vec<u8>;
    type Writable = writable::On;

    fn connect<'scope>(self: Pin<&'scope mut Self>, slot: client::SlotScope<'scope>) {
        let this = self.get_mut();
        this.active += 1;
        (this.observe)(Ok(slot.id()));
    }

    fn failed(self: Pin<&mut Self>, _: client::AttemptScope<'_, 'd>, cause: &errors::Connect) {
        (self.get_mut().observe)(Err(Callback::Failed(cause)));
    }

    fn datagram<'scope>(self: Pin<&'scope mut Self>, _: client::SlotScope<'scope>, data: Vec<u8>) {
        (self.get_mut().observe)(Err(Callback::Datagram(data)));
    }

    fn stream<'scope>(
        self: Pin<&'scope mut Self>,
        _: client::SlotScope<'scope>,
        id: Id,
        data: Option<Vec<u8>>,
        end: bool,
    ) {
        (self.get_mut().observe)(Err(Callback::Stream(id, data, end)));
    }

    fn close<'scope>(self: Pin<&'scope mut Self>, _: client::SlotScope<'scope>) {
        let this = self.get_mut();
        match this.active.checked_sub(1) {
            Some(active) => this.active = active,
            None => (this.observe)(Err(Callback::Close)),
        }
    }

    fn stream_event<'scope>(
        self: Pin<&'scope mut Self>,
        slot: client::SlotScope<'scope>,
        event: Event,
    ) {
        let event = match event {
            Event::Reset {
                id,
                error_code: code,
            } => Callback::Reset(slot.attempt_id(), id, code),
            Event::Stopped {
                id,
                error_code: code,
            } => Callback::Stopped(slot.attempt_id(), id, code),
            Event::Writable | Event::Readable { .. } => return,
        };
        (self.get_mut().observe)(Err(event));
    }

    fn packet(self: Pin<&mut Self>, _: SocketAddr, cause: packet::Failure<'_>, _: usize) {
        (self.get_mut().observe)(Err(Callback::Packet(cause)));
    }

    fn certificate<const DOMAIN: u8>(
        self: Pin<&mut Self>,
        _: id::Handle<id::Driver<'d>, DOMAIN>,
        _: SocketAddr,
        cause: &rustls::Error,
    ) {
        (self.get_mut().observe)(Err(Callback::Certificate(cause)));
    }
}

#[derive(Debug)]
pub enum PeerError {
    Io(io::Error),
    Plan(builder::Error),
    Setup(peer::Setup),
    Receive(errors::Receive),
    Transmit(errors::Transmit),
    ShortSend { expected: usize, actual: usize },
}

pub struct Peer {
    pub router: router::Router<Capture>,
    socket: UdpSocket,
}

impl Peer {
    pub fn new(config: rustls::ServerConfig, options: Options) -> Result<Self, PeerError> {
        Self::with_limit(config, options, NonZero::<usize>::MIN)
    }

    pub fn with_limit(
        config: rustls::ServerConfig,
        options: Options,
        limit: NonZero<usize>,
    ) -> Result<Self, PeerError> {
        let socket = UdpSocket::bind("127.0.0.1:0").map_err(PeerError::Io)?;
        socket.set_nonblocking(true).map_err(PeerError::Io)?;
        Ok(Self {
            router: Capture::server(
                Capture::default(),
                config,
                options,
                builder::Plan::try_new(limit.get(), 8, 16 * 1024).map_err(PeerError::Plan)?,
            )
            .map_err(PeerError::Setup)?,
            socket,
        })
    }

    pub fn addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn observations(&self) -> Rc<RefCell<dispatch::Events>> {
        Rc::clone(&self.router.handler().events)
    }

    pub fn receive(&mut self, now: Instant) -> Result<(), PeerError> {
        let mut packet = [0; 2048];
        loop {
            match self.socket.recv_from(&mut packet) {
                Ok((len, from)) => Capture::recv(&mut self.router, from, &mut packet[..len], now)
                    .map_err(PeerError::Receive)?,
                Err(cause) if cause.kind() == io::ErrorKind::WouldBlock => break,
                Err(cause) => return Err(PeerError::Io(cause)),
            }
        }
        Ok(())
    }

    pub fn send(&mut self, mut flight: Flight) -> Result<(), PeerError> {
        self.transmit(&mut flight)?;
        Pin::new(&mut self.router).output().recycle(flight);
        Ok(())
    }

    pub fn transmit(&self, flight: &mut Flight) -> Result<(), PeerError> {
        let addr = flight.addr();
        for packet in flight.segments_mut() {
            let actual = self.socket.send_to(packet, addr).map_err(PeerError::Io)?;
            if actual != packet.len() {
                return Err(PeerError::ShortSend {
                    expected: packet.len(),
                    actual,
                });
            }
        }
        Ok(())
    }

    pub fn poll(&mut self, now: Instant) -> Result<(), PeerError> {
        self.receive(now)?;
        for flight in Capture::output(&mut self.router, now).map_err(PeerError::Transmit)? {
            self.send(flight)?;
        }
        Ok(())
    }

    pub fn datagrams(&self) -> Ref<'_, Vec<(id::Handle, Vec<u8>)>> {
        Ref::map(self.router.handler().events.borrow(), |events| {
            &events.datagrams
        })
    }
}

pub enum Error<'pool> {
    Timeout,
    Peer(PeerError),
    Deadline(clock::Range<Duration>),
    Acquire(datagram::Error),
    Send(SendFailure<Packet<'pool>>),
    Accepted(u8),
}

#[derive(Default)]
pub struct Observed<'pool> {
    pub error: Option<Error<'pool>>,
    pub owners: Vec<(*const u8, *const u8)>,
    pub payloads: Vec<Vec<u8>>,
    pub available: Vec<usize>,
    pub idle: Vec<writable::Receipt>,
    pub ready: Vec<writable::Receipt>,
}

pub enum Stage<'pool> {
    Connect,
    Accepted(Packet<'pool>),
    Retained(Packet<'pool>),
    Retry(Packet<'pool>),
    FinalAccepted(Packet<'pool>),
    Shutdown(Packet<'pool>),
}

#[pin_project::pin_project]
#[derive(dope::Application)]
#[dispatcher(driver = 'd)]
#[coordinate]
pub struct App<'d, 'pool, F: for<'a> FnMut(Result<client::SlotId, Callback<'a>>) + Unpin> {
    #[pin]
    #[manifold(control)]
    pub client: client::Dialer<'pool, 'd, 1, Connected<F>, Immediate, auth::Owned>,
    #[dispatcher(state)]
    pub peer: Peer,
    #[dispatcher(state)]
    pub arena: &'pool Arena,
    #[dispatcher(state)]
    pub stage: Stage<'pool>,
    #[dispatcher(state)]
    pub finish: Finish,
    #[dispatcher(state)]
    pub observed: Rc<RefCell<Observed<'pool>>>,
    #[dispatcher(state)]
    pub timeout: clock::Deadline<'d>,
    #[dispatcher(schedule)]
    pub next: clock::Deadline<'d>,
}

impl<'d, 'pool, F: for<'a> FnMut(Result<client::SlotId, Callback<'a>>) + Unpin> App<'d, 'pool, F> {
    fn coordinate(mut this: app_coord::Fields<'_, 'd, 'pool, F>) -> control::Flow {
        if this.finish.stop.is_none() {
            return control::Flow::Idle;
        }
        let result = (|| {
            if this.timeout.is_due(this.step.now()) {
                return Err(Error::Timeout);
            }
            let slot = client::SlotId::from_index(0);
            let stage = mem::replace(this.stage, Stage::Connect);
            let retained = matches!(&stage, Stage::Retained(_));
            match stage {
                Stage::Connect => {
                    this.peer
                        .poll(this.step.now().into_raw())
                        .map_err(Error::Peer)?;
                    *this.next = this
                        .step
                        .now()
                        .try_add(Duration::from_millis(1))
                        .map_err(Error::Deadline)?;
                    if this.client.protocol().is_empty() {
                        return Ok(());
                    }
                    this.client.take();
                    let mut packet = this.arena.try_acquire(32).map_err(Error::Acquire)?;
                    packet.payload_mut().fill(1);
                    match this.client.at(this.step.clock()).try_pooled(slot, packet) {
                        Ok(()) => {}
                        Err(SendFailure::Full(packet)) => {
                            drop(packet);
                            return Ok(());
                        }
                        Err(cause) => return Err(Error::Send(cause)),
                    }
                    let mut packet = this.arena.try_acquire(32).map_err(Error::Acquire)?;
                    packet.payload_mut().fill(2);
                    let pointer = packet.payload().as_ptr();
                    let packet = match this.client.at(this.step.clock()).try_pooled(slot, packet) {
                        Err(SendFailure::Full(packet)) => packet,
                        Ok(()) => return Err(Error::Accepted(2)),
                        Err(cause) => return Err(Error::Send(cause)),
                    };
                    this.observed
                        .borrow_mut()
                        .owners
                        .push((packet.payload().as_ptr(), pointer));
                    this.observed
                        .borrow_mut()
                        .payloads
                        .push(packet.payload().to_vec());
                    this.observed
                        .borrow_mut()
                        .available
                        .push(this.arena.available());
                    this.observed.borrow_mut().idle.push(this.client.take());
                    *this.stage = Stage::Accepted(packet);
                    *this.next = *this.timeout;
                }
                Stage::Accepted(packet) => {
                    *this.stage = if this.arena.available() == 1 {
                        Stage::Retained(packet)
                    } else {
                        Stage::Accepted(packet)
                    };
                }
                Stage::Retained(packet) | Stage::Retry(packet) => {
                    if retained {
                        this.observed.borrow_mut().ready.push(this.client.take());
                        this.observed.borrow_mut().idle.push(this.client.take());
                    } else if this.client.take() == writable::Receipt::Idle {
                        *this.stage = Stage::Retry(packet);
                        return Ok(());
                    }
                    this.observed
                        .borrow_mut()
                        .payloads
                        .push(packet.payload().to_vec());
                    let pointer = packet.payload().as_ptr();
                    match this.client.at(this.step.clock()).try_pooled(slot, packet) {
                        Ok(()) => {}
                        Err(SendFailure::Full(packet)) => {
                            this.observed
                                .borrow_mut()
                                .owners
                                .push((packet.payload().as_ptr(), pointer));
                            *this.stage = Stage::Retry(packet);
                            return Ok(());
                        }
                        Err(cause) => return Err(Error::Send(cause)),
                    }
                    let mut packet = this.arena.try_acquire(32).map_err(Error::Acquire)?;
                    packet.payload_mut().fill(3);
                    let pointer = packet.payload().as_ptr();
                    let packet = match this.client.at(this.step.clock()).try_pooled(slot, packet) {
                        Err(SendFailure::Full(packet)) => packet,
                        Ok(()) => return Err(Error::Accepted(3)),
                        Err(cause) => return Err(Error::Send(cause)),
                    };
                    this.observed
                        .borrow_mut()
                        .owners
                        .push((packet.payload().as_ptr(), pointer));
                    this.observed.borrow_mut().idle.push(this.client.take());
                    *this.stage = Stage::FinalAccepted(packet);
                }
                Stage::FinalAccepted(packet) => {
                    *this.stage = if this.arena.available() == 1 {
                        Stage::Shutdown(packet)
                    } else {
                        Stage::FinalAccepted(packet)
                    };
                }
                Stage::Shutdown(packet) => {
                    *this.stage = Stage::Shutdown(packet);
                    this.finish.fire();
                }
            }
            Ok(())
        })();
        if let Err(cause) = result {
            this.observed.borrow_mut().error = Some(cause);
            this.finish.fire();
        }
        control::Flow::Idle
    }
}
