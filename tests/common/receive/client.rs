use crate::common::retry::{
    Finish,
    traces::Immediate,
    writable::{self, Callback, PeerError},
};
use crate::common::suite::mux::dispatch::Capture;
use dope::core::driver::schedule::clock;
use dope::runtime::control;
use dope_quic::client::{self, auth, protocol};
use dope_quic::conn::{Epoch, id, life::options::Options, stream};
use dope_quic::errors;
use dope_quic::runtime::mux::{
    handler::hook::{wire::packet, writable::Off},
    output::Flight,
};
use dope_quic::stream::RecvBuffer;
use dope_quic::wire::stream::Id;
use std::{
    cell::RefCell,
    net::SocketAddr,
    num::NonZero,
    pin::Pin,
    rc::Rc,
    time::{Duration, Instant},
};

pub const PREFIX: &[u8; 7] = b"prefix!";
pub const SUFFIX: &[u8; 7] = b"suffix!";
pub const RESET: [errors::Code; 2] = [errors::Code::from_u8(0x91), errors::Code::from_u8(0xa1)];
pub const STOPPED: [errors::Code; 2] = [errors::Code::from_u8(0x92), errors::Code::from_u8(0xa2)];

#[derive(Debug)]
pub enum Error {
    Peer(PeerError),
    Access(errors::Access),
    Stream(stream::Error),
    MissingConnection,
    Flights(usize),
    Packets(usize),
    Unacked(usize),
    MissingPrefix,
    StaleAttempt(Result<(), errors::Access>),
    Deadline(clock::Range<Duration>),
    Timeout,
}

#[derive(Default)]
pub struct State {
    pub bytes: Vec<Vec<u8>>,
    pub connects: Vec<Option<client::AttemptId>>,
    pub owners: Vec<(Option<client::AttemptId>, client::AttemptId)>,
    pub terminals: Vec<(client::AttemptId, stream::Event)>,
    pub ends: Vec<(client::AttemptId, Id, bool, usize)>,
    pub stale_checked: bool,
    pub error: Option<Error>,
}

pub struct Received<F> {
    pub state: Rc<RefCell<State>>,
    pub active: Option<client::AttemptId>,
    pub observe: F,
}

impl<'d, F: for<'a> FnMut(Result<client::SlotId, Callback<'a>>) + Unpin> protocol::Protocol<'d>
    for Received<F>
{
    type Writable = Off;
    type Receive = RecvBuffer<'d>;

    fn connect<'scope>(self: Pin<&'scope mut Self>, slot: client::SlotScope<'scope>) {
        let this = self.get_mut();
        this.state
            .borrow_mut()
            .connects
            .push(this.active.replace(slot.attempt_id()));
        (this.observe)(Ok(slot.id()));
    }

    fn failed(self: Pin<&mut Self>, _: client::AttemptScope<'_, 'd>, cause: &errors::Connect) {
        (self.get_mut().observe)(Err(Callback::Failed(cause)));
    }

    fn datagram<'scope>(
        self: Pin<&'scope mut Self>,
        _: client::SlotScope<'scope>,
        data: Self::Receive,
    ) {
        (self.get_mut().observe)(Err(Callback::Datagram(data.as_ref().to_vec())));
    }

    fn stream<'scope>(
        self: Pin<&'scope mut Self>,
        slot: client::SlotScope<'scope>,
        id: Id,
        data: Option<Self::Receive>,
        end: bool,
    ) {
        let mut state = self.state.borrow_mut();
        state.owners.push((self.active, slot.attempt_id()));
        let present = data.is_some();
        if let Some(data) = data {
            state.bytes.push(data.as_ref().to_vec());
        }
        if end {
            let count = state.bytes.len();
            state.ends.push((slot.attempt_id(), id, present, count));
        }
    }

    fn close<'scope>(self: Pin<&'scope mut Self>, slot: client::SlotScope<'scope>) {
        let this = self.get_mut();
        this.state
            .borrow_mut()
            .owners
            .push((this.active.take(), slot.attempt_id()));
    }

    fn stream_event<'scope>(
        self: Pin<&'scope mut Self>,
        slot: client::SlotScope<'scope>,
        event: stream::Event,
    ) {
        let mut state = self.state.borrow_mut();
        state.owners.push((self.active, slot.attempt_id()));
        state.terminals.push((slot.attempt_id(), event));
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

#[derive(Clone, Copy)]
enum Stage {
    Handshake,
    Prefix(Id),
    Acknowledgment,
    Delivered,
    Terminated(id::Handle),
    Replacement(id::Handle),
}

pub struct Peer {
    pub inner: writable::Peer,
    stage: Stage,
    held: Option<Flight>,
    stale: Vec<Flight>,
}

impl Peer {
    pub fn new(config: rustls::ServerConfig, options: Options) -> Result<Self, PeerError> {
        Ok(Self {
            inner: writable::Peer::with_limit(
                config,
                options,
                NonZero::<usize>::MIN.saturating_add(1),
            )?,
            stage: Stage::Handshake,
            held: None,
            stale: Vec::new(),
        })
    }

    fn unacked(&self, handle: id::Handle) -> Result<usize, Error> {
        Ok(self
            .inner
            .router
            .conn(handle)
            .ok_or(Error::MissingConnection)?
            .view()
            .recovery()
            .unacked(Epoch::Application))
    }

    fn poll(&mut self, now: Instant) -> Result<(), Error> {
        self.inner.receive(now).map_err(Error::Peer)?;
        let handle = self
            .inner
            .router
            .handler()
            .events
            .borrow()
            .established
            .last()
            .copied();
        match self.stage {
            Stage::Handshake => {
                for flight in Capture::output(&mut self.inner.router, now)
                    .map_err(PeerError::Transmit)
                    .map_err(Error::Peer)?
                {
                    self.inner.send(flight).map_err(Error::Peer)?;
                }
                if let Some(handle) = handle
                    && self.unacked(handle)? == 0
                {
                    let id = Pin::new(&mut self.inner.router)
                        .observe(now, |mut turn| {
                            turn.protocol().with_conn(handle, |mut conn| {
                                let mut streams = conn.streams();
                                let mut send = streams.send();
                                let stream = send.open_bidi().map_err(Error::Stream)?;
                                send.send(stream.send(), PREFIX).map_err(Error::Stream)?;
                                Ok(stream.id())
                            })
                        })
                        .map_err(Error::Access)??;
                    self.stage = Stage::Prefix(id);
                }
            }
            Stage::Prefix(id) => {
                let mut flights = Capture::output(&mut self.inner.router, now)
                    .map_err(PeerError::Transmit)
                    .map_err(Error::Peer)?;
                if flights.is_empty() {
                    return Ok(());
                }
                if flights.len() != 1 {
                    return Err(Error::Flights(flights.len()));
                }
                let flight = flights.pop().ok_or(Error::MissingPrefix)?;
                if flight.packet_count().get() != 1 {
                    return Err(Error::Packets(flight.packet_count().get()));
                }
                self.held = Some(flight);
                let handle = handle.ok_or(Error::MissingConnection)?;
                Pin::new(&mut self.inner.router)
                    .observe(now, |mut turn| {
                        turn.protocol().with_conn(handle, |mut conn| {
                            let mut streams = conn.streams();
                            let stream = streams.view().resolve_send(id)?;
                            let mut send = streams.send();
                            send.send(stream, SUFFIX)?;
                            send.finish(stream)
                        })
                    })
                    .map_err(Error::Access)?
                    .map_err(Error::Stream)?;
                let flights = Capture::output(&mut self.inner.router, now)
                    .map_err(PeerError::Transmit)
                    .map_err(Error::Peer)?;
                if flights.len() != 1 {
                    return Err(Error::Flights(flights.len()));
                }
                for flight in flights {
                    if flight.packet_count().get() != 1 {
                        return Err(Error::Packets(flight.packet_count().get()));
                    }
                    self.inner.send(flight).map_err(Error::Peer)?;
                }
                let unacked = self.unacked(handle)?;
                if unacked != 2 {
                    return Err(Error::Unacked(unacked));
                }
                self.stage = Stage::Acknowledgment;
            }
            Stage::Acknowledgment => {
                if self.unacked(handle.ok_or(Error::MissingConnection)?)? < 2 {
                    let flight = self.held.take().ok_or(Error::MissingPrefix)?;
                    self.inner.send(flight).map_err(Error::Peer)?;
                    self.stage = Stage::Delivered;
                }
            }
            Stage::Delivered | Stage::Terminated(_) => {
                self.inner.poll(now).map_err(Error::Peer)?;
            }
            Stage::Replacement(previous) => {
                self.inner.poll(now).map_err(Error::Peer)?;
                if handle.is_some_and(|handle| handle != previous) {
                    self.stage = Stage::Handshake;
                }
            }
        }
        Ok(())
    }

    fn terminate(&mut self, now: Instant, index: usize) -> Result<(), Error> {
        for flight in self.stale.drain(..) {
            self.inner.send(flight).map_err(Error::Peer)?;
        }
        let handle = self
            .inner
            .router
            .handler()
            .events
            .borrow()
            .established
            .last()
            .copied()
            .ok_or(Error::MissingConnection)?;
        Pin::new(&mut self.inner.router)
            .observe(now, |mut turn| {
                turn.protocol().with_conn(handle, |mut conn| {
                    let mut streams = conn.streams();
                    let mut send = streams.send();
                    let empty = send.open_bidi()?;
                    send.finish(empty.send())?;
                    let terminal = send.open_bidi()?;
                    send.reset(terminal.send(), RESET[index])?;
                    let receive = streams.view().resolve_recv(terminal.id())?;
                    streams.receive().stop(receive, STOPPED[index])
                })
            })
            .map_err(Error::Access)?
            .map_err(Error::Stream)?;
        let flights = Capture::output(&mut self.inner.router, now)
            .map_err(PeerError::Transmit)
            .map_err(Error::Peer)?;
        for mut flight in flights {
            self.inner.transmit(&mut flight).map_err(Error::Peer)?;
            self.stale.push(flight);
        }
        self.stage = Stage::Terminated(handle);
        Ok(())
    }
}

#[pin_project::pin_project]
#[derive(dope::Application)]
#[dispatcher(driver = 'd)]
#[coordinate]
pub struct App<'d, F: for<'a> FnMut(Result<client::SlotId, Callback<'a>>) + Unpin> {
    #[pin]
    #[manifold(control)]
    pub client: client::Dialer<'d, 'd, 1, Received<F>, Immediate, auth::Owned>,
    #[dispatcher(state)]
    pub peer: Peer,
    #[dispatcher(state)]
    pub received: Rc<RefCell<State>>,
    #[dispatcher(state)]
    pub finish: Finish,
    #[dispatcher(state)]
    pub timeout: clock::Deadline<'d>,
    #[dispatcher(schedule)]
    pub next: clock::Deadline<'d>,
}

impl<'d, F: for<'a> FnMut(Result<client::SlotId, Callback<'a>>) + Unpin> App<'d, F> {
    fn coordinate(mut this: app_coord::Fields<'_, 'd, F>) -> control::Flow {
        if this.finish.stop.is_none() {
            return control::Flow::Idle;
        }
        let result = (|| {
            this.peer.poll(this.step.now().into_raw())?;
            let (bytes, events, ends) = {
                let received = this.received.borrow();
                (
                    received.bytes.len(),
                    received.terminals.len(),
                    received.ends.len(),
                )
            };
            match (bytes, events, ends, this.peer.stage) {
                (2, 0, 1, Stage::Delivered) => {
                    this.peer.terminate(this.step.now().into_raw(), 0)?;
                }
                (2, 2, 2, Stage::Terminated(handle)) => {
                    this.client.at(this.step.clock()).restart_all();
                    this.peer.stage = Stage::Replacement(handle);
                }
                (4, 2, 3, Stage::Delivered) => {
                    this.peer.terminate(this.step.now().into_raw(), 1)?;
                }
                (4, 4, 4, Stage::Terminated(_)) => {
                    let previous = this.received.borrow().terminals[0].0;
                    let result = this
                        .client
                        .at(this.step.clock())
                        .with_attempt(previous, |_| ());
                    if result != Err(errors::Access::InvalidHandle) {
                        return Err(Error::StaleAttempt(result));
                    }
                    this.received.borrow_mut().stale_checked = true;
                    this.finish.fire();
                }
                _ => {}
            }
            if this.timeout.is_due(this.step.now()) {
                return Err(Error::Timeout);
            }
            *this.next = this
                .step
                .now()
                .try_add(Duration::from_millis(1))
                .map_err(Error::Deadline)?;
            Ok(())
        })();
        if let Err(cause) = result {
            this.received.borrow_mut().error = Some(cause);
            if this.finish.stop.is_some() {
                this.finish.fire();
            }
        }
        control::Flow::Idle
    }
}
