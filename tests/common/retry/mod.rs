pub mod queue;
pub mod sender;
pub mod traces;
pub mod writable;
use crate::common::retry::traces::{Backoff, CausalConfig, CauseBackoff, Immediate};
use dope::core::io::datagram::payload::Len;
use dope_quic::errors::Code;
use dope_quic::runtime::endpoint::config::Config;

use settings::claim::Needs;
use settings::errors::Claim;
use std::cell::Cell;
use std::marker::PhantomPinned;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::rc::Rc;
use std::time::Duration;

use dope::core::driver::schedule::clock;
use dope::core::driver::settings;
use dope::manifold::app::dispatch;
use dope::runtime::control;
use dope::runtime::shutdown;
use dope_quic::client;
use dope_quic::client::AttemptId;
use dope_quic::client::AttemptScope;
use dope_quic::client::Dialer;
use dope_quic::client::SlotId;
use dope_quic::client::auth;
use dope_quic::client::protocol;
use dope_quic::conn::{id, stream::Event};
use dope_quic::errors::{self, Connect, SendFailure, detail};
use dope_quic::proto::cid;
use dope_quic::runtime::endpoint::Endpoint;
use dope_quic::runtime::mux::handler;
use dope_quic::runtime::mux::handler::hook::life::create;
use dope_quic::runtime::mux::handler::hook::life::ready;
use dope_quic::runtime::mux::handler::hook::set;
use dope_quic::runtime::mux::handler::hook::wire::cert;
use dope_quic::runtime::mux::handler::hook::wire::ingress;
use dope_quic::runtime::mux::handler::hook::wire::packet;
use dope_quic::runtime::mux::handler::hook::writable::Off;
use dope_quic::wire::stream::Id;
use dope_test::harness::observe::VecCellExt as _;
use o3::buffer::resident;

pub const ENDPOINT: Config = Config {
    max_conns: 1,
    outgoing_capacity: 64,
    outgoing_bytes_capacity: 1 << 20,
    packet_buffer_slots: 64,
    packet_buffer_bytes: u16::MAX as u32,
    cid_rotation: cid::Rotation::disabled(),
};
pub const SERVER_ROUTE: u8 = 0;
pub const CLIENT_ROUTE: u8 = 1;
pub const BIND: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

pub struct Finish {
    pub stop: Option<shutdown::Trigger>,
    pub done: Rc<Cell<Vec<Result<(), Fire>>>>,
}

#[derive(Debug)]
pub enum Fire {
    Missing,
    Trigger(shutdown::FireError),
}

impl Finish {
    pub fn fire(&mut self) {
        self.done.push(
            self.stop
                .take()
                .ok_or(Fire::Missing)
                .and_then(|stop| stop.fire().map_err(Fire::Trigger)),
        );
    }
}

pub struct Close(pub Rc<Errors>);

impl<'d> handler::Handler<SERVER_ROUTE, Vec<u8>, resident::Shared<'d>, id::Driver<'d>> for Close {
    type Connection = ();
    type Create = create::Unit;
    type Events = set::Set<
        set::On,
        set::Off,
        set::Off,
        set::Off,
        set::Off,
        set::Off,
        ingress::Off,
        packet::On,
    >;
}

impl<'d> ready::Sink<SERVER_ROUTE, Vec<u8>, resident::Shared<'d>, id::Driver<'d>> for Close {
    fn established(
        event: ready::Event<'_, Self, SERVER_ROUTE, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>,
    ) {
        let (_, mut slot, _, _) = event.into();
        slot.transport().lifecycle().close(Code::ZERO, Vec::new());
    }
}

#[derive(Default)]
pub struct Attempts {
    pub connects: Rc<Cell<usize>>,
    pub connected: bool,
    pub previous: Cell<Option<AttemptId>>,
    pub current: Cell<Option<AttemptId>>,
    pub exact_checked: Rc<Cell<bool>>,
}

#[pin_project::pin_project]
pub struct Events {
    pub attempts: Attempts,
    pub finish: Finish,
    pub timed_out: Rc<Cell<bool>>,
    pub address: Rc<Cell<*const Events>>,
    pub streams: Rc<Cell<Option<(AttemptId, Id, usize)>>>,
    pub errors: Rc<Errors>,
    #[pin]
    pub pinned: PhantomPinned,
}

impl Events {
    pub fn new(stop: shutdown::Trigger) -> Self {
        Self {
            attempts: Attempts::default(),
            finish: Finish {
                stop: Some(stop),
                done: Rc::default(),
            },
            timed_out: Rc::default(),
            address: Rc::default(),
            streams: Rc::default(),
            errors: Rc::default(),
            pinned: PhantomPinned,
        }
    }

    pub fn settings(entries: u32, res: impl settings::Resource) -> Result<settings::Config, Claim> {
        let baseline = Config::driver(settings::Datagram::try_new(
            settings::Ring::try_round(entries)?,
            Len::fixed::<2048>(),
        )?);
        Needs::from_tree(&res)?.apply_to(baseline)
    }

    fn observe(self: Pin<&Self>) {
        let address = self.get_ref() as *const Self;
        let prior = self.address.get();
        if prior.is_null() {
            self.address.set(address);
        } else if prior != address {
            self.errors
                .violations
                .push(Violation::Moved(prior, address));
        }
    }

    fn slot(&self, slot: &client::SlotScope<'_>, expected: usize) {
        if slot.id() != SlotId::from_index(0) || slot.generation() != expected as u32 {
            self.errors.violations.push(Violation::Slot {
                id: slot.id(),
                generation: slot.generation(),
                expected,
            });
        }
    }
}

impl<'d> protocol::Protocol<'d> for Events {
    type Writable = Off;
    type Receive = Vec<u8>;

    fn failed(self: Pin<&mut Self>, attempt: AttemptScope<'_, 'd>, error: &Connect) {
        self.as_ref().observe();
        self.errors.connections.push(format!(
            "connect attempt {} failed: {error:?}",
            attempt.id().generation(),
        ));
    }

    fn packet(self: Pin<&mut Self>, from: SocketAddr, error: packet::Failure<'_>, len: usize) {
        self.as_ref().observe();
        self.errors.record(from, len, error);
    }

    fn certificate<const DOMAIN: u8>(
        self: Pin<&mut Self>,
        handle: id::Handle<id::Driver<'d>, DOMAIN>,
        from: SocketAddr,
        failure: &rustls::Error,
    ) {
        self.as_ref().observe();
        self.errors.certificate(handle, from, failure);
    }

    fn connect<'scope>(mut self: Pin<&'scope mut Self>, slot: client::SlotScope<'scope>) {
        self.as_ref().observe();
        let connects = self.attempts.connects.get() + 1;
        self.slot(&slot, connects);
        if slot.attempt_id().generation() != slot.generation() {
            self.errors.violations.push(Violation::Generation {
                attempt: slot.attempt_id().generation(),
                slot: slot.generation(),
            });
        }
        let this = self.as_mut().project();
        this.attempts
            .previous
            .set(this.attempts.current.replace(Some(slot.attempt_id())));
        this.attempts.connects.set(connects);
        this.attempts.connected = true;
        if connects == 3 {
            this.finish.fire();
        }
    }

    fn datagram<'scope>(
        self: Pin<&'scope mut Self>,
        slot: client::SlotScope<'scope>,
        data: Self::Receive,
    ) {
        self.as_ref().observe();
        self.slot(&slot, self.attempts.connects.get());
        if data.as_slice() != [0x42] {
            self.errors.violations.push(Violation::Datagram(data));
        }
    }

    fn stream<'scope>(
        self: Pin<&'scope mut Self>,
        slot: client::SlotScope<'scope>,
        id: Id,
        data: Option<Self::Receive>,
        _: bool,
    ) {
        self.as_ref().observe();
        self.streams.set(Some((
            slot.attempt_id(),
            id,
            data.map_or(0, |data| data.len()),
        )));
    }

    fn close<'scope>(mut self: Pin<&'scope mut Self>, slot: client::SlotScope<'scope>) {
        self.as_ref().observe();
        self.slot(&slot, self.attempts.connects.get());
        self.as_mut().project().attempts.connected = false;
    }

    fn stream_event<'scope>(
        self: Pin<&'scope mut Self>,
        slot: client::SlotScope<'scope>,
        event: Event,
    ) {
        self.as_ref().observe();
        let (kind, id, code) = match event {
            Event::Reset {
                id,
                error_code: code,
            } => ("reset", id, code),
            Event::Stopped {
                id,
                error_code: code,
            } => ("stopped", id, code),
            Event::Writable | Event::Readable { .. } => return,
        };
        self.errors.connections.push(format!(
            "unexpected {kind} for {:?}, stream {id:?}: {code:?}",
            slot.attempt_id(),
        ));
    }
}

pub struct EventControl<'step>(pub Pin<&'step mut Events>);

impl EventControl<'_> {
    fn observe(&mut self) {
        self.0.as_ref().observe();
    }

    fn stop_timeout(&mut self) {
        self.0.as_ref().observe();
        let events = self.0.as_mut().project();
        events.timed_out.set(true);
        events.finish.fire();
    }
}

impl<'d> protocol::Control<'d> for Events {
    type View<'step>
        = EventControl<'step>
    where
        Self: 'step,
        'd: 'step;

    fn view<'step>(protocol: dispatch::raw::Loan<'step, 'd, Self>) -> Self::View<'step>
    where
        'd: 'step,
    {
        EventControl(protocol.into_pin())
    }
}

#[pin_project::pin_project]
#[derive(dope::Application)]
#[dispatcher(driver = 'd)]
#[coordinate]
pub struct Context<'d, 'state> {
    #[pin]
    #[manifold(control)]
    pub client:
        Dialer<'d, 'd, CLIENT_ROUTE, Events, Backoff<'state>, auth::Owned, traces::Config<'state>>,
    #[dispatcher(schedule)]
    pub timeout: clock::Deadline<'d>,
}

#[pin_project::pin_project]
#[derive(dope::Application)]
#[dispatcher(driver = 'd)]
#[coordinate]
pub struct Causal<'d, 'state> {
    #[pin]
    #[manifold]
    pub server: Endpoint<'d, SERVER_ROUTE, Close>,
    #[pin]
    #[manifold(control)]
    pub client: Dialer<
        'd,
        'd,
        CLIENT_ROUTE,
        Events,
        CauseBackoff<'state>,
        auth::Owned,
        CausalConfig<'state>,
    >,
    #[dispatcher(schedule)]
    pub timeout: clock::Deadline<'d>,
}

impl<'d, 'state> Context<'d, 'state> {
    fn coordinate(mut this: context_coord::Fields<'_, 'd, 'state>) -> control::Flow {
        if this.timeout.is_due(this.step.now()) && this.client.protocol().finish.stop.is_some() {
            this.client.protocol_mut().stop_timeout();
        }
        control::Flow::Idle
    }
}

impl<'d, 'state> Causal<'d, 'state> {
    fn coordinate(mut this: causal_coord::Fields<'_, 'd, 'state>) -> control::Flow {
        this.client.protocol_mut().observe();
        let protocol = this.client.protocol();
        if protocol.attempts.connected {
            let current = protocol.attempts.current.get();
            let previous = protocol.attempts.previous.get();
            let checked = protocol.attempts.exact_checked.clone();
            let errors = protocol.errors.clone();
            let mut client = this.client.at(this.step.clock());
            match current {
                Some(current) => match client.with_attempt(current, |_| ()) {
                    Ok(()) | Err(errors::Access::Closed) => {}
                    Err(error) => errors.violations.push(Violation::Current(error)),
                },
                None => errors.violations.push(Violation::MissingCurrent),
            }
            if let Some(previous) = previous {
                let result = client.with_attempt(previous, |_| ());
                if result != Err(errors::Access::InvalidHandle) {
                    errors.violations.push(Violation::Previous(result));
                }
                checked.set(true);
            }
        }
        if this.timeout.is_due(this.step.now()) {
            this.client.protocol_mut().stop_timeout();
        }
        control::Flow::Idle
    }
}

#[pin_project::pin_project]
#[derive(dope::Application)]
#[dispatcher(driver = 'd)]
#[coordinate]
pub struct Pooled<'d, 'tls> {
    #[pin]
    #[manifold]
    pub server: Endpoint<'d, SERVER_ROUTE, Close>,
    #[pin]
    #[manifold(control)]
    pub client: Dialer<'d, 'd, CLIENT_ROUTE, Events, Immediate, auth::Pooled<'tls>>,
    #[dispatcher(state)]
    pub failures: Rc<Cell<Vec<SendFailure<Vec<u8>>>>>,
    #[dispatcher(schedule)]
    pub timeout: clock::Deadline<'d>,
}

impl<'d, 'tls> Pooled<'d, 'tls> {
    fn coordinate(mut this: pooled_coord::Fields<'_, 'd, 'tls>) -> control::Flow {
        this.client.protocol_mut().observe();
        if this.timeout.is_due(this.step.now()) {
            this.client.protocol_mut().stop_timeout();
            return control::Flow::Idle;
        }
        if this.client.protocol().attempts.connected {
            let slot = SlotId::from_index(0);
            match this.client.path_stats(slot) {
                Some(stats) if stats.srtt.is_some() && stats.cwnd > 0 => {}
                stats => {
                    this.client
                        .protocol()
                        .errors
                        .violations
                        .push(Violation::Path(stats.map(|stats| (stats.srtt, stats.cwnd))));
                    return control::Flow::Idle;
                }
            }
            if let Err(failure) = this
                .client
                .at(this.step.clock())
                .try_datagram(slot, vec![0x42])
            {
                this.failures.push(failure);
            }
        }
        control::Flow::Idle
    }
}

impl<'d> cert::Sink<SERVER_ROUTE, id::Driver<'d>> for Close {
    fn certificate(event: cert::Event<'_, '_, Self, SERVER_ROUTE, id::Driver<'d>>) {
        let (this, handle, from, failure) = event.into_parts();
        this.0.certificate(handle, from, failure);
    }
}

impl<'d> packet::Sink<SERVER_ROUTE, Vec<u8>, resident::Shared<'d>, id::Driver<'d>> for Close {
    fn packet(event: packet::Event<'_, Self>) {
        let (this, from, error, len) = event.into_parts();
        this.0.record(from, len, error);
    }
}

#[derive(Default)]
pub struct Errors {
    pub packets: Cell<Vec<(SocketAddr, errors::Receive, usize)>>,
    pub certificates: Cell<Vec<String>>,
    pub connections: Cell<Vec<String>>,
    pub detail: Cell<Option<(SocketAddr, usize, detail::Diagnostic)>>,
    pub violations: Cell<Vec<Violation>>,
}

#[derive(Debug)]
pub enum Violation {
    Moved(*const Events, *const Events),
    Slot {
        id: SlotId,
        generation: u32,
        expected: usize,
    },
    Generation {
        attempt: u32,
        slot: u32,
    },
    Datagram(Vec<u8>),
    MissingCurrent,
    Current(errors::Access),
    Previous(Result<(), errors::Access>),
    Path(Option<(Option<Duration>, u64)>),
}

impl Errors {
    fn certificate<'d, const DOMAIN: u8>(
        &self,
        handle: id::Handle<id::Driver<'d>, DOMAIN>,
        from: SocketAddr,
        failure: &rustls::Error,
    ) {
        self.certificates.push(format!(
            "certificate route: {DOMAIN}, connection: {}, generation: {}, from: {from:?}, failure: {failure:?}",
            handle.index(), handle.generation(),
        ));
    }

    fn record(&self, from: SocketAddr, len: usize, error: packet::Failure<'_>) {
        match error {
            packet::Failure::Receive(error) => self.packets.push((from, error, len)),
            packet::Failure::Diagnostic(detail) => {
                self.detail.set(Some((from, len, detail.clone())))
            }
        }
    }
}
