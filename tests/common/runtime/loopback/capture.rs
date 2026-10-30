use dope::core::{Errno, driver::result::SubmitError, io::datagram::ReceiveError};
use dope::manifold::app::dispatch;
use dope::manifold::network::datagram::RejectCause;
use dope_quic::errors::detail;
use dope_quic::runtime::endpoint;
use dope_quic::runtime::mux::handler::hook::wire::endpoint::Off;
use dope_test::harness::observe::VecCellExt as _;
use dope_test::quic::net::{Completion, Oracle, Outcome, Violation};
use std::cell::{Cell, RefCell};
use std::net::SocketAddr;
use std::rc::Rc;

use dope::runtime::shutdown;
use dope_quic::conn::life::tls::clients::Authority;
use dope_quic::conn::{id, output::transmit};
use dope_quic::errors;
use dope_quic::proto::param;
use dope_quic::runtime::mux::handler::hook::data::datagram;
use dope_quic::runtime::mux::handler::hook::life::{close, closing, create, ready};
use dope_quic::runtime::mux::handler::hook::set;
use dope_quic::runtime::mux::handler::hook::wire::{cert, ingress, packet, socket};
use dope_quic::runtime::mux::handler::{self, net};
use o3::buffer::resident;

use crate::common::runtime::loopback::CLIENT_ROUTE;
use crate::common::runtime::loopback::load;

#[derive(Default)]
pub struct Events<'d, const ID: u8> {
    pub certificates: Cell<bool>,
    pub packet: Cell<Option<(SocketAddr, usize, errors::Receive)>>,
    pub detail: Cell<Option<(SocketAddr, usize, detail::Diagnostic)>>,
    pub established: Cell<Vec<id::Handle<id::Driver<'d>, ID>>>,
    pub closed: Cell<Vec<id::Handle<id::Driver<'d>, ID>>>,
    pub transmit: Cell<Vec<(errors::Transmit<id::Driver<'d>, ID>, usize)>>,
}

#[derive(Clone)]
pub struct Observed(Rc<RefCell<Ledger>>);

enum Ledger {
    Open(Oracle),
    Failed(Failure),
}

#[derive(Clone, Debug)]
pub enum Failure {
    Transmit(transmit::Error),
    Receive(ReceiveError),
    Rejected(RejectCause),
    Contract(Violation),
    Send {
        bytes: usize,
        error: Errno,
        contract: Option<Violation>,
    },
    Submit {
        bytes: usize,
        error: SubmitError,
        contract: Option<Violation>,
    },
    Shutdown {
        bytes: usize,
        contract: Option<Violation>,
    },
}

impl Default for Observed {
    fn default() -> Self {
        Self(Rc::new(RefCell::new(Ledger::Open(Oracle::default()))))
    }
}

impl Observed {
    pub(super) fn is_complete(&self) -> bool {
        matches!(&*self.0.borrow(), Ledger::Open(oracle) if oracle.is_complete())
    }

    fn observe<'d, const ID: u8>(&self, event: &net::Event<'_, id::Driver<'d>, ID>) {
        let mut ledger = self.0.borrow_mut();
        let Ledger::Open(oracle) = &mut *ledger else {
            return;
        };
        match event {
            net::Event::Transmit(error) => {
                *ledger = Ledger::Failed(Failure::Transmit(error.cause().clone()));
            }
            net::Event::Receive { error, .. } => *ledger = Ledger::Failed(Failure::Receive(*error)),
            net::Event::Rejected { error, .. } => {
                *ledger = Ledger::Failed(Failure::Rejected(*error))
            }
            net::Event::Accepted(value) => {
                if let Err(error) = oracle.accept(
                    value.shape().datagrams(),
                    value.bytes(),
                    value.shape().is_segmented(),
                ) {
                    *ledger = Ledger::Failed(Failure::Contract(error));
                }
            }
            net::Event::Transferred(_) => {}
            net::Event::Settled(value) => {
                let bytes = value.payload().len();
                match value.outcome() {
                    net::Outcome::Sent(sent) => {
                        if let Err(error) = oracle.settle(bytes, Outcome::Sent(sent.into_raw())) {
                            *ledger = Ledger::Failed(Failure::Contract(error));
                        }
                    }
                    net::Outcome::Failed(error) => {
                        let contract = oracle.settle(bytes, Outcome::Failed).err();
                        *ledger = Ledger::Failed(Failure::Send {
                            bytes,
                            error: *error,
                            contract,
                        });
                    }
                    net::Outcome::Shutdown => {
                        let contract = oracle.settle(bytes, Outcome::Shutdown).err();
                        *ledger = Ledger::Failed(Failure::Shutdown { bytes, contract });
                    }
                    net::Outcome::Submit(error) => {
                        let contract = oracle.settle(bytes, Outcome::Failed).err();
                        *ledger = Ledger::Failed(Failure::Submit {
                            bytes,
                            error: *error,
                            contract,
                        });
                    }
                }
            }
        }
    }

    pub fn finish(&self) -> Result<Completion, Failure> {
        match &*self.0.borrow() {
            Ledger::Open(oracle) => oracle.finish().map_err(Failure::Contract),
            Ledger::Failed(error) => Err(error.clone()),
        }
    }
}

pub struct Connect<P = param::Set> {
    pub peer: SocketAddr,
    pub authority: Authority,
    pub params: P,
}

pub struct Capture<'d, const ID: u8> {
    pub events: Rc<Events<'d, ID>>,
    pub stop: Rc<Cell<Option<shutdown::Trigger>>>,
    pub connect: Option<Connect>,
    pub timed_out: Rc<Cell<bool>>,
    pub fairness: Rc<load::Fairness>,
    pub gso_active: Rc<Cell<Option<bool>>>,
    pub network: Network,
}

pub struct Network {
    pub observed: Observed,
    pub ingress: Rc<Cell<usize>>,
}

impl<const ID: u8> Capture<'_, ID> {
    pub(super) fn finish(&self, stop: shutdown::Trigger) {
        if let Err(error) = stop.fire() {
            self.fairness.failures.push(load::Failure::Signal(error));
        }
    }
}

impl<'d, const ID: u8> handler::Handler<ID, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID>
{
    type Connection = ();
    type Create = create::Unit;
    type Events = set::Set<
        set::On,
        set::On,
        set::Off,
        set::Off,
        set::Off,
        set::On,
        ingress::On,
        packet::On,
        Off,
        closing::Off,
        close::On,
    >;
}

impl<'d, const ID: u8> ready::Sink<ID, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID>
{
    fn established(
        event: ready::Event<'_, Self, ID, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>,
    ) {
        let (this, _, handle, _) = event.into();
        this.events.established.push(handle);
    }
}

impl<'d, const ID: u8> datagram::Sink<ID, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID>
{
    fn datagram(
        event: datagram::Event<'_, Self, ID, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>,
    ) {
        let (this, _, _, data, _) = event.into();
        if ID == CLIENT_ROUTE {
            if let Err(error) = this.fairness.packets.oracle.borrow_mut().observe(&data) {
                this.fairness.failures.push(load::Failure::Payload(error));
            }
            let count = this.fairness.packets.oracle.borrow().delivered();
            this.fairness.received.set(count);
            if this.fairness.first_received_at.get().is_none() {
                this.fairness
                    .first_received_at
                    .set(Some(this.fairness.admitted.get()));
            }
            if count > this.fairness.target {
                this.fairness.failures.push(load::Failure::Count {
                    actual: count,
                    maximum: this.fairness.target,
                });
            }
        }
    }
}

impl<'d, const ID: u8> socket::Sink<ID, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID>
{
    fn socket(event: socket::Event<'_, Self, ID, id::Driver<'d>>) {
        let (this, event) = event.into_parts();
        this.network.observed.observe(&event);
        if let net::Event::Transmit(error) = event {
            this.events.transmit.push((error, this.events.closed.len()));
        }
    }
}

impl<'d, const ID: u8> ingress::Sink<ID, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID>
{
    fn ingress<'scope, 'driver>(event: ingress::Event<'scope, 'driver, Self>) {
        let (this, ingress) = event.into_parts();
        if ingress.bytes() == 0 {
            this.fairness.failures.push(load::Failure::EmptyIngress);
        }
        let count = match this.network.ingress.get().checked_add(1) {
            Some(count) => count,
            None => {
                this.fairness
                    .failures
                    .push(load::Failure::IngressOverflow(this.network.ingress.get()));
                return;
            }
        };
        this.network.ingress.set(count);
    }
}

impl<'d, const ID: u8> close::Sink<ID, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID>
{
    fn close(event: close::Event<'_, Self, ID, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>) {
        let (this, _, _, handle) = event.into_parts();
        this.events.closed.push(handle);
        if this.events.transmit.len() != 0
            && let Some(stop) = this.stop.take()
        {
            this.finish(stop);
        }
    }
}

pub struct Control<'step, 'd, const ID: u8>(&'step mut Capture<'d, ID>);

impl<'step, 'd, const ID: u8> Control<'step, 'd, ID> {
    pub fn new(capture: &'step mut Capture<'d, ID>) -> Self {
        Self(capture)
    }

    pub fn timeout(&mut self) {
        let Some(stop) = self.0.stop.take() else {
            return;
        };
        self.0.timed_out.set(true);
        self.0.finish(stop);
    }

    pub fn fail(&mut self, error: load::Failure) {
        self.0.fairness.failures.push(error);
        self.is_failed();
    }

    pub fn is_failed(&mut self) -> bool {
        let failed = self.0.fairness.failures.len() != 0 || self.0.fairness.stale.get();
        if failed && let Some(stop) = self.0.stop.take() {
            self.0.finish(stop);
        }
        failed
    }

    pub fn take_connect(&mut self) -> Option<Connect> {
        self.0.connect.take()
    }

    pub fn gso_active(&self) -> Option<bool> {
        self.0.gso_active.get()
    }

    pub fn set_gso(&mut self, active: bool) {
        self.0.gso_active.set(Some(active));
    }
}

impl<'d, const ID: u8> cert::Sink<ID, id::Driver<'d>> for Capture<'d, ID> {
    fn certificate(event: cert::Event<'_, '_, Self, ID, id::Driver<'d>>) {
        let (this, _, _, _) = event.into_parts();
        this.events.certificates.set(true);
    }
}

impl<'d, const ID: u8> packet::Sink<ID, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID>
{
    fn packet(event: packet::Event<'_, Self>) {
        let (this, from, error, len) = event.into_parts();
        match error {
            packet::Failure::Receive(error) => this.events.packet.set(Some((from, len, error))),
            packet::Failure::Diagnostic(detail) => {
                this.events.detail.set(Some((from, len, detail.clone())))
            }
        }
    }
}

// SAFETY: the control moves only test-owned command/timer state and cannot
// replace the handler installed beneath the endpoint.
unsafe impl<'d, const ID: u8> endpoint::raw::Control<'d, ID> for Capture<'d, ID> {
    type View<'step>
        = Control<'step, 'd, ID>
    where
        Self: 'step,
        'd: 'step;

    fn view<'step>(handler: dispatch::raw::Loan<'step, 'd, Self>) -> Self::View<'step>
    where
        'd: 'step,
    {
        Control::new(handler.into_pin().get_mut())
    }
}
