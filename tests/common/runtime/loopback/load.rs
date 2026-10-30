use dope_test::harness::observe::VecCellExt as _;
use dope_test::quic;
use o3::mem::quota;
use std::cell::{Cell, RefCell};
use std::pin::Pin;
use std::rc::Rc;

use app::step;
use dope::core::driver::{
    retained,
    schedule::{app, ready},
};
use dope::runtime::shutdown;
use dope_quic::conn::id;
use dope_quic::errors::{self, SendFailure};
use dope_quic::runtime::mux::app::{Accepted, Driver, Selected, Set, Turn};
use o3::buffer::resident;

use crate::common::runtime::loopback::capture::Capture;
use crate::common::runtime::loopback::{APPLICATION_PAYLOAD, SATURATED_DATAGRAMS, SERVER_ROUTE};

#[derive(Debug)]
pub enum Failure {
    Encode(quic::EncodeError),
    Send(SendFailure<Vec<u8>>),
    Payload(quic::Violation),
    Handle,
    Selection(errors::Access),
    Ready { expected: bool, actual: bool },
    MissingReady,
    Count { actual: usize, maximum: usize },
    Unsealed,
    Signal(shutdown::FireError),
    EmptyIngress,
    IngressOverflow(usize),
    Connect(errors::Connect),
}

pub struct Fairness {
    pub target: usize,
    pub admitted: Cell<usize>,
    pub ready_stage: Cell<u8>,
    pub received: Cell<usize>,
    pub first_received_at: Cell<Option<usize>>,
    pub packets: Packets,
    pub failures: Cell<Vec<Failure>>,
    pub stale: Cell<bool>,
}

pub struct Packets {
    pub scenario: quic::Datagram,
    pub oracle: RefCell<quic::Oracle>,
}

impl Fairness {
    pub fn saturated() -> Result<Self, quic::ShapeError> {
        let scenario = Packets::scenario()?;
        Ok(Self {
            target: SATURATED_DATAGRAMS,
            admitted: Cell::new(0),
            ready_stage: Cell::new(0),
            received: Cell::new(0),
            first_received_at: Cell::new(None),
            packets: Packets {
                scenario,
                oracle: RefCell::new(quic::Oracle::new(scenario)),
            },
            failures: Cell::new(Vec::new()),
            stale: Cell::new(false),
        })
    }
}

pub struct Load {
    pub fairness: Rc<Fairness>,
    pub credit: bool,
    pub pending: Option<Vec<u8>>,
}

impl Load {
    fn send<'d, S>(
        &self,
        selected: S,
        handle: id::Handle<id::Driver<'d>, SERVER_ROUTE>,
        payload: Vec<u8>,
    ) -> Result<(), Failure>
    where
        S: Selected<
                Capture<'d, SERVER_ROUTE>,
                SERVER_ROUTE,
                Vec<u8>,
                resident::Shared<'d>,
                id::Driver<'d>,
            >,
    {
        selected.run(|mut conn| {
            if conn.handle() != handle {
                return Err(Failure::Handle);
            }
            let result = conn
                .transport()
                .datagrams()
                .try_send(payload)
                .map_err(Failure::Send);
            conn.idle();
            result
        })
    }
}

impl<'d> Driver<'d, Capture<'d, SERVER_ROUTE>, SERVER_ROUTE, Vec<u8>, resident::Shared<'d>>
    for Load
{
    fn has_work(&self, handler: Pin<&Capture<'d, SERVER_ROUTE>>) -> bool {
        self.credit
            && handler.events.established.len() != 0
            && self.fairness.admitted.get() < self.fairness.target
    }

    fn drive<
        'scope,
        'turn,
        C: Set<Capture<'d, SERVER_ROUTE>, SERVER_ROUTE, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>,
    >(
        &mut self,
        turn: Turn<'scope, Capture<'d, SERVER_ROUTE>, C>,
        parent: ready::Target<'d>,
        work: app::Work<'turn, 'd>,
        _driver: &mut retained::Context<'_, '_, 'd>,
    ) -> quota::Admission<step::Flow> {
        let (handler, mut conns) = turn.into_parts();
        let handler = handler.as_ref();
        let ready = handler.events.established.take();
        let handle = ready.first().copied();
        handler.events.established.set(ready);
        let Some(handle) = handle else {
            return quota::Admission::Empty;
        };
        let Some(permit) = work.permit() else {
            parent.wake();
            return quota::Admission::Exhausted;
        };
        let receipt = step::Receipt::direct(permit);
        let sequence = self.fairness.admitted.get();
        if self.fairness.ready_stage.get() == 0 {
            let stale = handle
                .domain()
                .handle(handle.position(), handle.generation().wrapping_add(1));
            let rejected = match conns.try_select(stale) {
                Ok(selected) => {
                    selected.run(|mut conn| conn.idle());
                    self.fairness.stale.set(true);
                    return quota::Admission::Item(receipt.settle(step::Flow::Yield));
                }
                Err(rejected) => rejected,
            };
            let (open, error) = rejected.into_parts();
            conns = open;
            if error != errors::Access::InvalidHandle {
                self.fairness.failures.push(Failure::Selection(error));
                return quota::Admission::Item(receipt.settle(step::Flow::Yield));
            }
            let Ok(selected) = conns.select(handle) else {
                return quota::Admission::Item(receipt.settle(step::Flow::Yield));
            };
            selected.run(|mut conn| conn.ready());
            self.fairness.ready_stage.set(1);
            return quota::Admission::Item(receipt.settle(step::Flow::Batch));
        }
        if self.fairness.ready_stage.get() == 1 {
            if !conns.has_ready() {
                self.fairness.failures.push(Failure::Ready {
                    expected: true,
                    actual: false,
                });
                return quota::Admission::Item(receipt.settle(step::Flow::Yield));
            }
            let Some(selected) = conns.next() else {
                self.fairness.failures.push(Failure::MissingReady);
                return quota::Admission::Item(receipt.settle(step::Flow::Yield));
            };
            selected.run(|mut conn| {
                if conn.handle() == handle {
                    conn.ready();
                } else {
                    self.fairness.failures.push(Failure::Handle);
                }
            });
            self.fairness.ready_stage.set(2);
            return quota::Admission::Item(receipt.settle(step::Flow::Batch));
        }
        let payload = match self.pending.take() {
            Some(payload) => payload,
            None => match self.fairness.packets.scenario.try_payload(0, sequence) {
                Ok(payload) => payload,
                Err(error) => {
                    self.fairness.failures.push(Failure::Encode(error));
                    return quota::Admission::Item(receipt.settle(step::Flow::Yield));
                }
            },
        };
        let result = if self.fairness.ready_stage.get() == 2 {
            if !conns.has_ready() {
                self.fairness.failures.push(Failure::Ready {
                    expected: true,
                    actual: false,
                });
                return quota::Admission::Item(receipt.settle(step::Flow::Yield));
            }
            let Some(selected) = conns.next() else {
                self.fairness.failures.push(Failure::MissingReady);
                return quota::Admission::Item(receipt.settle(step::Flow::Yield));
            };
            self.fairness.ready_stage.set(3);
            self.send(selected, handle, payload)
        } else {
            if conns.has_ready() {
                self.fairness.failures.push(Failure::Ready {
                    expected: false,
                    actual: true,
                });
                return quota::Admission::Item(receipt.settle(step::Flow::Yield));
            }
            let Ok(selected) = conns.select(handle) else {
                return quota::Admission::Item(receipt.settle(step::Flow::Yield));
            };
            self.send(selected, handle, payload)
        };
        match result {
            Ok(()) => {
                self.fairness.admitted.set(sequence + 1);
                let flow = if sequence + 1 < self.fairness.target {
                    step::Flow::Batch
                } else {
                    step::Flow::Yield
                };
                quota::Admission::Item(receipt.settle(flow))
            }
            Err(Failure::Send(SendFailure::Full(payload))) => {
                self.pending = Some(payload);
                self.credit = false;
                quota::Admission::Item(receipt.settle(step::Flow::Yield))
            }
            Err(error) => {
                self.fairness.failures.push(error);
                quota::Admission::Item(receipt.settle(step::Flow::Yield))
            }
        }
    }
}

impl Accepted for &mut Load {
    fn accepted(self) {
        self.credit = true;
    }
}

impl Packets {
    pub fn scenario() -> Result<quic::Datagram, quic::ShapeError> {
        quic::Datagram::try_new(1, SATURATED_DATAGRAMS, APPLICATION_PAYLOAD)
    }
}
