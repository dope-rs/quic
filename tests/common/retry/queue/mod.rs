use crate::common::retry::{
    Finish,
    writable::{Peer, PeerError},
};
use crate::common::runtime::loopback::capture::Connect;
use dope::core::driver::{route::KeyTag, schedule, schedule::clock};
use dope::core::io::datagram::ReceiveError;
use dope::manifold::app::dispatch;
use dope::manifold::network::datagram::{RejectCause, Transport};
use dope::runtime::control;
use dope_quic::conn::{id, output::transmit};
use dope_quic::errors;
use dope_quic::errors::SendFailure;
use dope_quic::proto::datagram::{self, Arena, Packet, Sealed};
use dope_quic::proto::param;
use dope_quic::runtime::endpoint::{Endpoint, Idle, owner::Owned};
use dope_quic::runtime::mux::handler::{hook, net};
use hook::wire::packet;

mod events;
pub use events::Events;
use std::{
    cell::{Cell, RefCell},
    mem,
    pin::Pin,
    ptr,
    rc::Rc,
    time::Duration,
};

const BYTES: usize = 32;
type Owner<'d> = net::Owner<id::Driver<'d>, 1>;
type Client<'d, 'pool, F> = Endpoint<'d, 1, Events<'d, F>, Vec<u8>, Idle, Owned, Sealed<'pool>>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Handshake,
    First,
    Second,
    Blocked,
    Release,
    Done,
}

#[derive(Clone, Copy)]
struct Record<'d> {
    owner: Option<Owner<'d>>,
    flight: Option<Owner<'d>>,
    pointer: *const u8,
}

pub enum Observed<'a> {
    Certificate(&'a rustls::Error),
    Packet(packet::Failure<'a>),
    Receive(ReceiveError),
    Rejected(RejectCause),
    Transmit(transmit::Error),
    Blocked,
    ReplacedOwner(bool),
    ReplacedFlight(bool),
    Active(Option<usize>),
    Settled {
        outcome: &'a net::Outcome,
        wire: &'a [u8],
        pointer: *const u8,
    },
    Quota {
        before: usize,
        after: usize,
    },
    Park {
        submitted: bool,
        writable: usize,
        second: Option<bool>,
    },
    Receipt(usize),
    Delivered {
        first: &'a [u8],
        second: &'a [u8],
        available: usize,
    },
}

pub enum Error<'pool> {
    Timeout,
    Connect(errors::Connect),
    Peer(PeerError),
    Deadline(clock::Range<Duration>),
    Acquire(datagram::Error),
    Send(SendFailure<Packet<'pool>>),
}

pub struct State<'d, F> {
    phase: Cell<Phase>,
    connected: Cell<Option<id::Handle<id::Driver<'d>, 1>>>,
    active: Cell<usize>,
    records: Cell<[Record<'d>; 2]>,
    completed: Cell<usize>,
    writable: Cell<usize>,
    pending: Cell<bool>,
    observe: RefCell<F>,
}

impl<'d, F> State<'d, F> {
    pub fn new(observe: F) -> Self {
        Self {
            phase: Cell::new(Phase::Handshake),
            connected: Cell::new(None),
            active: Cell::new(0),
            records: Cell::new(
                [Record {
                    owner: None,
                    flight: None,
                    pointer: ptr::null(),
                }; 2],
            ),
            completed: Cell::new(0),
            writable: Cell::new(0),
            pending: Cell::new(false),
            observe: RefCell::new(observe),
        }
    }
}

/// Retains one real endpoint while limiting only its two controlled queue turns.
#[pin_project::pin_project]
pub struct Queued<'d, 'pool, F: for<'a> FnMut(Observed<'a>)> {
    #[pin]
    pub endpoint: Client<'d, 'pool, F>,
    pub state: Rc<State<'d, F>>,
}

impl<'d, 'pool, F: for<'a> FnMut(Observed<'a>)> dispatch::raw::Projection<'d>
    for Queued<'d, 'pool, F>
{
    type Inner = Client<'d, 'pool, F>;

    fn inner(self: Pin<&Self>) -> Pin<&Self::Inner> {
        self.project_ref().endpoint
    }

    fn inner_mut(self: Pin<&mut Self>) -> Pin<&mut Self::Inner> {
        self.project().endpoint
    }
}

// SAFETY: all forwarded operations keep the same installed, structurally pinned
// endpoint; controlled passes drive protocol work against the same socket.
unsafe impl<'d, 'pool, F: for<'a> FnMut(Observed<'a>)> dispatch::raw::Manifold<'d>
    for Queued<'d, 'pool, F>
{
    type Route = KeyTag<1>;
    type Dispatch = dispatch::raw::Projected<Self>;
    type Install = dispatch::raw::Projected<Self>;
    type Finish = dispatch::raw::Projected<Self>;
    type Activate = dispatch::raw::Projected<Self>;
    type Probe = dispatch::raw::Projected<Self>;
    type PrePark = dispatch::raw::Retained;
    type Shutdown = dispatch::raw::Plain;

    const COORDS: usize =
        <<Self as dispatch::raw::Projection<'d>>::Inner as dispatch::raw::Manifold<'d>>::COORDS;

    unsafe fn pre_park<'a, 'turn, 'root>(
        mut self: Pin<&'a mut Self>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut dispatch::raw::Context<'_, 'root, 'd, Self::PrePark>,
    ) -> Pin<&'a mut Self>
    where
        Self: 'root,
    {
        let phase = self.state.phase.get();
        if phase == Phase::Second {
            return self;
        }
        let passes = match phase {
            Phase::First => 1,
            Phase::Blocked => 2,
            _ => {
                // SAFETY: the exact installed endpoint remains pinned.
                unsafe {
                    dispatch::raw::Manifold::pre_park(
                        self.as_mut().project().endpoint,
                        turn,
                        driver,
                    );
                }
                return self;
            }
        };
        if turn.app().remaining() < passes {
            return self;
        }
        for _ in 0..passes {
            turn.app().share::<{ usize::MAX }, _>(|share| {
                let before = share.work().remaining();
                let endpoint =
                    dispatch::raw::Projection::inner_mut(self.as_mut().project().endpoint);
                let (handler, socket) = endpoint.split();
                let now = driver.driver_ref().clock().now();
                Transport::pre_park(handler, socket, now, share.work(), driver.state_token());
                (self.state.observe.borrow_mut())(Observed::Quota {
                    before,
                    after: share.work().remaining(),
                });
            });
        }
        (self.state.observe.borrow_mut())(Observed::Park {
            submitted: self.state.records.get()[0].flight.is_some(),
            writable: self.state.writable.get(),
            second: (phase == Phase::Blocked)
                .then_some(self.state.records.get()[1].owner.is_some()),
        });
        match phase {
            Phase::First if self.state.records.get()[0].owner.is_some() => {
                self.state.phase.set(Phase::Second)
            }
            Phase::Blocked => {
                self.state.phase.set(Phase::Release);
            }
            _ => {}
        }
        self
    }

    fn shutdown<'a, 'turn, 'root>(
        mut self: Pin<&'a mut Self>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut dispatch::raw::Context<'_, 'root, 'd, Self::Shutdown>,
    ) -> Pin<&'a mut Self>
    where
        Self: 'root,
    {
        self.state.phase.set(Phase::Done);
        dispatch::raw::Manifold::shutdown(self.as_mut().project().endpoint, turn, driver);
        self
    }
}

// SAFETY: Installed retains the exact owner; every endpoint view is a short
// projection of that same pinned owner during the coordination step.
unsafe impl<'d, 'pool, F: for<'a> FnMut(Observed<'a>)> dispatch::raw::Control<'d>
    for Queued<'d, 'pool, F>
{
    type View<'step>
        = dispatch::raw::Installed<'step, 'd, Self>
    where
        Self: 'step,
        'd: 'step;

    fn view<'step>(owner: dispatch::raw::Installed<'step, 'd, Self>) -> Self::View<'step>
    where
        'd: 'step,
    {
        owner
    }
}

pub enum Pending<'pool> {
    Connect(Connect<&'pool param::Set>),
    Packet(Option<Packet<'pool>>),
}

#[pin_project::pin_project]
#[derive(dope::Application)]
#[dispatcher(driver = 'd)]
#[coordinate]
pub struct App<'d, 'pool, F: for<'a> FnMut(Observed<'a>)> {
    #[pin]
    #[manifold(control)]
    pub client: Queued<'d, 'pool, F>,
    #[dispatcher(state)]
    pub peer: Peer,
    #[dispatcher(state)]
    pub pending: Pending<'pool>,
    #[dispatcher(state)]
    pub arena: &'pool Arena,
    #[dispatcher(state)]
    pub finish: Finish,
    #[dispatcher(state)]
    pub error: Rc<Cell<Option<Error<'pool>>>>,
    #[dispatcher(state)]
    pub timeout: clock::Deadline<'d>,
    #[dispatcher(schedule)]
    pub next: clock::Deadline<'d>,
}

impl<'d, 'pool, F: for<'a> FnMut(Observed<'a>)> App<'d, 'pool, F> {
    fn coordinate(mut this: app_coord::Fields<'_, 'd, 'pool, F>) -> control::Flow {
        if this.finish.stop.is_none() {
            return control::Flow::Idle;
        }
        if let Err(cause) = Self::try_progress(&mut this) {
            this.error.set(Some(cause));
            this.finish.fire();
        }
        control::Flow::Idle
    }

    fn try_progress(this: &mut app_coord::Fields<'_, 'd, 'pool, F>) -> Result<(), Error<'pool>> {
        if this.timeout.is_due(this.step.now()) {
            return Err(Error::Timeout);
        }
        let clock = this.step.clock();
        let queued = this.client.as_mut().project();
        let state = &*queued.state;
        // SAFETY: this is the same structural endpoint projection retained by
        // the installed Queued owner, borrowed only for this coordination step.
        let mut client =
            unsafe { <Client<'d, 'pool, F> as dispatch::raw::Control<'d>>::root(queued.endpoint) };
        let mut pending = match mem::replace(this.pending, Pending::Packet(None)) {
            Pending::Connect(connect) => {
                client
                    .at(clock)
                    .connect(
                        connect.peer,
                        &connect.authority,
                        connect.params.clone(),
                        vec![0x45; 8],
                    )
                    .map_err(Error::Connect)?;
                None
            }
            Pending::Packet(packet) => packet,
        };
        let result = (|| {
            let phase = state.phase.get();
            if matches!(phase, Phase::Handshake | Phase::Release) {
                this.peer
                    .poll(this.step.now().into_raw())
                    .map_err(Error::Peer)?;
                *this.next = this
                    .step
                    .now()
                    .try_add(Duration::from_millis(1))
                    .map_err(Error::Deadline)?;
            }
            match phase {
                Phase::Handshake | Phase::Second => {
                    let Some(handle) = state.connected.get() else {
                        return Ok(());
                    };
                    if phase == Phase::Handshake
                        && (state.active.get() != 0
                            || client.inspect(handle, |_, _, conn| conn.lifecycle().is_confirmed())
                                != Some(true))
                    {
                        return Ok(());
                    }
                    let index = usize::from(phase == Phase::Second);
                    let packet = match pending.take() {
                        Some(packet) => packet,
                        None => {
                            let mut packet =
                                this.arena.try_acquire(BYTES).map_err(Error::Acquire)?;
                            packet.payload_mut().fill(index as u8 + 1);
                            let mut records = state.records.get();
                            records[index].pointer = packet.payload().as_ptr();
                            state.records.set(records);
                            packet
                        }
                    };
                    match client.at(clock).try_pooled(handle, packet) {
                        Ok(()) => {
                            state.phase.set(if index == 0 {
                                Phase::First
                            } else {
                                Phase::Blocked
                            });
                            *this.next = *this.timeout;
                        }
                        Err(SendFailure::Full(packet)) => pending = Some(packet),
                        Err(cause) => return Err(Error::Send(cause)),
                    }
                }
                Phase::Release => {
                    if state.records.get()[1].owner.is_some() {
                        (state.observe.borrow_mut())(Observed::Receipt(state.writable.get()));
                        state.pending.set(false);
                    }
                    let received = this.peer.datagrams();
                    if state.completed.get() == 2
                        && let [(_, first), (_, second)] = received.as_slice()
                    {
                        (state.observe.borrow_mut())(Observed::Delivered {
                            first,
                            second,
                            available: this.arena.available(),
                        });
                        state.phase.set(Phase::Done);
                        this.finish.fire();
                    }
                }
                _ => {}
            }
            Ok(())
        })();
        *this.pending = Pending::Packet(pending);
        result
    }
}
