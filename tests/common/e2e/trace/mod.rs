use o3::depot::capacity;

mod action;
pub mod diff;
mod mismatch;
mod receipt;
pub mod replay;
mod snapshot;
mod step;
mod steps;

pub use action::Action;
pub use mismatch::Mismatch;
pub use receipt::Receipt;
pub use snapshot::Snapshot;
pub use step::Step;
pub use steps::Steps;

/// Shared work ceiling for deterministic regression and fuzz execution.
pub const MAX_STEPS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    Client,
    Server,
}

impl Endpoint {
    pub const fn index(self) -> usize {
        match self {
            Self::Client => 0,
            Self::Server => 1,
        }
    }

    pub const fn peer(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

/// Absolute client-path identity stable across repeated replay actions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathId(u16);

impl PathId {
    pub const INITIAL: Self = Self(0);

    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

impl Direction {
    pub const fn source(self) -> Endpoint {
        match self {
            Self::ClientToServer => Endpoint::Client,
            Self::ServerToClient => Endpoint::Server,
        }
    }

    pub const fn destination(self) -> Endpoint {
        self.source().peer()
    }

    pub const fn index(self) -> usize {
        self.source().index()
    }
}

/// Explicit reason that an application datagram was not admitted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    Admission(Admission),
    Closed,
    Full,
    TooLarge,
    Unsupported,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Crypto {
        needed: usize,
        reason: capacity::Reason,
    },
    Packet {
        space: u8,
        number: u64,
        controls: u8,
        streams: u8,
        reason: capacity::Reason,
    },
    Stream {
        records: usize,
        reason: capacity::Reason,
    },
}

/// Expected refusal of a connection-local command.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    State,
    Permission,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Contract {
    action: Action,
    receipt: Receipt,
}

impl Contract {
    pub const fn action(self) -> Action {
        self.action
    }

    pub const fn receipt(self) -> Receipt {
        self.receipt
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AccessFault {
    Closed,
    InvalidHandle,
}

/// Exact distinct client paths required by one compact trace.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PathPlan {
    bits: u32,
}

impl PathPlan {
    pub const fn path_count(self) -> usize {
        self.bits.count_ones() as usize
    }

    pub const fn contains(self, path: PathId) -> bool {
        path.get() <= 16 && self.bits & (1_u32 << path.get()) != 0
    }

    pub const fn paths(self) -> Paths {
        Paths {
            remaining: self.bits,
        }
    }
}

pub struct Paths {
    remaining: u32,
}

impl Iterator for Paths {
    type Item = PathId;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let path = self.remaining.trailing_zeros();
        self.remaining &= self.remaining - 1;
        Some(PathId::new(path as u16))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.remaining.count_ones() as usize;
        (left, Some(left))
    }
}

impl ExactSizeIterator for Paths {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    UnsentDelivery {
        destination: Endpoint,
        delivered: u16,
        accepted: u16,
    },
}

pub enum Transition<E> {
    Applied(Receipt),
    Failed(E),
}

pub enum Execution<E> {
    Complete(Snapshot),
    Failed(E),
}

pub trait Driver {
    type Error;

    fn apply(&mut self, step: Step) -> Transition<Self::Error>;
    fn snapshot(&self) -> Snapshot;
}
/// Canonical field whose observations first differ between two adapters.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Difference {
    Receipt,
    Established(Endpoint),
    Closed(Endpoint),
    Accepted(Endpoint),
    Delivered(Endpoint),
    Pending(Direction),
    ClientPath,
    ElapsedMillis,
}

/// Typed value captured on one side of a differential mismatch.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Value {
    Receipt(Receipt),
    Boolean(bool),
    Count(u16),
    Path(PathId),
    Millis(u64),
}
/// Borrowed compact trace. Construction and iteration allocate nothing.
///
/// The trace and its returned steps retain the exact input lifetime.
#[derive(Clone, Copy)]
pub struct Trace<'input> {
    input: &'input [u8],
}

impl<'input> Trace<'input> {
    pub const fn new(input: &'input [u8]) -> Self {
        Self { input }
    }

    pub const fn input(self) -> &'input [u8] {
        self.input
    }

    pub const fn steps(self) -> Steps<'input> {
        Steps::new(self.input)
    }

    /// Pre-scans the trace into its allocation-free set of logical paths.
    pub fn path_plan(self) -> PathPlan {
        let mut bits = 1_u32 << PathId::INITIAL.get();
        for step in self.steps() {
            if let Action::RebindClient { path } = step.action() {
                bits |= 1_u32 << path.get();
            }
        }
        PathPlan { bits }
    }
}

impl Trace<'_> {
    /// Replays this trace against both adapters in exact causal lockstep.
    pub fn compare<M: Driver, K: Driver>(
        self,
        memory: &mut M,
        kernel: &mut K,
    ) -> Execution<diff::ReplayError<M::Error, K::Error>> {
        let snapshot = memory.snapshot();
        if let Some(error) = Mismatch::snapshot(None, snapshot, kernel.snapshot()) {
            return Execution::Failed(diff::ReplayError::Initial(error));
        }
        let mut driver = diff::Pair::new(memory, kernel, snapshot);
        match self.replay(&mut driver) {
            Execution::Complete(snapshot) => Execution::Complete(snapshot),
            Execution::Failed(error) => Execution::Failed(diff::ReplayError::Replay(error)),
        }
    }
}

impl Trace<'_> {
    pub fn replay<D: Driver>(self, driver: &mut D) -> Execution<replay::Error<D::Error>> {
        let mut snapshot = driver.snapshot();
        if let Err(error) = snapshot.try_validate() {
            return Execution::Failed(replay::Error::InitialInvariant { error });
        }
        for step in self.steps() {
            let action = step.action();
            let receipt = match driver.apply(step) {
                Transition::Applied(receipt) => receipt,
                Transition::Failed(error) => {
                    return Execution::Failed(replay::Error::Driver { step, error });
                }
            };
            if !receipt.is_valid(action) {
                return Execution::Failed(replay::Error::Contract {
                    step,
                    error: Contract { action, receipt },
                });
            }
            snapshot = driver.snapshot();
            if let Err(error) = snapshot.try_validate() {
                return Execution::Failed(replay::Error::Invariant { step, error });
            }
        }
        Execution::Complete(snapshot)
    }
}

const _: () = {
    assert!(std::mem::size_of::<PathPlan>() == std::mem::size_of::<u32>());
    assert!(std::mem::size_of::<Paths>() == std::mem::size_of::<u32>());
};
