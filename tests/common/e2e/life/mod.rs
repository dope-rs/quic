pub mod contract;
pub mod driver;
pub mod error;
pub mod identity;
mod scenario;
pub mod state;

pub use scenario::Scenario;

const MAX_ROUTES: usize = u8::MAX as usize + 1;
const MAX_TRANSPORTS: usize = u8::MAX as usize + 1;
const MAX_SHARDS: usize = u8::MAX as usize + 1;
use dope_test::quic::wire::MAX_CONNECTION_ID_BYTES;

/// Original destination CID shared by both endpoints as stable identity.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Witness {
    bytes: [u8; MAX_CONNECTION_ID_BYTES],
    len: u8,
}

impl Witness {
    const EMPTY: Self = Self {
        bytes: [0; MAX_CONNECTION_ID_BYTES],
        len: 0,
    };

    pub fn try_new(value: &[u8]) -> Result<Self, error::Witness> {
        if value.len() > MAX_CONNECTION_ID_BYTES {
            return Err(error::Witness::Length {
                actual: value.len(),
                maximum: MAX_CONNECTION_ID_BYTES,
            });
        }
        let mut witness = Self::EMPTY;
        witness.bytes[..value.len()].copy_from_slice(value);
        witness.len = value.len() as u8;
        Ok(witness)
    }
}

impl<const N: usize> From<[u8; N]> for Witness {
    fn from(value: [u8; N]) -> Self {
        const { assert!(N <= MAX_CONNECTION_ID_BYTES) };
        let mut witness = Self::EMPTY;
        witness.bytes[..N].copy_from_slice(&value);
        witness.len = N as u8;
        witness
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RouteSpec {
    route: identity::RouteId,
    transport: identity::TransportId,
    shard: identity::ShardId,
}

impl RouteSpec {
    pub const fn new(
        route: identity::RouteId,
        owner: identity::TransportId,
        shard: identity::ShardId,
    ) -> Self {
        Self {
            route,
            transport: owner,
            shard,
        }
    }

    pub const fn route(self) -> identity::RouteId {
        self.route
    }

    pub const fn transport(self) -> identity::TransportId {
        self.transport
    }

    pub const fn shard(self) -> identity::ShardId {
        self.shard
    }
}

/// Dense route ownership graph in which every declared transport owns a route.
#[derive(Clone, Copy)]
pub struct Topology<'topology> {
    transports: u16,
    routes: &'topology [RouteSpec],
}

impl<'topology> Topology<'topology> {
    pub fn try_new(
        owners: u16,
        shards: u16,
        routes: &'topology [RouteSpec],
    ) -> Result<Self, error::Topology> {
        if owners == 0 || usize::from(owners) > MAX_TRANSPORTS {
            return Err(error::Topology::Transports {
                actual: owners,
                maximum: MAX_TRANSPORTS,
            });
        }
        if shards == 0 || usize::from(shards) > MAX_SHARDS {
            return Err(error::Topology::Shards {
                actual: shards,
                maximum: MAX_SHARDS,
            });
        }
        if routes.is_empty() || routes.len() > MAX_ROUTES {
            return Err(error::Topology::Routes {
                actual: routes.len(),
                maximum: MAX_ROUTES,
            });
        }
        let mut seen = [false; MAX_TRANSPORTS];
        let mut mapped = [false; MAX_SHARDS];
        for (index, spec) in routes.iter().copied().enumerate() {
            if usize::from(spec.route().get()) != index {
                return Err(error::Topology::Route {
                    index,
                    actual: spec.route(),
                });
            }
            if u16::from(spec.transport().get()) >= owners {
                return Err(error::Topology::Transport {
                    route: spec.route(),
                    actual: spec.transport(),
                    count: owners,
                });
            }
            if u16::from(spec.shard().get()) >= shards {
                return Err(error::Topology::Shard {
                    route: spec.route(),
                    actual: spec.shard(),
                    count: shards,
                });
            }
            seen[usize::from(spec.transport().get())] = true;
            mapped[usize::from(spec.shard().get())] = true;
        }
        if let Some(index) = seen[..usize::from(owners)].iter().position(|owned| !*owned) {
            return Err(error::Topology::UnownedTransport { index });
        }
        if let Some(index) = mapped[..usize::from(shards)]
            .iter()
            .position(|owned| !*owned)
        {
            return Err(error::Topology::UnmappedShard { index });
        }
        Ok(Self {
            transports: owners,
            routes,
        })
    }

    const fn routes(self) -> &'topology [RouteSpec] {
        self.routes
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Target {
    All,
    Transport(identity::TransportId),
    Route(identity::RouteId),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::common::e2e::life) enum Change {
    Probe(u32),
    Rotate,
    Rebind {
        epoch: identity::BindingEpoch,
        sequence: u32,
    },
    Cycle,
    Drain,
}

/// Fixed-size, owner-free mutation of a routed connection lifecycle.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Action {
    Probe {
        target: Target,
        sequence: u32,
    },
    RotateLocalCids {
        target: Target,
    },
    RebindTransports {
        target: Target,
        epoch: identity::BindingEpoch,
        probe_sequence: u32,
    },
    CycleConnections {
        target: Target,
    },
    Drain {
        target: Target,
    },
}

impl Action {
    pub(in crate::common::e2e::life) const fn parts(self) -> (Target, Change) {
        match self {
            Self::Probe { target, sequence } => (target, Change::Probe(sequence)),
            Self::RotateLocalCids { target } => (target, Change::Rotate),
            Self::RebindTransports {
                target,
                epoch,
                probe_sequence: probe,
            } => (
                target,
                Change::Rebind {
                    epoch,
                    sequence: probe,
                },
            ),
            Self::CycleConnections { target } => (target, Change::Cycle),
            Self::Drain { target } => (target, Change::Drain),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Step {
    ordinal: u32,
    action: Action,
}

impl Step {
    pub const fn new(ordinal: u32, action: Action) -> Self {
        Self { ordinal, action }
    }

    pub const fn ordinal(self) -> u32 {
        self.ordinal
    }

    pub const fn action(self) -> Action {
        self.action
    }

    fn try_validate(self, topology: Topology<'_>) -> Result<ValidStep, ScopeFault> {
        let (target, change) = self.action.parts();
        match target {
            Target::All => {}
            Target::Transport(id) if u16::from(id.get()) < topology.transports => {}
            Target::Transport(id) => return Err(ScopeFault::Transport(id)),
            Target::Route(id) if matches!(change, Change::Rebind { .. }) => {
                return Err(ScopeFault::Rebind(id));
            }
            Target::Route(id) if topology.routes.get(usize::from(id.get())).is_some() => {}
            Target::Route(id) => return Err(ScopeFault::Route(id)),
        }
        Ok(ValidStep { step: self })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ScopeFault {
    Transport(identity::TransportId),
    Route(identity::RouteId),
    Rebind(identity::RouteId),
}

/// Topology-validated lifecycle transition.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ValidStep {
    step: Step,
}

impl ValidStep {
    pub const fn step(self) -> Step {
        self.step
    }

    pub const fn action(self) -> Action {
        self.step.action
    }
}

/// Canonical active-connection lifecycle steps.
pub const CANONICAL_ACTIVE_STEPS: [Step; 7] = [
    Step::new(
        0,
        Action::Probe {
            target: Target::All,
            sequence: 0,
        },
    ),
    Step::new(
        1,
        Action::RotateLocalCids {
            target: Target::All,
        },
    ),
    Step::new(
        2,
        Action::Probe {
            target: Target::All,
            sequence: 1,
        },
    ),
    Step::new(
        3,
        Action::RebindTransports {
            target: Target::All,
            epoch: identity::BindingEpoch::new(1),
            probe_sequence: 2,
        },
    ),
    Step::new(
        4,
        Action::RotateLocalCids {
            target: Target::All,
        },
    ),
    Step::new(
        5,
        Action::CycleConnections {
            target: Target::All,
        },
    ),
    Step::new(
        6,
        Action::Probe {
            target: Target::All,
            sequence: 3,
        },
    ),
];

pub enum Execution<E> {
    Complete,
    Failed(E),
}

const _: () = {
    assert!(std::mem::size_of::<identity::RouteId>() == 1);
    assert!(std::mem::size_of::<identity::TransportId>() == 1);
    assert!(std::mem::size_of::<identity::ShardId>() == 1);
    assert!(std::mem::size_of::<identity::Generation>() == 4);
    assert!(std::mem::size_of::<identity::CidEpoch>() == 8);
    assert!(std::mem::size_of::<Witness>() == MAX_CONNECTION_ID_BYTES + 1);
    assert!(std::mem::size_of::<ValidStep>() == std::mem::size_of::<Step>());
    assert!(!std::mem::needs_drop::<Action>());
    assert!(!std::mem::needs_drop::<Step>());
    assert!(!std::mem::needs_drop::<state::Route>());
};
