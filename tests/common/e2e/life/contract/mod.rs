use crate::common::e2e::life;
use life::identity;

pub(super) mod checks;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Field {
    TransportEpoch,
    ClientGeneration,
    ServerGeneration,
    CidEpoch,
    PathEpoch,
    ConnectionWitness,
    Accepted,
    Delivered,
    Live,
}

pub enum Error<E> {
    Driver(E),
    WrongOrdinal {
        expected: u32,
        observed: u32,
    },
    InvalidAction {
        step: life::Step,
        error: life::ScopeFault,
    },
    SettlementTimeout {
        step: life::Step,
        polls: u16,
    },
    WrongRoute {
        expected: identity::RouteId,
        observed: identity::RouteId,
    },
    WrongTransport {
        route: identity::RouteId,
        expected: identity::TransportId,
        observed: identity::TransportId,
    },
    WrongShard {
        route: identity::RouteId,
        expected: identity::ShardId,
        observed: identity::ShardId,
    },
    UnsentDelivery {
        route: identity::RouteId,
        accepted: u64,
        delivered: u64,
    },
    CounterRegressed {
        route: identity::RouteId,
        field: Field,
    },
    ActionNotApplied {
        step: life::Step,
        route: identity::RouteId,
    },
    ProbeCount {
        step: life::Step,
        route: identity::RouteId,
        before: u64,
        after: u64,
    },
    UnexpectedMutation {
        step: life::Step,
        route: identity::RouteId,
        field: Field,
    },
    NotDrained {
        route: identity::RouteId,
        accepted: u64,
        delivered: u64,
        live: bool,
    },
}
