use std::num::TryFromIntError;

use crate::common::e2e::life;

use life::RouteSpec;
use life::driver;
use life::identity::{
    BindingEpoch, CidEpoch, Generation, PathEpoch, RouteId, ShardId, TransportId,
};
use life::state::{Binding, Connection, Delivery, Route};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Scope {
    Owned,
    All,
}

#[derive(Clone, Copy)]
enum Pending {
    Fresh(driver::Ticket, life::ValidStep),
    Seen(driver::Ticket, life::ValidStep),
}

#[derive(Debug)]
pub enum Error {
    Generation(TryFromIntError),
    Route(RouteId),
    MissingTicket(driver::Ticket),
    PendingTicket,
    Ticket {
        expected: driver::Ticket,
        actual: driver::Ticket,
    },
    Sequence {
        expected: u64,
        actual: u64,
    },
}

pub struct Model {
    pub routes: [Route; 4],
    pending: Option<Pending>,
    next: u64,
    scope: Scope,
}

impl Default for Model {
    fn default() -> Self {
        Self {
            routes: [0, 1, 2, 3].map(initial),
            pending: None,
            next: 0,
            scope: Scope::Owned,
        }
    }
}

impl Model {
    pub fn leaky() -> Self {
        Self {
            scope: Scope::All,
            ..Self::default()
        }
    }

    fn is_target(&self, target: life::Target, state: Route) -> bool {
        self.scope == Scope::All
            || match target {
                life::Target::All => true,
                life::Target::Transport(id) => state.spec().transport() == id,
                life::Target::Route(id) => state.spec().route() == id,
            }
    }

    fn settle(&mut self, step: life::ValidStep) -> Result<(), Error> {
        match step.action() {
            life::Action::Probe { target, sequence } => {
                for index in 0..self.routes.len() {
                    let state = self.routes[index];
                    if self.is_target(target, state) {
                        let counts = state.delivery();
                        if counts.accepted() != u64::from(sequence) {
                            return Err(Error::Sequence {
                                expected: counts.accepted(),
                                actual: u64::from(sequence),
                            });
                        }
                        self.routes[index] = with_delivery(
                            state,
                            counts.accepted() + 1,
                            counts.delivered(),
                            counts.is_live(),
                        );
                    }
                }
            }
            life::Action::RotateLocalCids { target } => {
                for index in 0..self.routes.len() {
                    let state = self.routes[index];
                    if self.is_target(target, state) {
                        self.routes[index] = Route::new(
                            state.spec(),
                            state.binding(),
                            state.connection(),
                            CidEpoch::new(state.cid().get() + 1),
                            state.delivery(),
                        );
                    }
                }
            }
            life::Action::RebindTransports {
                target,
                epoch,
                probe_sequence: probe,
            } => {
                for index in 0..self.routes.len() {
                    let state = self.routes[index];
                    if self.is_target(target, state) {
                        let counts = state.delivery();
                        if counts.accepted() != u64::from(probe) {
                            return Err(Error::Sequence {
                                expected: counts.accepted(),
                                actual: u64::from(probe),
                            });
                        }
                        self.routes[index] = Route::new(
                            state.spec(),
                            Binding::new(epoch, PathEpoch::new(state.binding().path().get() + 1)),
                            state.connection(),
                            state.cid(),
                            Delivery::new(
                                counts.accepted() + 1,
                                counts.delivered(),
                                counts.is_live(),
                            ),
                        );
                    }
                }
            }
            life::Action::CycleConnections { target } => {
                for index in 0..self.routes.len() {
                    let state = self.routes[index];
                    if self.is_target(target, state) {
                        let conn = state.connection();
                        let next = Generation::new(conn.client().get() + 1);
                        let byte = u8::try_from(next.get()).map_err(Error::Generation)?;
                        self.routes[index] = Route::new(
                            state.spec(),
                            state.binding(),
                            Connection::new(
                                next,
                                Generation::new(conn.server().get() + 1),
                                life::Witness::from([state.spec().route().get(), byte]),
                            ),
                            state.cid(),
                            state.delivery(),
                        );
                    }
                }
            }
            life::Action::Drain { target } => {
                for index in 0..self.routes.len() {
                    let state = self.routes[index];
                    if self.is_target(target, state) {
                        let accepted = state.delivery().accepted();
                        self.routes[index] = with_delivery(state, accepted, accepted, false);
                    }
                }
            }
        }
        Ok(())
    }
}

fn initial(id: u8) -> Route {
    Route::new(
        RouteSpec::new(
            RouteId::new(id),
            TransportId::new(id / 2),
            ShardId::new(id % 2),
        ),
        Binding::new(BindingEpoch::INITIAL, PathEpoch::INITIAL),
        Connection::new(
            Generation::INITIAL,
            Generation::INITIAL,
            life::Witness::from([id, 0]),
        ),
        CidEpoch::INITIAL,
        Delivery::new(0, 0, true),
    )
}

fn with_delivery(state: Route, accepted: u64, done: u64, live: bool) -> Route {
    Route::new(
        state.spec(),
        state.binding(),
        state.connection(),
        state.cid(),
        Delivery::new(accepted, done, live),
    )
}

pub const SPECS: [RouteSpec; 4] = [
    RouteSpec::new(RouteId::new(0), TransportId::new(0), ShardId::new(0)),
    RouteSpec::new(RouteId::new(1), TransportId::new(0), ShardId::new(1)),
    RouteSpec::new(RouteId::new(2), TransportId::new(1), ShardId::new(0)),
    RouteSpec::new(RouteId::new(3), TransportId::new(1), ShardId::new(1)),
];

impl driver::Driver for Model {
    type Error = Error;

    fn issue(&mut self, step: life::ValidStep) -> driver::Issue<Self::Error> {
        if self.pending.is_some() {
            return driver::Issue::Failed(Error::PendingTicket);
        }
        let ticket = driver::Ticket::new(self.next);
        self.next += 1;
        self.pending = Some(Pending::Fresh(ticket, step));
        driver::Issue::Issued(ticket)
    }

    fn poll(&mut self, ticket: driver::Ticket) -> driver::Poll<Self::Error> {
        let Some(pending) = self.pending.take() else {
            return driver::Poll::Failed(Error::MissingTicket(ticket));
        };
        let (Pending::Fresh(owner, _) | Pending::Seen(owner, _)) = pending;
        if ticket != owner {
            self.pending = Some(pending);
            return driver::Poll::Failed(Error::Ticket {
                expected: owner,
                actual: ticket,
            });
        }
        match pending {
            Pending::Fresh(owner, step) => {
                self.pending = Some(Pending::Seen(owner, step));
                driver::Poll::Pending
            }
            Pending::Seen(_, step) => match self.settle(step) {
                Ok(()) => driver::Poll::Settled,
                Err(error) => driver::Poll::Failed(error),
            },
        }
    }

    fn snapshot(&self, route: RouteId) -> Result<Route, Self::Error> {
        self.routes
            .get(usize::from(route.get()))
            .copied()
            .ok_or(Error::Route(route))
    }
}

pub struct Idle {
    pub model: Model,
    pub pending: Option<driver::Ticket>,
}

impl driver::Driver for Idle {
    type Error = Error;

    fn issue(&mut self, step: life::ValidStep) -> driver::Issue<Self::Error> {
        if self.pending.is_some() {
            return driver::Issue::Failed(Error::PendingTicket);
        }
        let ticket = driver::Ticket::new(u64::from(step.step().ordinal()));
        self.pending = Some(ticket);
        driver::Issue::Issued(ticket)
    }

    fn poll(&mut self, ticket: driver::Ticket) -> driver::Poll<Self::Error> {
        let Some(owner) = self.pending.take() else {
            return driver::Poll::Failed(Error::MissingTicket(ticket));
        };
        if ticket != owner {
            self.pending = Some(owner);
            return driver::Poll::Failed(Error::Ticket {
                expected: owner,
                actual: ticket,
            });
        }
        driver::Poll::Settled
    }

    fn snapshot(&self, route: RouteId) -> Result<Route, Self::Error> {
        self.model.snapshot(route)
    }
}
