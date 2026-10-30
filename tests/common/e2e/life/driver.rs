use crate::common::e2e::life::{ValidStep, identity, state};

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Ticket(u64);

impl Ticket {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

pub enum Issue<E> {
    Issued(Ticket),
    Failed(E),
}

pub enum Poll<E> {
    Pending,
    Settled,
    Failed(E),
}

pub trait Driver {
    type Error;

    /// Starts a topology-validated action.
    fn issue(&mut self, step: ValidStep) -> Issue<Self::Error>;

    /// Advances external work and reports observed settlement.
    fn poll(&mut self, ticket: Ticket) -> Poll<Self::Error>;

    fn snapshot(&self, route: identity::RouteId) -> Result<state::Route, Self::Error>;
}
