use crate::common::e2e::life::{
    self,
    driver::{Driver, Issue, Poll, Ticket},
    identity::RouteId,
    state::Route,
};
use crate::common::suite::cid::{Error, contract::Wire};
impl Driver for Wire {
    type Error = Error;

    fn issue(&mut self, step: life::ValidStep) -> Issue<Self::Error> {
        if let Some((ticket, valid)) = self.steps.pending {
            return Issue::Failed(Error::Pending {
                ticket,
                step: valid.step(),
            });
        }
        let ticket = Ticket::new(self.steps.next);
        self.steps.next += 1;
        self.steps.pending = Some((ticket, step));
        Issue::Issued(ticket)
    }

    fn poll(&mut self, ticket: Ticket) -> Poll<Self::Error> {
        let Some((pending, step)) = self.steps.pending.take() else {
            return Poll::Failed(Error::Idle { ticket });
        };
        if pending != ticket {
            self.steps.pending = Some((pending, step));
            return Poll::Failed(Error::Ticket {
                expected: pending,
                actual: ticket,
            });
        }
        match self.execute(step) {
            Ok(()) => Poll::Settled,
            Err(error) => Poll::Failed(error),
        }
    }

    fn snapshot(&self, route: RouteId) -> Result<Route, Error> {
        if route != RouteId::new(0) {
            return Err(Error::Route(route));
        }
        Ok(self.route)
    }
}
