use crate::runtime::brand;

use std::net;

use dope::core::driver::schedule::clock;
use o3::mem::{Rejected, rc};

use crate::{client, runtime::routing};

/// Snapshot of the resident retry entry selected for one attempt.
#[must_use = "a due client attempt must be bound or deferred"]
pub(in crate::client) struct Due<A, R> {
    pub(super) slot: client::SlotId,
    pub(super) attempt: client::AttemptState,
    pub(super) addr: net::SocketAddr,
    pub(super) auth: A,
    pub(super) route: R,
}

impl<A, R: routing::PeerRoute> Due<A, R> {
    pub(in crate::client) fn address(&self) -> net::SocketAddr {
        self.addr
    }

    pub(in crate::client) fn auth(&self) -> &A {
        &self.auth
    }

    pub(in crate::client) fn route(&self) -> R {
        self.route
    }

    pub(in crate::client) fn scope<'scope, 'd>(
        &self,
        brand: brand::Token<'scope>,
        started: clock::Moment<'d>,
    ) -> client::AttemptScope<'scope, 'd> {
        self.attempt.scope(brand, self.slot, started)
    }
}

impl<A, R: routing::PeerRoute> Due<Result<A, rc::Error>, R> {
    pub(in crate::client) fn transpose(self) -> Result<Due<A, R>, Rejected<Due<(), R>, rc::Error>> {
        let Self {
            slot,
            attempt,
            addr,
            auth,
            route,
        } = self;
        match auth {
            Ok(auth) => Ok(Due {
                slot,
                attempt,
                addr,
                auth,
                route,
            }),
            Err(error) => Err(Rejected::new(
                Due {
                    slot,
                    attempt,
                    addr,
                    auth: (),
                    route,
                },
                error,
            )),
        }
    }
}
