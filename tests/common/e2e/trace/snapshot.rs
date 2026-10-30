use crate::common::e2e::trace;

/// Transport-independent semantic state exposed after every transition.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Snapshot {
    established: [bool; 2],
    closed: [bool; 2],
    accepted: [u16; 2],
    delivered: [u16; 2],
    pending_packets: [u16; 2],
    client_path: trace::PathId,
    elapsed_millis: u64,
}

impl Snapshot {
    pub const fn new(
        up: [bool; 2],
        closed: [bool; 2],
        accepted: [u16; 2],
        sent: [u16; 2],
        pending: [u16; 2],
        elapsed: u64,
    ) -> Self {
        Self {
            established: up,
            closed,
            accepted,
            delivered: sent,
            pending_packets: pending,
            client_path: trace::PathId::INITIAL,
            elapsed_millis: elapsed,
        }
    }

    pub const fn with_path(
        up: [bool; 2],
        closed: [bool; 2],
        accepted: [u16; 2],
        sent: [u16; 2],
        pending: [u16; 2],
        path: trace::PathId,
        elapsed: u64,
    ) -> Self {
        Self {
            established: up,
            closed,
            accepted,
            delivered: sent,
            pending_packets: pending,
            client_path: path,
            elapsed_millis: elapsed,
        }
    }

    pub const fn is_up(self, endpoint: trace::Endpoint) -> bool {
        self.established[endpoint.index()]
    }

    pub const fn is_closed(self, endpoint: trace::Endpoint) -> bool {
        self.closed[endpoint.index()]
    }

    pub const fn accepted(self, endpoint: trace::Endpoint) -> u16 {
        self.accepted[endpoint.index()]
    }

    pub const fn delivered(self, endpoint: trace::Endpoint) -> u16 {
        self.delivered[endpoint.index()]
    }

    pub const fn pending(self, dir: trace::Direction) -> u16 {
        self.pending_packets[dir.index()]
    }

    pub const fn client_path(self) -> trace::PathId {
        self.client_path
    }

    pub const fn elapsed(self) -> u64 {
        self.elapsed_millis
    }

    pub fn try_validate(self) -> Result<(), trace::Violation> {
        for dst in [trace::Endpoint::Client, trace::Endpoint::Server] {
            let count = self.delivered(dst);
            let accepted = self.accepted(dst.peer());
            if count > accepted {
                return Err(trace::Violation::UnsentDelivery {
                    destination: dst,
                    delivered: count,
                    accepted,
                });
            }
        }
        Ok(())
    }
}
