use crate::common::e2e::trace;

/// Fixed-size, owner-free QUIC state-machine mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Deliver(trace::Direction),
    Drop(trace::Direction),
    Duplicate(trace::Direction),
    Reorder(trace::Direction),
    SendDatagram {
        from: trace::Endpoint,
        sequence: u16,
    },
    Advance {
        millis: u16,
    },
    KeyUpdate(trace::Endpoint),
    RebindClient {
        path: trace::PathId,
    },
    Close(trace::Endpoint),
    /// Alternating bounded delivery until both directions are idle.
    Drain,
    Noop,
}
