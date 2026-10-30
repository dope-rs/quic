use std::net;

use crate::conn::id;
use crate::errors;

/// Failure to move one output flight across a socket-free link.
pub enum Error<'d, const FROM: u8, const TO: u8> {
    Source(errors::Transmit<id::Driver<'d>, FROM>),
    Destination(errors::Transmit<id::Driver<'d>, TO>),
    WrongPeer {
        actual: net::SocketAddr,
        expected: net::SocketAddr,
    },
    FlightTooLarge {
        resident_bytes: usize,
        limit: usize,
    },
    Projection {
        projected: usize,
        resident: u32,
    },
    Receive(errors::Receive),
}
