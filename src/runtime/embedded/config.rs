use crate::{conn, proto::param, runtime::mux};

/// Socket-free mux capacity plan.
#[derive(Clone, Copy)]
pub struct Config {
    pub max_connections: usize,
    pub outgoing_capacity: usize,
    pub outgoing_bytes_capacity: usize,
    pub link_capacity: usize,
    pub max_flight_resident_bytes: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_connections: mux::DEFAULT_MAX_CONNS,
            outgoing_capacity: mux::DEFAULT_OUTGOING_CAP,
            outgoing_bytes_capacity: mux::DEFAULT_OUTGOING_BYTES_CAP,
            link_capacity: mux::DEFAULT_OUTGOING_CAP,
            max_flight_resident_bytes: conn::MAX_BATCH_PACKETS as u32
                * param::DEFAULT_MAX_UDP_PAYLOAD_SIZE as u32,
        }
    }
}
