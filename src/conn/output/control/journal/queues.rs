use crate::conn::output::control::journal::{Flights, Lanes};

/// Owns every ready/in-flight queue inside its shared link storage owner.
pub(in crate::conn::output::control) struct Queues {
    pub(in crate::conn::output::control) lanes: Lanes,
    pub(in crate::conn::output::control) flights: Flights,
}

impl Queues {
    pub(super) fn new() -> Self {
        Self {
            lanes: Lanes::new(),
            flights: Flights::new(),
        }
    }
}
