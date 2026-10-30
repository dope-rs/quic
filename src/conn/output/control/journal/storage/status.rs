use crate::conn;
use std::num::NonZero;

#[derive(Clone, Copy)]
pub(in crate::conn::output::control) enum Status {
    Queued,
    InFlight {
        epoch: conn::Epoch,
        carriers: NonZero<u16>,
        probe_round: u32,
    },
}
