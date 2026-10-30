use o3::buffer::hold;

use crate::stream::{release, send::admit};

/// Exact physical owners released from one source after budget commitment.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Event {
    pub source: admit::Source,
    pub charge: hold::Charge,
    pub cause: release::Cause,
}

impl Event {
    pub(in crate::stream) const fn new(
        source: admit::Source,
        charge: hold::Charge,
        cause: release::Cause,
    ) -> Self {
        Self {
            source,
            charge,
            cause,
        }
    }
}

const _: () = assert!(core::mem::size_of::<Event>() == 5 * core::mem::size_of::<usize>());
