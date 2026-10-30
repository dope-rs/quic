//! Receive-side metadata for one prepared stream input.

use crate::conn::stream::resident;
use crate::errors;
use crate::wire::stream::Id;
use crate::wire::{frame, ranges::plan, varint};

pub(in crate::conn) struct Input {
    pub(in crate::conn) key: Option<resident::Key>,
    pub(in crate::conn) id: Id,
    pub(in crate::conn) offset: varint::VarInt,
    pub(in crate::conn) plan: plan::Record,
    pub(in crate::conn) boundary: frame::Boundary,
}

impl Input {
    pub(in crate::conn) const fn new(
        key: Option<resident::Key>,
        id: Id,
        offset: varint::VarInt,
        plan: plan::Record,
        boundary: frame::Boundary,
    ) -> Self {
        Self {
            key,
            id,
            offset,
            plan,
            boundary,
        }
    }
}

/// One validated RESET_STREAM publication and its exact released credit.
#[derive(Clone, Copy)]
pub(in crate::conn) struct Reset {
    pub(in crate::conn) key: Option<resident::Key>,
    pub(in crate::conn) id: Id,
    pub(in crate::conn) code: errors::Code,
    pub(in crate::conn) end: u64,
    pub(in crate::conn) free: u64,
}
