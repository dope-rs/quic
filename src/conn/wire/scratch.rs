use std::{mem, ops};

use o3::alloc::{self, VecExt as _};

use crate::conn::stream::state::receive::recv::map::scope;
use crate::conn::wire::{crypto::chunks, ingress::frames::record};
use crate::wire::ranges::{self, inserts};

/// Bounded metadata storage shared by one serialized receive lane.
/// It never owns packet payloads; its exclusive borrow prevents reentrancy.
pub(in crate::conn) struct Scratch {
    pub(in crate::conn) records: record::Storage,
    pub(in crate::conn) buffers: Buffers,
}

pub(in crate::conn) struct Buffers {
    pub(in crate::conn) segments: Vec<ops::Range<u64>>,
    pub(in crate::conn) parts: Vec<inserts::Part>,
    pub(in crate::conn) crypto: chunks::Scratch,
    pub(in crate::conn) streams: scope::Storage,
}

impl Scratch {
    pub(in crate::conn) fn try_new() -> Result<Self, alloc::Error> {
        Ok(Self {
            records: record::Storage::try_new()?,
            buffers: Buffers {
                segments: Vec::try_new(ranges::MAX)?,
                parts: Vec::try_new(ranges::MAX)?,
                crypto: chunks::Scratch::try_new()?,
                streams: scope::Storage::try_new()?,
            },
        })
    }
}

const _: () = assert!(
    mem::size_of::<Scratch>()
        == std::mem::size_of::<record::Storage>()
            + std::mem::size_of::<Vec<ops::Range<u64>>>()
            + std::mem::size_of::<Vec<inserts::Part>>()
            + std::mem::size_of::<chunks::Scratch>()
            + std::mem::size_of::<scope::Storage>()
);
