use std::num::NonZero;

use o3::depot::queue::links;

mod cores;
mod lease;
mod stores;

pub(in crate::conn) use cores::{Core, Occupied};
pub(in crate::conn) use lease::Lease;
use stores::Storage;

const NONE: u32 = u32::MAX;

struct Free(links::Index);

pub(in crate::conn) struct Vacancy(Kind);

enum Kind {
    Recycled(Free),
    Virgin(NonZero<u32>),
}

const _: () = {
    assert!(size_of::<Free>() == size_of::<u32>());
    assert!(size_of::<Option<Free>>() == size_of::<Free>());
    assert!(size_of::<Kind>() == 2 * size_of::<u32>());
};
