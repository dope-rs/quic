mod half;
mod lane;
mod plan;
mod set;
mod storage;
mod tree;

pub(in crate::conn) use half::Half;
pub(in crate::conn) use plan::Plan;
pub(in crate::conn) use set::Set;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::conn) enum Insertion {
    Inserted,
    Present,
    Unavailable,
}

const MIN_DEGREE: usize = 8;
const MIN_KEYS: usize = MIN_DEGREE - 1;
const MAX_KEYS: usize = MIN_DEGREE * 2 - 1;
const MAX_CHILDREN: usize = MIN_DEGREE * 2;
const MAX_LEVELS: usize = 6;
const MAX_INTERVALS: usize = 65_536;
const LANES: usize = 4;

const _: () = assert!(2 * MIN_DEGREE.pow(MAX_LEVELS as u32) - 1 > MAX_INTERVALS);
