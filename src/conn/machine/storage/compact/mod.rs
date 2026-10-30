//! Single-allocation generational storage without a dense iteration index.

pub(in crate::conn::machine::storage) use slot::Slot;
pub(in crate::conn) use table::{Occupied, Table};

pub(in crate::conn) mod raw;
mod slot;

mod table;
