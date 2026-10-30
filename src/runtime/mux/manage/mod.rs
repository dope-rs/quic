use std::mem;

pub mod config;
mod cursor;
mod shutdown;

use cursor::Cursor;
pub use shutdown::Shutdown;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GsoError {
    Unavailable,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Status {
    Complete,
    Pending,
}

#[derive(Default)]
pub(in crate::runtime::mux) struct State {
    pub(in crate::runtime::mux) shutting_down: bool,
    pub(in crate::runtime::mux) admission_closed: bool,
    pub(in crate::runtime::mux) cursor: Cursor,
}

const _: () = assert!(mem::size_of::<State>() == 2 * mem::size_of::<usize>());
