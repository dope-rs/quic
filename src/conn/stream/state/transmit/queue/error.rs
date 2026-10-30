use o3::{alloc, depot::queue::pool};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::conn) enum Error {
    Plan(pool::Error),
    Alloc(alloc::Error),
}
