use dope::core::driver::schedule::ready;
use dope::core::driver::storage;

/// Failure to bind a socket-free link to its owning driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Ready(ready::Capacity),
    Resident(storage::Exhausted),
}

impl From<ready::Capacity> for Error {
    fn from(error: ready::Capacity) -> Self {
        Self::Ready(error)
    }
}

impl From<storage::Exhausted> for Error {
    fn from(error: storage::Exhausted) -> Self {
        Self::Resident(error)
    }
}
