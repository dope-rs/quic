use crate::stream;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Capacity(stream::Capacity),
}

impl From<stream::Capacity> for Error {
    fn from(capacity: stream::Capacity) -> Self {
        Self::Capacity(capacity)
    }
}
