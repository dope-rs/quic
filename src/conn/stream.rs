#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NotEstablished,
    PeerLimit,
    IdOverflow,
    InvalidStream,
    ValueOutOfRange,
}

impl_error!(Error {
    Self::NotEstablished => "connection is not established",
    Self::PeerLimit => "peer stream limit reached",
    Self::IdOverflow => "stream ID space exhausted",
    Self::InvalidStream => "invalid stream operation",
    Self::ValueOutOfRange => "stream value is out of range",
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Data { stream_id: u64 },
    Finished { stream_id: u64 },
    Reset { stream_id: u64, error_code: u64 },
    Stopped { stream_id: u64, error_code: u64 },
}

impl Event {
    pub(super) fn key(&self) -> (u64, u8) {
        match *self {
            Self::Data { stream_id } => (stream_id, 0),
            Self::Finished { stream_id } => (stream_id, 1),
            Self::Reset { stream_id, .. } => (stream_id, 2),
            Self::Stopped { stream_id, .. } => (stream_id, 3),
        }
    }
}
