use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectError {
    Capacity,
    InvalidConfig,
    Tls,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Capacity => "connection capacity exhausted",
            Self::InvalidConfig => "invalid connection configuration",
            Self::Tls => "TLS connection initialization failed",
        })
    }
}

impl Error for ConnectError {}

#[derive(Debug, PartialEq, Eq)]
pub enum TrySendError<T> {
    Closed(T),
    Full(T),
    TooLarge(T),
    Unsupported(T),
}

impl<T> TrySendError<T> {
    pub fn into_inner(self) -> T {
        match self {
            Self::Closed(value)
            | Self::Full(value)
            | Self::TooLarge(value)
            | Self::Unsupported(value) => value,
        }
    }
}

impl<T> fmt::Display for TrySendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Closed(_) => "connection closed",
            Self::Full(_) => "datagram queue full",
            Self::TooLarge(_) => "datagram too large",
            Self::Unsupported(_) => "datagrams unsupported",
        })
    }
}

impl<T: fmt::Debug> Error for TrySendError<T> {}
