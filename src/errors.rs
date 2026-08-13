use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectFailure {
    Closed,
    Capacity,
    InvalidConfig,
    InvalidTlsConfig(shin::client::config::Error),
    Tls,
}

impl fmt::Display for ConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Closed => "multiplexer is shutting down",
            Self::Capacity => "connection capacity exhausted",
            Self::InvalidConfig => "invalid connection configuration",
            Self::InvalidTlsConfig(error) => {
                return write!(f, "invalid TLS configuration: {error}");
            }
            Self::Tls => "TLS connection initialization failed",
        })
    }
}

impl Error for ConnectFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidTlsConfig(error) => Some(error),
            Self::Closed | Self::Capacity | Self::InvalidConfig | Self::Tls => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SendFailure<T> {
    Closed(T),
    Full(T),
    TooLarge(T),
    Unsupported(T),
}

impl<T> SendFailure<T> {
    pub fn into_inner(self) -> T {
        match self {
            Self::Closed(value)
            | Self::Full(value)
            | Self::TooLarge(value)
            | Self::Unsupported(value) => value,
        }
    }
}

impl<T> fmt::Display for SendFailure<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Closed(_) => "connection closed",
            Self::Full(_) => "datagram queue full",
            Self::TooLarge(_) => "datagram too large",
            Self::Unsupported(_) => "datagrams unsupported",
        })
    }
}

impl<T: fmt::Debug> Error for SendFailure<T> {}
