pub mod detail;

use std::mem;

use conn::{id, output::transmit};
use dope::{core::Errno, core::driver::schedule::sequence, runtime::civil};
use life::options;
use o3::{alloc, base::time, buffer::write::consume, mem::rc};
use options::builder;

use crate::{
    conn::{self, life, stream},
    security::crypto,
    wire::{packet::long::retry, varint},
};

/// Application code proven to fit `RESET_STREAM`, `STOP_SENDING`, and `CONNECTION_CLOSE`.
/// Its representation is exactly [`varint::VarInt`]; construction performs the sole range check.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Code(varint::VarInt);

impl Code {
    pub const ZERO: Self = Self(varint::VarInt::ZERO);
    pub const MAX: Self = Self(varint::VarInt::MAX_VALUE);
    pub const MAX_VALUE: u64 = varint::VarInt::MAX;

    pub const fn new(value: u64) -> Option<Self> {
        match varint::VarInt::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    pub const fn from_u8(value: u8) -> Self {
        Self(varint::VarInt::from_u8(value))
    }

    pub const fn from_u16(value: u16) -> Self {
        Self(varint::VarInt::from_u16(value))
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub const fn as_varint(&self) -> &varint::VarInt {
        &self.0
    }

    pub(crate) const fn from_varint(value: varint::VarInt) -> Self {
        Self(value)
    }
}

impl Default for Code {
    fn default() -> Self {
        Self::ZERO
    }
}

impl From<varint::VarInt> for Code {
    fn from(value: varint::VarInt) -> Self {
        Self(value)
    }
}

impl From<Code> for varint::VarInt {
    fn from(value: Code) -> Self {
        value.0
    }
}

impl From<Code> for u64 {
    fn from(value: Code) -> Self {
        value.get()
    }
}

impl TryFrom<u64> for Code {
    type Error = varint::Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(varint::Error::TooLarge { value })
    }
}

#[derive(Debug)]
pub enum Connect {
    Allocation(alloc::Error),
    ApplicationRejected,
    Authority(rustls::Error),
    AuthorityMismatch,
    Closed,
    Capacity,
    ConnectionId(consume::Error),
    Entropy(Errno),
    RandomSpaceExhausted(sequence::Exhausted),
    IdentifierSpaceExhausted,
    InvalidConfig,
    Options(builder::Invalid),
    Param(alloc::Error),
    Protocol(conn::Error),
    Reference(rc::Error),
    Setup(rustls::Error),
    Stream(stream::Build),
    TlsCrypto(alloc::Error),
}

#[derive(Debug)]
pub enum Receive {
    Accept(Connect),
    ApplicationRejected,
    Allocation {
        error: alloc::Error,
        requested: usize,
    },
    Civil(civil::Error),
    Expiry(time::Add),
    Packet(conn::Error),
    Retry(retry::Crypto),
}

impl From<builder::Invalid> for Connect {
    fn from(error: builder::Invalid) -> Self {
        Self::Options(error)
    }
}

impl From<alloc::Error> for Connect {
    fn from(error: alloc::Error) -> Self {
        Self::Allocation(error)
    }
}

impl From<alloc::Exhausted> for Connect {
    fn from(error: alloc::Exhausted) -> Self {
        Self::Allocation(error.into())
    }
}

impl From<rc::Error> for Connect {
    fn from(error: rc::Error) -> Self {
        Self::Reference(error)
    }
}

impl From<consume::Error> for Connect {
    fn from(error: consume::Error) -> Self {
        Self::ConnectionId(error)
    }
}

/// Rejection before a saved address capability crosses TLS installation.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Preflight {
    AuthorityMismatch,
    InvalidConfig,
    Capacity,
    Closed,
    IdentifierSpaceExhausted,
}

impl Preflight {
    const fn error(self) -> &'static Connect {
        match self {
            Self::AuthorityMismatch => &Connect::AuthorityMismatch,
            Self::InvalidConfig => &Connect::InvalidConfig,
            Self::Capacity => &Connect::Capacity,
            Self::Closed => &Connect::Closed,
            Self::IdentifierSpaceExhausted => &Connect::IdentifierSpaceExhausted,
        }
    }
}

impl From<Preflight> for Connect {
    fn from(error: Preflight) -> Self {
        match error {
            Preflight::AuthorityMismatch => Self::AuthorityMismatch,
            Preflight::InvalidConfig => Self::InvalidConfig,
            Preflight::Capacity => Self::Capacity,
            Preflight::Closed => Self::Closed,
            Preflight::IdentifierSpaceExhausted => Self::IdentifierSpaceExhausted,
        }
    }
}

enum ReconnectState {
    Retained(Preflight, life::Reconnect),
    Consumed(Connect),
}

/// Reconnect failure with exact ownership of any capability that had not yet
/// crossed the TLS installation boundary.
pub struct Reconnect(ReconnectState);

impl Reconnect {
    pub(crate) fn retained(error: Preflight, saved: life::Reconnect) -> Self {
        Self(ReconnectState::Retained(error, saved))
    }

    pub(crate) fn consumed(error: Connect) -> Self {
        Self(ReconnectState::Consumed(error))
    }

    pub const fn error(&self) -> &Connect {
        match &self.0 {
            ReconnectState::Retained(error, _) => error.error(),
            ReconnectState::Consumed(error) => error,
        }
    }

    pub fn into_parts(self) -> (Connect, Option<life::Reconnect>) {
        match self.0 {
            ReconnectState::Retained(error, saved) => (error.into(), Some(saved)),
            ReconnectState::Consumed(error) => (error, None),
        }
    }
}

/// Failure to enter one scoped connection mutation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Access {
    /// The multiplexer is shutting down or the connection is already closed.
    Closed,
    /// The handle belongs to another endpoint or names a stale slot generation.
    InvalidHandle,
}

/// Exact connection and cause of one output failure.
#[derive(Debug)]
pub struct Transmit<I = id::Static, const DOMAIN: u8 = 0> {
    connection: id::Handle<I, DOMAIN>,
    cause: transmit::Error,
}

impl<I, const DOMAIN: u8> Transmit<I, DOMAIN> {
    pub(crate) const fn new(conn: id::Handle<I, DOMAIN>, cause: transmit::Error) -> Self {
        Self {
            connection: conn,
            cause,
        }
    }

    pub const fn connection(&self) -> &id::Handle<I, DOMAIN> {
        &self.connection
    }

    pub const fn cause(&self) -> &transmit::Error {
        &self.cause
    }

    pub fn into_parts(self) -> (id::Handle<I, DOMAIN>, transmit::Error) {
        (self.connection, self.cause)
    }
}

#[derive(Debug, PartialEq)]
pub enum SendFailure<T> {
    Admission(T, transmit::Admission<crypto::Dimensions>),
    Closed(T),
    Full(T),
    TooLarge(T),
    Unsupported(T),
    Crypto(crypto::Error),
}

const _: () = {
    assert!(mem::size_of::<Code>() == mem::size_of::<u64>());
    assert!(mem::align_of::<Code>() == mem::align_of::<u64>());
};
