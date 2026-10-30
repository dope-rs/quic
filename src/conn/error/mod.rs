pub(in crate::conn) mod timing;

use crate::conn::{self, Timing, wire};
use crate::proto::param;
use crate::security::crypto;
use crate::wire::{frame, packet, varint};
use frame::decode::error;
use packet::{decode, long::retry, short};
use wire::path;

const FLOW_CONTROL_ERROR: varint::VarInt = varint::VarInt::from_u8(0x3);
const STREAM_LIMIT_ERROR: varint::VarInt = varint::VarInt::from_u8(0x4);
const STREAM_STATE_ERROR: varint::VarInt = varint::VarInt::from_u8(0x5);
const FINAL_SIZE_ERROR: varint::VarInt = varint::VarInt::from_u8(0x6);
const FRAME_ENCODING_ERROR: varint::VarInt = varint::VarInt::from_u8(0x7);
const TRANSPORT_PARAMETER_ERROR: varint::VarInt = varint::VarInt::from_u8(0x8);
const CONNECTION_ID_LIMIT_ERROR: varint::VarInt = varint::VarInt::from_u8(0x9);
const PROTOCOL_VIOLATION_ERROR: varint::VarInt = varint::VarInt::from_u8(0x0a);
const CRYPTO_BUFFER_EXCEEDED_ERROR: varint::VarInt = varint::VarInt::from_u8(0x0d);

#[derive(Clone, Debug)]
pub enum Error {
    Internal,
    Timing(Timing),
    Crypto(crypto::Error),
    Short(short::Reject),
    Long(decode::Error),
    Retry(retry::Fault),
    Path(path::Error),
    HeaderDecode,
    Frame(error::Fault),
    FrameLimit { actual: usize, maximum: usize },
    Handshake(wire::Handshake),
    Tls(wire::Tls),
    UnexpectedEpoch,
    TransportParameterMismatch,
    Parameter(param::Error),
    PeerClosed,
    IdleTimeout,
    FlowControl,
    StreamLimit,
    StreamState,
    FinalSize,
    CryptoBufferExceeded,
    StreamBufferExceeded,
    PacketCeiling,
    EventCapacity,
    ConnectionIdLimit,
    ProtocolViolation,
    KeyUpdate,
    AeadLimitReached,
}

impl Error {
    pub(in crate::conn) fn close_code(&self) -> Option<varint::VarInt> {
        match self {
            Self::Internal | Self::Timing(_) | Self::Path(path::Error::Peer(_)) => {
                Some(conn::INTERNAL_ERROR)
            }
            Self::FlowControl => Some(FLOW_CONTROL_ERROR),
            Self::StreamLimit => Some(STREAM_LIMIT_ERROR),
            Self::StreamState => Some(STREAM_STATE_ERROR),
            Self::FinalSize => Some(FINAL_SIZE_ERROR),
            Self::Frame(_) | Self::FrameLimit { .. } => Some(FRAME_ENCODING_ERROR),
            Self::TransportParameterMismatch | Self::Parameter(_) => {
                Some(TRANSPORT_PARAMETER_ERROR)
            }
            Self::ConnectionIdLimit => Some(CONNECTION_ID_LIMIT_ERROR),
            Self::ProtocolViolation
            | Self::UnexpectedEpoch
            | Self::PacketCeiling
            | Self::Tls(wire::Tls::Epoch(_)) => Some(PROTOCOL_VIOLATION_ERROR),
            Self::CryptoBufferExceeded => Some(CRYPTO_BUFFER_EXCEEDED_ERROR),
            Self::KeyUpdate => Some(conn::KEY_UPDATE_ERROR),
            Self::AeadLimitReached => Some(conn::AEAD_LIMIT_REACHED),
            Self::Crypto(crypto::Error::Limit) => Some(conn::AEAD_LIMIT_REACHED),
            Self::Crypto(
                crypto::Error::InitialSuite
                | crypto::Error::KeyDimensions { .. }
                | crypto::Error::TagDimensions { .. }
                | crypto::Error::BodyDimensions { .. }
                | crypto::Error::HeaderEncrypt(_)
                | crypto::Error::HeaderDecrypt(_),
            ) => Some(conn::INTERNAL_ERROR),
            Self::Crypto(crypto::Error::ReservedBits { .. }) => Some(PROTOCOL_VIOLATION_ERROR),
            Self::Handshake(error) => Some(match error.alert {
                Some(alert) => varint::VarInt::from_u16(0x100 + u16::from(u8::from(alert))),
                None => conn::INTERNAL_ERROR,
            }),
            Self::Tls(_) => Some(conn::INTERNAL_ERROR),
            Self::Crypto(
                crypto::Error::Sample { .. }
                | crypto::Error::Number { .. }
                | crypto::Error::Allocation { .. }
                | crypto::Error::Encrypt(_)
                | crypto::Error::Decrypt(_),
            )
            | Self::Short(_)
            | Self::Long(_)
            | Self::Retry(_)
            | Self::Path(_)
            | Self::HeaderDecode
            | Self::PeerClosed
            | Self::IdleTimeout
            | Self::StreamBufferExceeded
            | Self::EventCapacity => None,
        }
    }
}

impl From<param::Error> for Error {
    fn from(error: param::Error) -> Self {
        Self::Parameter(error)
    }
}

impl From<crypto::Error> for Error {
    fn from(error: crypto::Error) -> Self {
        Self::Crypto(error)
    }
}

impl From<Timing> for Error {
    fn from(error: Timing) -> Self {
        Self::Timing(error)
    }
}
