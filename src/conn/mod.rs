use std::{error, fmt};

use crate::frame;
use crate::transport_params;

mod commit;
pub mod config;
mod control;
mod crypto_tx;
pub mod datagram;
mod delivery;
mod egress;
mod event_queue;
pub(crate) mod handshake;
pub(crate) mod ingress;
mod receive_workspace;
pub use receive_workspace::ReceiveWorkspace;
mod journal;
pub mod packet;
pub(crate) mod path;
mod peer;
mod reassembly;
pub mod recovery;
mod recv;
mod retired;
mod send;
pub mod server;
pub mod session;
pub mod setup;
pub mod status;
pub mod stream;
mod stream_journal;
mod streams;
pub mod tls;
pub mod transmit;

const MIN_INITIAL_LEN: usize = 1200;
const TAG_LEN: usize = 16;
const PN_LEN: u8 = 4;
const STREAM_FRAME_OVERHEAD: usize = 25;
const PACKET_JOURNAL_CAPACITY: usize = 4096;
const CRYPTO_JOURNAL_CAPACITY: usize = 4096;
const CONTROL_JOURNAL_CAPACITY: usize = 8192;
const STREAM_JOURNAL_CAPACITY: usize = 16384;
const PACKET_CONTROL_CAPACITY: usize = 16;
const PACKET_STREAM_CAPACITY: usize = 16;
const STREAM_SCHEDULE_CAPACITY: usize = 256;
const STREAM_SCHEDULE_WORK_LIMIT: usize = 256;
const MAX_PATH_TOKENS: usize = 64;
pub(crate) const MAX_FRAMES_PER_PACKET: usize = 256;
const _: () = assert!(MAX_FRAMES_PER_PACKET == u8::MAX as usize + 1);
/// Bound for generated ACK gaps and ranges that each occupy at most two bytes.
const MAX_GENERATED_ACK_FRAME_BYTES: usize =
    1 + 8 + 1 + 2 + 2 + frame::MAX_ADDITIONAL_ACK_RANGES * 4;
const MAX_BATCH_PACKETS: usize = 64;
const MAX_QUEUE_CAPACITY: usize = 65_536;
const MAX_STREAMS: u64 = 65_536;

const MAX_STREAM_COUNT: u64 = 1 << 60;
const MAX_FLOW_CONTROL_CREDIT: u64 = 1 << 30;
pub(crate) const MAX_ACTIVE_CONNECTION_IDS: usize = 8;
const MAX_PENDING_RETIRE_CONNECTION_IDS: usize = 64;
const INTERNAL_ERROR: u64 = 0x1;
const CONTROL_CAPACITY_REASON: &[u8] = b"control queue capacity exhausted";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle(pub u64);

impl Handle {
    pub(crate) fn from_parts(index: u32, generation: u32) -> Self {
        Self((u64::from(generation) << 32) | u64::from(index))
    }

    pub(crate) fn index(self) -> u32 {
        self.0 as u32
    }

    pub(crate) fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Handshaking,
    Established,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    PacketDecrypt,
    HeaderDecode,
    FrameDecode,
    FrameEncode,
    PacketEncrypt,
    Tls,
    UnexpectedEpoch,
    TransportParameterMismatch,
    TransportParameterDecode,
    PeerClosed,
    IdleTimeout,
    FlowControl,
    FinalSize,
    CryptoBufferExceeded,
    StreamBufferExceeded,
    PacketCeiling,
    EventCapacity,
    ConnectionIdLimit,
    ProtocolViolation,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PacketDecrypt => "packet decryption failed",
            Self::HeaderDecode => "packet header decoding failed",
            Self::FrameDecode => "frame decoding failed",
            Self::FrameEncode => "frame encoding failed",
            Self::PacketEncrypt => "packet encryption failed",
            Self::Tls => "TLS processing failed",
            Self::UnexpectedEpoch => "unexpected encryption epoch",
            Self::TransportParameterMismatch => "transport parameters do not match the connection",
            Self::TransportParameterDecode => "transport parameter decoding failed",
            Self::PeerClosed => "peer closed the connection",
            Self::IdleTimeout => "connection idle timeout expired",
            Self::FlowControl => "flow control limit exceeded",
            Self::FinalSize => "stream final size changed",
            Self::CryptoBufferExceeded => "crypto reassembly capacity exceeded",
            Self::StreamBufferExceeded => "stream reassembly capacity exceeded",
            Self::PacketCeiling => "packet size exceeds the configured ceiling",
            Self::EventCapacity => "connection event capacity exceeded",
            Self::ConnectionIdLimit => "connection ID capacity exceeded",
            Self::ProtocolViolation => "QUIC protocol violation",
        })
    }
}

impl error::Error for Error {}

impl From<transport_params::TransportParameterError> for Error {
    fn from(_: transport_params::TransportParameterError) -> Self {
        Self::TransportParameterDecode
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Epoch {
    Initial = 0,
    Handshake = 1,
    Application = 2,
}

impl Epoch {
    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::Initial,
            1 => Self::Handshake,
            _ => Self::Application,
        }
    }
}

const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<journal::Table>();
};
const _: () = assert!(std::mem::size_of::<journal::Packet>() == 48);
const _: () = assert!(!std::mem::needs_drop::<commit::Packet>());
