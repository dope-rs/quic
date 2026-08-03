use std::collections::{BTreeMap, VecDeque};
use std::ops::{Deref, DerefMut, Range};
use std::time::{Duration, Instant};

use shin::connection::{DriveError, Event, EventContext, EventSink};
use shin::crypto::sig::SigningKey;
use subtle::ConstantTimeEq;

use crate::ConnectError;
use crate::TrySendError;
use crate::clock::WallClock;
use crate::frame::{AckRanges, Frame, TYPE_PADDING, TYPE_PING};
use crate::new_reno::{MAX_DATAGRAM_SIZE, NewReno};
use crate::pacer::Pacer;
use crate::packet::RetryPacket;
use crate::packet::ZeroRttHeader;
use crate::packet::{
    HandshakeHeader, InitialHeader, LONG_HANDSHAKE, LONG_INITIAL, LONG_ZERO_RTT, LongHeader,
    QUIC_V1, ShortHeader, ShortHeaderRef,
};
use crate::packet_protection::PacketProtection;
use crate::pmtud::{DEFAULT_MAX_PMTU, MAX_PMTU, Pmtud};
use crate::pn_space::{PnSpace, SentPacket};
use crate::qkdf::{InitialSecrets, PacketKeys};
use crate::rtt::INITIAL_RTT;
use crate::rtt::PACKET_THRESHOLD;
use crate::rtt::RttTracker;
use crate::secrets::StatelessResetSecret;
use crate::stream::RecvStream;
use crate::stream::{SendBuffer, SendStream};
use crate::transport_params;
use crate::transport_params::DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
use crate::transport_params::Params;
use crate::transport_params::TransportParameterError;
use crate::varint::VarInt;
use core::array::from_fn;
use shin::client::config::ClientCertSource;
use shin::client::config::Resumption;
use shin::client::config::Verifier;
use shin::client::{self, Client};
use shin::crypto::ticket::TicketKeys;
use shin::server::Server;
use shin::server::Shard;
use shin::server::config::CertSource;
use shin::server::config::ClientCertVerifier;
use shin::server::config::EarlyDataGuard;
use shin::server::config::NoGuard;
use shin::wire::record::CipherSuite;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::mem::take;

mod commit;
mod control;
pub mod datagram;
mod delivery;
mod journal;
pub mod packet;
mod peer;
mod reassembly;
mod retired;
mod send;
pub mod server;
pub mod session;
pub mod stream;

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
const MAX_FRAMES_PER_PACKET: usize = 256;
const MAX_BATCH_PACKETS: usize = 64;
const MAX_RECYCLED_SEND_STREAMS: usize = MAX_BATCH_PACKETS;
const MAX_QUEUE_CAPACITY: usize = 65_536;
const MAX_STREAMS: u64 = 65_536;

const MAX_STREAM_COUNT: u64 = 1 << 60;
const MAX_FLOW_CONTROL_CREDIT: u64 = 1 << 30;
const MAX_ACTIVE_CONNECTION_IDS: u64 = 8;
const MAX_PENDING_RETIRE_CONNECTION_IDS: usize = 64;
const MAX_SESSION_TICKETS: usize = 8;
const MAX_SESSION_TICKET_BYTES: usize = 256 * 1024;
const INTERNAL_ERROR: u64 = 0x1;
const CONTROL_CAPACITY_REASON: &[u8] = b"control queue capacity exhausted";

struct AckReceipt<'a> {
    largest: u64,
    delay_microseconds: u64,
    first_range: u64,
    additional_ranges: AckRanges<'a>,
    packets: Vec<SentPacket>,
}

struct ParsedAckRanges {
    bytes: Range<usize>,
    count: usize,
}

type ParsedFrame = Frame<Range<usize>, ParsedAckRanges>;

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

impl_error!(Error {
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
});

impl From<TransportParameterError> for Error {
    fn from(_: TransportParameterError) -> Self {
        Self::TransportParameterDecode
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Epoch {
    Initial = 0,
    Handshake = 1,
    Application = 2,
}

#[derive(Clone, Copy)]
enum StreamAccess {
    Receive,
    Send,
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

type TlsClock = fn() -> u64;

enum SideKind {
    Client(Box<Client<TlsClock>>),
    Server(Box<Server<TlsClock>>),
}

impl SideKind {
    fn read_client<S: EventSink + ?Sized>(
        &mut self,
        epoch: shin::connection::Epoch,
        data: &[u8],
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>> {
        match self {
            Self::Client(c) => c.read_into(epoch, data, events),
            Self::Server(_) => Err(shin::connection::Error::BadConfig.into()),
        }
    }

    fn read_server<G, V, S>(
        &mut self,
        epoch: shin::connection::Epoch,
        data: &[u8],
        shard: &mut Shard<G, V>,
        events: &mut S,
    ) -> Result<(), DriveError<S::Error>>
    where
        G: EarlyDataGuard,
        V: ClientCertVerifier,
        S: EventSink + ?Sized,
    {
        match self {
            Self::Client(_) => Err(shin::connection::Error::BadConfig.into()),
            Self::Server(server) => server.read_into(epoch, data, shard, events),
        }
    }
}

struct ShinEvents<'a> {
    pending_crypto_initial: &'a mut Vec<u8>,
    pending_crypto_handshake: &'a mut Vec<u8>,
    pending_crypto_app: &'a mut Vec<u8>,
    handshake_r: &'a mut Option<PacketProtection>,
    handshake_w: &'a mut Option<PacketProtection>,
    app_r: &'a mut Option<PacketProtection>,
    app_w: &'a mut Option<PacketProtection>,
    zero_rtt_r: &'a mut Option<PacketProtection>,
    zero_rtt_w: &'a mut Option<PacketProtection>,
    pending_synth_eod: &'a mut bool,
    peer_transport_params_raw: &'a mut Option<Vec<u8>>,
    pending_resumption_psk: &'a mut Option<[u8; 32]>,
    received_tickets: &'a mut VecDeque<session::Ticket>,
    received_ticket_bytes: &'a mut usize,
    is_client: bool,
    done: bool,
    reject_early_data: bool,
}

impl EventSink for ShinEvents<'_> {
    type Error = Error;

    fn event(&mut self, event: Event<'_>, context: EventContext) -> Result<(), Self::Error> {
        match event {
            Event::Send { epoch, data } => match epoch {
                shin::connection::Epoch::Plaintext => {
                    self.pending_crypto_initial.extend_from_slice(data)
                }
                shin::connection::Epoch::Handshake => {
                    self.pending_crypto_handshake.extend_from_slice(data)
                }
                shin::connection::Epoch::Application => {
                    self.pending_crypto_app.extend_from_slice(data)
                }
                shin::connection::Epoch::EarlyData => {}
            },
            Event::KeysReady {
                epoch,
                read_secret,
                write_secret,
            } => {
                if context.cipher_suite() != Some(CipherSuite::Aes128GcmSha256) {
                    return Err(Error::Tls);
                }
                let read_keys =
                    PacketKeys::aes_128(read_secret.as_slice()).map_err(|_| Error::Tls)?;
                let write_keys =
                    PacketKeys::aes_128(write_secret.as_slice()).map_err(|_| Error::Tls)?;
                let read = PacketProtection::aes_128(&read_keys).map_err(|_| Error::Tls)?;
                let write = PacketProtection::aes_128(&write_keys).map_err(|_| Error::Tls)?;
                match epoch {
                    shin::connection::Epoch::Handshake => {
                        *self.handshake_r = Some(read);
                        *self.handshake_w = Some(write);
                    }
                    shin::connection::Epoch::Application => {
                        *self.app_r = Some(read);
                        *self.app_w = Some(write);
                    }
                    shin::connection::Epoch::Plaintext | shin::connection::Epoch::EarlyData => {
                        return Err(Error::Tls);
                    }
                }
            }
            Event::PeerExtension { data, .. } => {
                *self.peer_transport_params_raw = Some(data.to_vec());
            }
            Event::Done => {
                self.done = true;
            }
            Event::KeyUpdate { .. } => return Err(Error::Tls),
            Event::ZeroRttKeysReady { secret } => {
                let keys = PacketKeys::aes_128(secret.as_slice()).map_err(|_| Error::Tls)?;
                if self.is_client {
                    *self.zero_rtt_w =
                        Some(PacketProtection::aes_128(&keys).map_err(|_| Error::Tls)?);
                } else {
                    *self.zero_rtt_r =
                        Some(PacketProtection::aes_128(&keys).map_err(|_| Error::Tls)?);
                    *self.pending_synth_eod = true;
                }
            }
            Event::EarlyDataAccepted => {}
            Event::EarlyDataRejected => {
                *self.zero_rtt_w = None;
                self.reject_early_data = true;
            }
            Event::NewSessionTicket {
                ticket_lifetime,
                ticket_age_add,
                ticket_nonce,
                ticket,
                max_early_data: _,
            } => {
                let psk = self.pending_resumption_psk.take().ok_or(Error::Tls)?;
                let ticket_bytes = ticket_nonce.len().saturating_add(ticket.len());
                if ticket_bytes > MAX_SESSION_TICKET_BYTES {
                    return Ok(());
                }
                while self.received_tickets.len() >= MAX_SESSION_TICKETS
                    || self.received_ticket_bytes.saturating_add(ticket_bytes)
                        > MAX_SESSION_TICKET_BYTES
                {
                    let Some(expired) = self.received_tickets.pop_front() else {
                        break;
                    };
                    *self.received_ticket_bytes = self
                        .received_ticket_bytes
                        .saturating_sub(expired.ticket_nonce.len() + expired.ticket.len());
                }
                self.received_tickets.push_back(session::Ticket {
                    ticket_lifetime,
                    ticket_age_add,
                    ticket_nonce: ticket_nonce.to_vec(),
                    ticket: ticket.to_vec(),
                    psk,
                });
                *self.received_ticket_bytes += ticket_bytes;
            }
            Event::ResumptionSecret { psk } => {
                *self.pending_resumption_psk = Some(psk);
            }
        }
        Ok(())
    }
}

struct EgressHot {
    peer_cid: Vec<u8>,
    initial_w: Option<PacketProtection>,
    handshake_w: Option<PacketProtection>,
    app_w: Option<PacketProtection>,
    zero_rtt_w: Option<PacketProtection>,
    spaces: [PnSpace; 3],
    rtt: RttTracker,
    pto_count: u32,
    loss_timer: Option<Instant>,
    pto_probe_allowance: u8,
    pto_probe_epoch: Option<Epoch>,
    scratch_pending: Vec<u64>,
    send_schedule: send::Schedule,
    packet_journals: journal::Table,
    crypto_deliveries: delivery::Tracker<delivery::Crypto>,
    stream_deliveries: delivery::Tracker<delivery::Stream>,
    pending_crypto_initial: Vec<u8>,
    pending_crypto_handshake: Vec<u8>,
    pending_crypto_app: Vec<u8>,
    pending_datagrams: VecDeque<Vec<u8>>,
    streams_send: send::Map,
    recycled_send_streams: Vec<SendStream>,
    peer_max_data: u64,
    peer_total_sent: u64,
    pending_close: Option<PendingClose>,
    cc: NewReno,
    pacer: Pacer,
    pmtud: Pmtud,
    packet_ceiling: usize,
    pmtud_probe_pn: Option<u64>,
    datagram_congestion_control: datagram::CongestionControl,
    pending_datagrams_capacity: usize,
    last_activity: Instant,
    amplification_received: u64,
    amplification_sent: u64,
    state: State,
    sent_initial: bool,
    handshake_confirmed: bool,
    ack_eliciting_sent_since_last_receive: bool,
    peer_address_validated: bool,
}

pub struct Connection {
    egress: EgressHot,
    control: control::Pending,
    side: SideKind,
    is_client: bool,
    local_cid: Vec<u8>,
    original_dcid: Vec<u8>,
    peer_first_scid: Option<Vec<u8>>,

    initial_r: Option<PacketProtection>,
    handshake_r: Option<PacketProtection>,
    app_r: Option<PacketProtection>,
    zero_rtt_r: Option<PacketProtection>,
    pending_synth_eod: bool,

    scratch_frames: Vec<u8>,
    scratch_header: Vec<u8>,
    scratch_parsed_frames: Vec<ParsedFrame>,

    incoming_datagrams: VecDeque<Vec<u8>>,
    incoming_datagrams_capacity: usize,
    peer_transport_params_raw: Option<Vec<u8>>,
    peer_transport_params: Option<transport_params::Params>,
    local_max_idle_timeout: Duration,

    cid_prefix: Option<u8>,
    stateless_reset_secret: Option<[u8; 32]>,
    stateless_reset_received: bool,
    outstanding_path_challenges: Vec<[u8; 8]>,
    validated_path_tokens: Vec<[u8; 8]>,

    local_cids: BTreeMap<u64, Vec<u8>>,
    peer_cids: BTreeMap<u64, (Vec<u8>, [u8; 16])>,
    local_active_connection_id_limit: u64,
    next_local_cid_seq: u64,
    cids_to_register: Vec<Vec<u8>>,
    auto_issued: bool,

    retry_token: Vec<u8>,
    retry_processed: bool,

    streams_recv: BTreeMap<u64, RecvStream>,
    retired_streams: retired::Streams,
    stream_events: VecDeque<stream::Event>,
    pending_stream_events: BTreeMap<(u64, u8), ()>,
    stream_events_capacity: usize,
    next_local_bidi_stream: u64,
    next_local_uni_stream: u64,
    peer_opened_streams: peer::Streams,
    local_max_streams: [u64; 2],
    initial_max_streams: [u64; 2],
    closed_peer_streams: [u64; 2],
    peer_max_streams: [u64; 2],
    opened_local_streams: [u64; 2],

    local_max_data: u64,
    conn_recv_total: u64,
    local_max_stream_data: BTreeMap<u64, u64>,
    local_initial_max_stream_data_bidi_local: u64,
    local_initial_max_stream_data_bidi_remote: u64,
    local_initial_max_stream_data_uni: u64,

    received_tickets: VecDeque<session::Ticket>,
    received_ticket_bytes: usize,
    pending_resumption_psk: Option<[u8; 32]>,
    recv_crypto: [reassembly::Crypto; 3],
}

pub struct Config {
    pub transport_params: transport_params::Params,
    pub datagram_congestion_control: datagram::CongestionControl,
    pub pending_datagrams_capacity: usize,
    pub incoming_datagrams_capacity: usize,
    pub stream_events_capacity: usize,
    pub packet_journal_capacity: usize,
    pub crypto_journal_capacity: usize,
    pub control_journal_capacity: usize,
    pub stream_journal_capacity: usize,
    pub cid_prefix: Option<u8>,
    pub stateless_reset_secret: Option<[u8; 32]>,
    pub require_address_validation: bool,
    pub retry_token_secret: Option<[u8; 32]>,
    pub ticket_secret: Option<[u8; 32]>,
    pub resumption: Option<Resumption>,
    pub enable_early_data: bool,
    pub resumption_peer_tp: Option<transport_params::Params>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub server_cert_chain: Option<Vec<Vec<u8>>>,
    pub client_cert: Option<ClientCertSource>,
    pub max_pmtu: u64,
}

impl Debug for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("transport_params", &self.transport_params)
            .field(
                "datagram_congestion_control",
                &self.datagram_congestion_control,
            )
            .field(
                "pending_datagrams_capacity",
                &self.pending_datagrams_capacity,
            )
            .field(
                "incoming_datagrams_capacity",
                &self.incoming_datagrams_capacity,
            )
            .field("stream_events_capacity", &self.stream_events_capacity)
            .field("packet_journal_capacity", &self.packet_journal_capacity)
            .field("crypto_journal_capacity", &self.crypto_journal_capacity)
            .field("control_journal_capacity", &self.control_journal_capacity)
            .field("stream_journal_capacity", &self.stream_journal_capacity)
            .field("cid_prefix", &self.cid_prefix)
            .field(
                "require_address_validation",
                &self.require_address_validation,
            )
            .field("enable_early_data", &self.enable_early_data)
            .field("resumption_peer_tp", &self.resumption_peer_tp)
            .field("alpn_protocols", &self.alpn_protocols)
            .field("server_cert_chain", &self.server_cert_chain.is_some())
            .field("client_cert", &self.client_cert.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            transport_params: Params::default(),
            datagram_congestion_control: datagram::CongestionControl::Standard,
            pending_datagrams_capacity: 1024,
            incoming_datagrams_capacity: 1024,
            stream_events_capacity: 1024,
            packet_journal_capacity: PACKET_JOURNAL_CAPACITY,
            crypto_journal_capacity: CRYPTO_JOURNAL_CAPACITY,
            control_journal_capacity: CONTROL_JOURNAL_CAPACITY,
            stream_journal_capacity: STREAM_JOURNAL_CAPACITY,
            cid_prefix: None,
            stateless_reset_secret: None,
            require_address_validation: false,
            retry_token_secret: None,
            ticket_secret: None,
            resumption: None,
            enable_early_data: false,
            resumption_peer_tp: None,
            alpn_protocols: Vec::new(),
            server_cert_chain: None,
            client_cert: None,
            max_pmtu: DEFAULT_MAX_PMTU,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), crate::ConnectError> {
        let indexed = [
            self.packet_journal_capacity,
            self.crypto_journal_capacity,
            self.control_journal_capacity,
            self.stream_journal_capacity,
        ];
        if self.max_pmtu < MIN_INITIAL_LEN as u64
            || self.max_pmtu > MAX_PMTU
            || usize::try_from(self.max_pmtu).is_err()
            || self.pending_datagrams_capacity > MAX_QUEUE_CAPACITY
            || self.incoming_datagrams_capacity > MAX_QUEUE_CAPACITY
            || self.stream_events_capacity == 0
            || self.stream_events_capacity > MAX_QUEUE_CAPACITY
            || self.packet_journal_capacity < 2
            || self.crypto_journal_capacity < 2
            || self.control_journal_capacity < PACKET_CONTROL_CAPACITY * 2
            || self.stream_journal_capacity < PACKET_STREAM_CAPACITY * 2
            || indexed
                .into_iter()
                .any(|capacity| capacity > u16::MAX as usize)
            || self.transport_params.initial_max_data > MAX_FLOW_CONTROL_CREDIT
            || self.transport_params.initial_max_stream_data_bidi_local > MAX_FLOW_CONTROL_CREDIT
            || self.transport_params.initial_max_stream_data_bidi_remote > MAX_FLOW_CONTROL_CREDIT
            || self.transport_params.initial_max_stream_data_uni > MAX_FLOW_CONTROL_CREDIT
            || self.transport_params.initial_max_streams_bidi > MAX_STREAMS
            || self.transport_params.initial_max_streams_uni > MAX_STREAMS
            || self.transport_params.active_connection_id_limit > MAX_ACTIVE_CONNECTION_IDS
            || self.transport_params.validate().is_err()
            || self
                .resumption_peer_tp
                .as_ref()
                .is_some_and(|params| params.validate().is_err())
        {
            return Err(ConnectError::InvalidConfig);
        }
        Ok(())
    }

    pub(crate) fn duplicate_connection(&self) -> Result<Self, ConnectError> {
        if self.resumption.is_some() || self.client_cert.is_some() {
            return Err(ConnectError::InvalidConfig);
        }
        Ok(Self {
            transport_params: self.transport_params.clone(),
            datagram_congestion_control: self.datagram_congestion_control,
            pending_datagrams_capacity: self.pending_datagrams_capacity,
            incoming_datagrams_capacity: self.incoming_datagrams_capacity,
            stream_events_capacity: self.stream_events_capacity,
            packet_journal_capacity: self.packet_journal_capacity,
            crypto_journal_capacity: self.crypto_journal_capacity,
            control_journal_capacity: self.control_journal_capacity,
            stream_journal_capacity: self.stream_journal_capacity,
            cid_prefix: self.cid_prefix,
            stateless_reset_secret: self.stateless_reset_secret,
            require_address_validation: self.require_address_validation,
            retry_token_secret: self.retry_token_secret,
            ticket_secret: self.ticket_secret,
            resumption: None,
            enable_early_data: self.enable_early_data,
            resumption_peer_tp: self.resumption_peer_tp.clone(),
            alpn_protocols: self.alpn_protocols.clone(),
            server_cert_chain: self.server_cert_chain.clone(),
            client_cert: None,
            max_pmtu: self.max_pmtu,
        })
    }
}

#[repr(transparent)]
pub(crate) struct ValidatedConfig(Config);

impl ValidatedConfig {
    pub(crate) fn new(config: Config) -> Result<Self, ConnectError> {
        config.validate()?;
        Ok(Self(config))
    }

    pub(crate) fn cap_max_pmtu(&mut self, ceiling: u64) -> Result<(), ConnectError> {
        if ceiling < MIN_INITIAL_LEN as u64 {
            return Err(ConnectError::InvalidConfig);
        }
        self.0.max_pmtu = self.0.max_pmtu.min(ceiling);
        Ok(())
    }

    pub(crate) fn duplicate_connection(&self) -> Result<Self, ConnectError> {
        self.0.duplicate_connection().map(Self)
    }

    fn into_inner(self) -> Config {
        self.0
    }
}

impl Deref for ValidatedConfig {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<transport_params::Params> for Config {
    fn from(params: transport_params::Params) -> Self {
        Self {
            transport_params: params,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone)]
struct PendingClose {
    is_application: bool,
    error_code: u64,
    frame_type: u64,
    reason: Vec<u8>,
}

enum SideSetup {
    Client { server_pubkey: [u8; 32] },
    Server { peer_cid: Vec<u8> },
}

impl Connection {
    fn local_tp_bytes(
        is_client: bool,
        local_cid: &[u8],
        original_dcid: &[u8],
        retry_scid: Option<&[u8]>,
        user_tp: transport_params::Params,
    ) -> Result<Vec<u8>, ConnectError> {
        let mut tp = user_tp;
        tp.initial_source_connection_id = Some(local_cid.to_vec());
        if !is_client {
            tp.original_destination_connection_id = Some(original_dcid.to_vec());
            if let Some(rscid) = retry_scid {
                tp.retry_source_connection_id = Some(rscid.to_vec());
            }
        }
        let mut buf = Vec::new();
        tp.encode(&mut buf)
            .map_err(|_| ConnectError::InvalidConfig)?;
        Ok(buf)
    }

    pub fn new_client(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        server_pubkey: [u8; 32],
        config: Config,
    ) -> Result<Self, ConnectError> {
        config.validate()?;
        let tp_original_dcid = initial_dcid.clone();
        let mut conn = Self::new_with(
            initial_dcid,
            local_cid,
            tp_original_dcid,
            None,
            config,
            SideSetup::Client { server_pubkey },
        )?;
        conn.start_client_handshake()?;
        Ok(conn)
    }

    pub fn new_server(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        peer_cid: Vec<u8>,
        signing_key: SigningKey,
        config: Config,
    ) -> Result<server::Connection, ConnectError> {
        let ids = server::Ids::initial(initial_dcid, local_cid, peer_cid);
        Self::new_server_with_policy::<server::Standard>(ids, signing_key, config, NoGuard)
    }

    pub fn new_server_retry(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        peer_cid: Vec<u8>,
        original_dcid: Vec<u8>,
        retry_scid: Vec<u8>,
        signing_key: SigningKey,
        config: Config,
    ) -> Result<server::Connection, ConnectError> {
        let ids = server::Ids::retry(initial_dcid, local_cid, peer_cid, original_dcid, retry_scid);
        Self::new_server_with_policy::<server::Standard>(ids, signing_key, config, NoGuard)
    }

    pub fn new_server_with_early_data_guard<G>(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        peer_cid: Vec<u8>,
        signing_key: SigningKey,
        config: Config,
        guard: G,
    ) -> Result<server::Connection<G>, ConnectError>
    where
        G: EarlyDataGuard + 'static,
    {
        let ids = server::Ids::initial(initial_dcid, local_cid, peer_cid);
        Self::new_server_with_policy::<server::Standard<G>>(ids, signing_key, config, guard)
    }

    pub fn new_server_mutual<V>(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        peer_cid: Vec<u8>,
        signing_key: SigningKey,
        config: Config,
        authentication: server::Authentication<V>,
    ) -> Result<server::Connection<NoGuard, V>, ConnectError>
    where
        V: ClientCertVerifier + 'static,
    {
        let ids = server::Ids::initial(initial_dcid, local_cid, peer_cid);
        Self::new_server_with_policy::<server::Mutual<NoGuard, V>>(
            ids,
            signing_key,
            config,
            authentication,
        )
    }

    pub fn new_server_mutual_with_early_data_guard<G, V>(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        peer_cid: Vec<u8>,
        signing_key: SigningKey,
        config: Config,
        authentication: server::Authentication<V, G>,
    ) -> Result<server::Connection<G, V>, ConnectError>
    where
        G: EarlyDataGuard + 'static,
        V: ClientCertVerifier + 'static,
    {
        let ids = server::Ids::initial(initial_dcid, local_cid, peer_cid);
        Self::new_server_with_policy::<server::Mutual<G, V>>(
            ids,
            signing_key,
            config,
            authentication,
        )
    }

    pub fn new_server_with_policy<P>(
        ids: server::Ids,
        signing_key: SigningKey,
        config: Config,
        setup: P::Setup,
    ) -> Result<server::Connection<P::Guard, P::Verifier>, ConnectError>
    where
        P: server::Policy,
    {
        let mut config = ValidatedConfig::new(config)?;
        let shard_config = Self::take_server_config(signing_key, &mut config)?;
        let conn = Self::new_server_connection(ids, config)?;
        Ok(server::Connection::new(
            conn,
            (P::BUILD_SHARD)(shard_config, setup),
        ))
    }

    pub(crate) fn take_server_config(
        signing_key: SigningKey,
        config: &mut ValidatedConfig,
    ) -> Result<shin::server::config::Config, ConnectError> {
        let server_config = shin::server::config::Config {
            source: match config.0.server_cert_chain.take() {
                Some(chain_der) => CertSource::X509 {
                    chain_der,
                    signing_key,
                },
                None => CertSource::RawPublicKey { signing_key },
            },
            alpn_protocols: take(&mut config.0.alpn_protocols),
            ticket_keys: config.0.ticket_secret.take().map(TicketKeys::single),
        };
        server_config
            .validate()
            .map_err(|_| ConnectError::InvalidConfig)?;
        Ok(server_config)
    }

    pub(crate) fn new_server_connection(
        ids: server::Ids,
        config: ValidatedConfig,
    ) -> Result<Self, ConnectError> {
        let server::Ids {
            initial_dcid,
            local_cid,
            peer_cid,
            tp_original_dcid,
            retry_scid,
        } = ids;
        Self::new_with(
            initial_dcid,
            local_cid,
            tp_original_dcid,
            retry_scid,
            config.into_inner(),
            SideSetup::Server { peer_cid },
        )
    }

    fn new_with(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        tp_original_dcid: Vec<u8>,
        retry_scid: Option<Vec<u8>>,
        config: Config,
        side_setup: SideSetup,
    ) -> Result<Self, ConnectError> {
        if initial_dcid.len() > 20 || local_cid.len() > 20 || tp_original_dcid.len() > 20 {
            return Err(ConnectError::InvalidConfig);
        }
        let Config {
            transport_params: mut user_tp,
            datagram_congestion_control,
            pending_datagrams_capacity,
            incoming_datagrams_capacity,
            stream_events_capacity,
            packet_journal_capacity,
            crypto_journal_capacity,
            control_journal_capacity,
            stream_journal_capacity,
            cid_prefix,
            stateless_reset_secret,
            require_address_validation: _,
            retry_token_secret: _,
            ticket_secret: _,
            resumption,
            enable_early_data,
            resumption_peer_tp,
            alpn_protocols,
            server_cert_chain: _,
            client_cert,
            max_pmtu,
        } = config;
        let secrets =
            InitialSecrets::from_dcid(&initial_dcid).map_err(|_| ConnectError::InvalidConfig)?;
        let local_idle = Duration::from_millis(user_tp.max_idle_timeout_ms);
        let local_max_data = user_tp.initial_max_data;
        let local_initial_max_stream_data_bidi_local = user_tp.initial_max_stream_data_bidi_local;
        let local_initial_max_stream_data_bidi_remote = user_tp.initial_max_stream_data_bidi_remote;
        let local_initial_max_stream_data_uni = user_tp.initial_max_stream_data_uni;
        let local_initial_max_streams_bidi = user_tp.initial_max_streams_bidi;
        let local_initial_max_streams_uni = user_tp.initial_max_streams_uni;
        let local_active_connection_id_limit = user_tp.active_connection_id_limit;

        let (
            side,
            is_client,
            peer_cid,
            peer_first_scid,
            peer_address_validated,
            initial_w,
            initial_r,
        ) = match side_setup {
            SideSetup::Client { server_pubkey } => {
                user_tp.stateless_reset_token = None;
                let tp_bytes = Self::local_tp_bytes(
                    true,
                    &local_cid,
                    &tp_original_dcid,
                    retry_scid.as_deref(),
                    user_tp,
                )?;
                let cfg = client::config::Config {
                    verifier: Verifier::RawPublicKey {
                        expected_pubkey: server_pubkey,
                    },
                    transport_params: tp_bytes,
                    alpn_protocols,
                    resumption,
                    enable_early_data,
                };
                let mut client = Client::with_workspace(
                    cfg,
                    WallClock::now_millis as TlsClock,
                    shin::wire::handshake::workspace::HandshakeWorkspace::for_client(),
                )
                .map_err(ConnectError::InvalidTlsConfig)?;
                if let Some(source) = client_cert {
                    let source = source
                        .try_into_template()
                        .map_err(ConnectError::InvalidTlsConfig)?;
                    client
                        .set_client_cert_template(source)
                        .map_err(|_| ConnectError::Tls)?;
                }
                (
                    SideKind::Client(Box::new(client)),
                    true,
                    initial_dcid.clone(),
                    None,
                    true,
                    PacketProtection::aes_128(
                        &PacketKeys::aes_128(&secrets.client)
                            .map_err(|_| ConnectError::InvalidConfig)?,
                    )
                    .map_err(|_| ConnectError::InvalidConfig)?,
                    PacketProtection::aes_128(
                        &PacketKeys::aes_128(&secrets.server)
                            .map_err(|_| ConnectError::InvalidConfig)?,
                    )
                    .map_err(|_| ConnectError::InvalidConfig)?,
                )
            }
            SideSetup::Server { peer_cid } => {
                user_tp.stateless_reset_token =
                    stateless_reset_secret.map(|s| StatelessResetSecret(s).token_for(&local_cid));
                let tp_bytes = Self::local_tp_bytes(
                    false,
                    &local_cid,
                    &tp_original_dcid,
                    retry_scid.as_deref(),
                    user_tp,
                )?;
                let cfg = shin::server::config::ConnectionConfig {
                    transport_params: tp_bytes,
                };
                let clock = WallClock::now_millis as TlsClock;
                let server = Server::with_workspace(
                    cfg,
                    clock,
                    shin::wire::handshake::workspace::HandshakeWorkspace::for_server(),
                );
                (
                    SideKind::Server(Box::new(server)),
                    false,
                    peer_cid.clone(),
                    Some(peer_cid),
                    false,
                    PacketProtection::aes_128(
                        &PacketKeys::aes_128(&secrets.server)
                            .map_err(|_| ConnectError::InvalidConfig)?,
                    )
                    .map_err(|_| ConnectError::InvalidConfig)?,
                    PacketProtection::aes_128(
                        &PacketKeys::aes_128(&secrets.client)
                            .map_err(|_| ConnectError::InvalidConfig)?,
                    )
                    .map_err(|_| ConnectError::InvalidConfig)?,
                )
            }
        };

        let mut local_cids = BTreeMap::new();
        local_cids.insert(0, local_cid.clone());
        let mut peer_cids = BTreeMap::new();
        peer_cids.insert(0, (peer_cid.clone(), [0u8; 16]));
        let spaces: [PnSpace; 3] = Default::default();
        let egress = EgressHot {
            peer_cid,
            initial_w: Some(initial_w),
            handshake_w: None,
            app_w: None,
            zero_rtt_w: None,
            spaces,
            rtt: RttTracker::default(),
            pto_count: 0,
            loss_timer: None,
            pto_probe_allowance: 0,
            pto_probe_epoch: None,
            scratch_pending: Vec::with_capacity(STREAM_SCHEDULE_CAPACITY),
            send_schedule: send::Schedule::new(),
            packet_journals: journal::Table::new(
                packet_journal_capacity,
                control_journal_capacity,
                stream_journal_capacity,
            ),
            crypto_deliveries: delivery::Tracker::new(crypto_journal_capacity),
            stream_deliveries: delivery::Tracker::new(stream_journal_capacity),
            pending_crypto_initial: Vec::new(),
            pending_crypto_handshake: Vec::new(),
            pending_crypto_app: Vec::new(),
            pending_datagrams: VecDeque::new(),
            streams_send: send::Map::default(),
            recycled_send_streams: Vec::new(),
            peer_max_data: 0,
            peer_total_sent: 0,
            pending_close: None,
            cc: NewReno::default(),
            pacer: Pacer::new(Instant::now()),
            pmtud: Pmtud::new(max_pmtu),
            packet_ceiling: usize::try_from(max_pmtu).unwrap_or(usize::MAX),
            pmtud_probe_pn: None,
            datagram_congestion_control,
            pending_datagrams_capacity,
            last_activity: Instant::now(),
            amplification_received: 0,
            amplification_sent: 0,
            state: State::Handshaking,
            sent_initial: false,
            handshake_confirmed: false,
            ack_eliciting_sent_since_last_receive: false,
            peer_address_validated,
        };

        let mut conn = Self {
            egress,
            control: control::Pending::new(control_journal_capacity),
            side,
            is_client,
            scratch_frames: Vec::with_capacity(MAX_DATAGRAM_SIZE as usize),
            scratch_header: Vec::with_capacity(128),
            scratch_parsed_frames: Vec::with_capacity(32),
            local_cid,
            original_dcid: initial_dcid,
            peer_first_scid,
            initial_r: Some(initial_r),
            handshake_r: None,
            app_r: None,
            zero_rtt_r: None,
            pending_synth_eod: false,
            incoming_datagrams: VecDeque::new(),
            incoming_datagrams_capacity,
            peer_transport_params_raw: None,
            peer_transport_params: None,
            local_max_idle_timeout: local_idle,
            cid_prefix,
            stateless_reset_secret,
            stateless_reset_received: false,
            outstanding_path_challenges: Vec::new(),
            validated_path_tokens: Vec::new(),
            local_cids,
            peer_cids,
            local_active_connection_id_limit,
            next_local_cid_seq: 1,
            cids_to_register: Vec::new(),
            auto_issued: false,
            retry_token: Vec::new(),
            retry_processed: false,
            streams_recv: BTreeMap::new(),
            retired_streams: retired::Streams::default(),
            stream_events: VecDeque::new(),
            pending_stream_events: BTreeMap::new(),
            stream_events_capacity,
            next_local_bidi_stream: if is_client { 0 } else { 1 },
            next_local_uni_stream: if is_client { 2 } else { 3 },
            peer_opened_streams: peer::Streams::default(),
            local_max_streams: [
                local_initial_max_streams_bidi,
                local_initial_max_streams_uni,
            ],
            initial_max_streams: [
                local_initial_max_streams_bidi,
                local_initial_max_streams_uni,
            ],
            closed_peer_streams: [0; 2],
            peer_max_streams: [0; 2],
            opened_local_streams: [0; 2],
            local_max_data,
            conn_recv_total: 0,
            local_max_stream_data: BTreeMap::new(),
            local_initial_max_stream_data_bidi_local,
            local_initial_max_stream_data_bidi_remote,
            local_initial_max_stream_data_uni,
            received_tickets: VecDeque::new(),
            received_ticket_bytes: 0,
            pending_resumption_psk: None,
            recv_crypto: from_fn(|_| reassembly::Crypto::default()),
        };
        if let Some(tp) = resumption_peer_tp {
            conn.egress.peer_max_data = tp.initial_max_data;
            conn.peer_max_streams = [tp.initial_max_streams_bidi, tp.initial_max_streams_uni];
            conn.peer_transport_params = Some(tp);
        }
        Ok(conn)
    }

    fn start_client_handshake(&mut self) -> Result<(), ConnectError> {
        self.drive_shin(|side, events| match side {
            SideKind::Client(client) => client.start_into(events),
            SideKind::Server(_) => Err(shin::connection::Error::BadConfig.into()),
        })
        .map_err(|_| ConnectError::Tls)
    }

    pub(crate) fn is_client(&self) -> bool {
        self.is_client
    }

    /// Receives and decrypts one datagram in place.
    ///
    /// The contents of `wire` are unspecified after this call.
    pub fn recv_packet(&mut self, wire: &mut [u8], now: Instant) -> Result<(), Error> {
        self.recv_packet_with(wire, now, &mut |side, epoch, data, events| {
            side.read_client(epoch, data, events)
        })
    }

    pub(crate) fn recv_packet_server<G, V>(
        &mut self,
        wire: &mut [u8],
        now: Instant,
        shard: &mut Shard<G, V>,
    ) -> Result<(), Error>
    where
        G: EarlyDataGuard,
        V: ClientCertVerifier,
    {
        self.recv_packet_with(wire, now, &mut |side, epoch, data, events| {
            side.read_server(epoch, data, shard, events)
        })
    }

    fn recv_packet_with<R>(
        &mut self,
        wire: &mut [u8],
        now: Instant,
        read: &mut R,
    ) -> Result<(), Error>
    where
        R: FnMut(
            &mut SideKind,
            shin::connection::Epoch,
            &[u8],
            &mut ShinEvents<'_>,
        ) -> Result<(), DriveError<Error>>,
    {
        if !self.egress.peer_address_validated {
            self.egress.amplification_received = self
                .egress
                .amplification_received
                .saturating_add(wire.len() as u64);
        }
        if self.try_receive_stateless_reset(wire) {
            return Ok(());
        }
        let mut rest = wire;
        while !rest.is_empty() {
            let first = *rest.first().ok_or(Error::HeaderDecode)?;
            if first & 0x80 == 0 {
                if first & 0x40 == 0 {
                    break;
                }
                self.recv_one_rtt(rest, now, read)?;
                break;
            }
            if first & 0x30 == 0x30 {
                self.recv_retry(rest)?;
                break;
            }
            let plen = match first & 0x30 {
                0x00 => {
                    let p = InitialHeader::decode_pre_hp(rest).map_err(|_| Error::HeaderDecode)?;
                    p.pn_offset + p.length
                }
                0x10 => {
                    let p = ZeroRttHeader::decode_pre_hp(rest).map_err(|_| Error::HeaderDecode)?;
                    p.pn_offset + p.length
                }
                _ => {
                    let p =
                        HandshakeHeader::decode_pre_hp(rest).map_err(|_| Error::HeaderDecode)?;
                    p.pn_offset + p.length
                }
            };
            if plen == 0 || plen > rest.len() {
                return Err(Error::HeaderDecode);
            }
            let (packet, tail) = rest.split_at_mut(plen);
            match first & 0x30 {
                0x00 => self.recv_initial(packet, now, read)?,
                0x10 => self.recv_zero_rtt(packet, now, read)?,
                _ => self.recv_handshake(packet, now, read)?,
            }
            rest = tail;
        }
        Ok(())
    }

    fn recv_zero_rtt<R>(&mut self, wire: &mut [u8], now: Instant, read: &mut R) -> Result<(), Error>
    where
        R: FnMut(
            &mut SideKind,
            shin::connection::Epoch,
            &[u8],
            &mut ShinEvents<'_>,
        ) -> Result<(), DriveError<Error>>,
    {
        let Some(zr) = self.zero_rtt_r.as_ref() else {
            return Ok(());
        };
        let prefix = ZeroRttHeader::decode_pre_hp(wire).map_err(|_| Error::HeaderDecode)?;
        let expected = self.egress.spaces[Epoch::Application as usize].expected_pn();
        let (pn, body) = zr
            .decrypt_long_in_place(wire, prefix.pn_offset, expected)
            .map_err(|_| Error::PacketDecrypt)?;
        self.process_packet_body(Epoch::Application, pn, &wire[body], now, read)
    }

    fn recv_retry(&mut self, wire: &[u8]) -> Result<(), Error> {
        if !self.is_client || self.retry_processed {
            return Ok(());
        }
        if self.handshake_r.is_some() || self.peer_first_scid.is_some() {
            return Ok(());
        }
        let pkt = RetryPacket::decode(wire).map_err(|_| Error::HeaderDecode)?;
        if !pkt.verify_integrity(&self.original_dcid) {
            return Ok(());
        }
        let active_ceiling = self
            .egress
            .packet_ceiling
            .min(usize::try_from(self.path_mtu()).unwrap_or(usize::MAX));
        let payload_limit = Self::initial_payload_limit_for(
            pkt.scid.len(),
            self.local_cid.len(),
            pkt.token.len(),
            active_ceiling,
        );
        let ch_bytes: Vec<u8> = {
            let space = &self.egress.spaces[Epoch::Initial as usize];
            let mut ranges =
                Vec::with_capacity(space.crypto_inflight.len() + space.crypto_retransmit.len() + 1);
            for (&offset, (data, _pn)) in &space.crypto_inflight {
                ranges.push((offset, data.as_slice()));
            }
            for (offset, data) in &space.crypto_retransmit {
                ranges.push((*offset, data.as_slice()));
            }
            if !self.egress.pending_crypto_initial.is_empty() {
                ranges.push((
                    space.crypto_next_offset,
                    self.egress.pending_crypto_initial.as_slice(),
                ));
            }
            ranges.sort_unstable_by_key(|range| range.0);
            let total = ranges.iter().fold(0u64, |end, (offset, data)| {
                end.max(offset.saturating_add(data.len() as u64))
            });
            let Ok(total) = usize::try_from(total) else {
                self.egress.state = State::Closed;
                return Err(Error::PacketCeiling);
            };
            let mut acc = Vec::with_capacity(total);
            for (offset, data) in ranges {
                let Ok(offset) = usize::try_from(offset) else {
                    self.egress.state = State::Closed;
                    return Err(Error::PacketCeiling);
                };
                if offset > acc.len() {
                    self.egress.state = State::Closed;
                    return Err(Error::Tls);
                }
                let overlap = acc.len().saturating_sub(offset).min(data.len());
                acc.extend_from_slice(&data[overlap..]);
            }
            acc
        };
        if active_ceiling < MIN_INITIAL_LEN
            || ch_bytes.is_empty()
            || Self::crypto_data_limit(0, payload_limit) == 0
        {
            self.egress.state = State::Closed;
            return Err(Error::PacketCeiling);
        }
        let new_secrets = InitialSecrets::from_dcid(&pkt.scid).map_err(|_| Error::Tls)?;
        self.discard_initial_keys();
        self.egress.initial_w = Some(
            PacketProtection::aes_128(
                &PacketKeys::aes_128(&new_secrets.client).map_err(|_| Error::Tls)?,
            )
            .map_err(|_| Error::Tls)?,
        );
        self.initial_r = Some(
            PacketProtection::aes_128(
                &PacketKeys::aes_128(&new_secrets.server).map_err(|_| Error::Tls)?,
            )
            .map_err(|_| Error::Tls)?,
        );
        self.egress.peer_cid = pkt.scid.clone();
        if let Some(entry) = self.peer_cids.get_mut(&0) {
            entry.0 = pkt.scid;
        }
        self.egress.pending_crypto_initial = ch_bytes;
        self.retry_token = pkt.token;
        self.retry_processed = true;
        self.egress.sent_initial = false;
        Ok(())
    }

    fn is_stateless_reset(&self, wire: &[u8]) -> bool {
        if wire.len() < 21 {
            return false;
        }
        let tail = &wire[wire.len() - 16..];
        let mut buf = [0u8; 16];
        buf.copy_from_slice(tail);
        let mut matched = subtle::Choice::from(0);
        for (_cid, token) in self.peer_cids.values() {
            if *token == [0u8; 16] {
                continue;
            }
            matched |= buf[..].ct_eq(&token[..]);
        }
        bool::from(matched)
    }

    pub(crate) fn try_receive_stateless_reset(&mut self, wire: &[u8]) -> bool {
        if self.egress.state != State::Established || !self.is_stateless_reset(wire) {
            return false;
        }
        self.egress.state = State::Closed;
        self.stateless_reset_received = true;
        true
    }

    pub fn was_stateless_reset(&self) -> bool {
        self.stateless_reset_received
    }

    pub fn send_path_challenge(&mut self, data: [u8; 8]) {
        if self.egress.state == State::Established {
            self.control.queue_path_challenge(
                data,
                &self.outstanding_path_challenges,
                MAX_PATH_TOKENS,
            );
        }
    }

    pub fn path_validated(&self, token: &[u8; 8]) -> bool {
        self.validated_path_tokens.contains(token)
    }

    pub fn stream_recv(&mut self, stream_id: u64, dst: &mut Vec<u8>) -> usize {
        let (n, consumed) = match self.streams_recv.get_mut(&stream_id) {
            Some(stream) => {
                let n = stream.read(dst);
                (n, stream.is_eof() && stream.reset_error().is_none())
            }
            None => (0, false),
        };
        self.release_stream_receive_credit(stream_id, n);
        if consumed {
            self.retire_recv(stream_id);
        }
        n
    }

    /// Transfers the stream's currently contiguous receive allocation to the caller.
    ///
    /// Returns `None` when the stream has no newly readable bytes. Consuming bytes
    /// through this method releases flow-control credit exactly like [`Self::stream_recv`].
    pub fn stream_recv_owned(&mut self, stream_id: u64) -> Option<Vec<u8>> {
        let (bytes, consumed) = match self.streams_recv.get_mut(&stream_id) {
            Some(stream) => {
                let bytes = stream.read_owned();
                (bytes, stream.is_eof() && stream.reset_error().is_none())
            }
            None => (None, false),
        };
        if let Some(bytes) = &bytes {
            self.release_stream_receive_credit(stream_id, bytes.len());
        }
        if consumed {
            self.retire_recv(stream_id);
        }
        bytes
    }

    fn retire_recv(&mut self, stream_id: u64) {
        let newly_closed = !self.recv_side_closed(stream_id);
        self.streams_recv.remove(&stream_id);
        self.retired_streams.retire_recv(stream_id);
        self.local_max_stream_data.remove(&stream_id);
        self.control.remove_max_stream_data(stream_id);
        if newly_closed {
            let uni = stream_id & 0x2 != 0;
            let peer_initiated = (stream_id & 0x1 == 0) != self.is_client;
            if peer_initiated && (uni || self.send_side_closed(stream_id)) {
                self.release_peer_stream_credit(uni);
            }
        }
    }

    fn retire_recv_if_consumed(&mut self, stream_id: u64) {
        let consumed = self
            .streams_recv
            .get(&stream_id)
            .is_some_and(|stream| stream.is_eof() && stream.reset_error().is_none());
        if consumed {
            self.retire_recv(stream_id);
        }
    }

    fn retire_send(&mut self, stream_id: u64) {
        self.control.retire_send_stream(stream_id);
        let Some(mut entry) = self.egress.streams_send.remove(&stream_id) else {
            return;
        };
        if entry.unschedule() {
            self.egress.send_schedule.deactivate();
        }
        entry.stream.recycle();
        if self.egress.recycled_send_streams.len() < MAX_RECYCLED_SEND_STREAMS {
            self.egress.recycled_send_streams.push(entry.stream);
        }
        let is_uni = stream_id & 0x2 != 0;
        let we_initiated = (stream_id & 0x1 == 0) == self.is_client;
        if !is_uni && !we_initiated {
            let recv_closed = self.recv_side_closed(stream_id);
            self.retired_streams.retire_peer_bidi_send(stream_id);
            if recv_closed {
                self.release_peer_stream_credit(false);
            }
        }
        self.retire_recv_if_consumed(stream_id);
    }

    fn release_peer_stream_credit(&mut self, uni: bool) {
        let kind = usize::from(uni);
        self.closed_peer_streams[kind] = self.closed_peer_streams[kind].saturating_add(1);
        let threshold = (self.initial_max_streams[kind] / 2).max(1);
        if self.closed_peer_streams[kind] < threshold {
            return;
        }
        let next = self.local_max_streams[kind]
            .saturating_add(self.closed_peer_streams[kind])
            .min(MAX_STREAM_COUNT);
        self.closed_peer_streams[kind] = 0;
        if next > self.local_max_streams[kind] {
            self.local_max_streams[kind] = next;
            self.control.queue_max_streams(uni, next);
        }
    }

    fn release_stream_receive_credit(&mut self, stream_id: u64, n: usize) {
        if n > 0 {
            let bump = n as u64;
            self.local_max_data = self.local_max_data.saturating_add(bump);
            let initial = self.local_initial_stream_credit(stream_id);
            let entry = self
                .local_max_stream_data
                .entry(stream_id)
                .or_insert(initial);
            *entry = entry.saturating_add(bump);
            self.control.queue_max_data(self.local_max_data);
            self.control.queue_max_stream_data(stream_id, *entry);
        }
    }

    fn local_stream_recv_limit(&self, id: u64) -> u64 {
        match self.local_max_stream_data.get(&id) {
            Some(limit) => *limit,
            None => self.local_initial_stream_credit(id),
        }
    }

    fn validate_stream_access(&self, id: u64, access: StreamAccess) -> Result<(), Error> {
        let is_uni = id & 0x2 != 0;
        let initiator_is_client = id & 0x1 == 0;
        let we_initiated = initiator_is_client == self.is_client;
        if we_initiated {
            let opened = if is_uni {
                id < self.next_local_uni_stream
            } else {
                id < self.next_local_bidi_stream
            };
            if !opened || is_uni && matches!(access, StreamAccess::Receive) {
                return Err(Error::ProtocolViolation);
            }
        } else {
            if !self.peer_opened_streams.contains(id)
                || is_uni && matches!(access, StreamAccess::Send)
            {
                return Err(Error::ProtocolViolation);
            }
        }
        Ok(())
    }

    /// Validates a frame that can create a peer-initiated stream. Opening one
    /// stream also opens every lower stream of the same type (RFC 9000 §3.2).
    fn validate_or_open_peer_stream(&mut self, id: u64, access: StreamAccess) -> Result<(), Error> {
        let is_uni = id & 0x2 != 0;
        let we_initiated = (id & 0x1 == 0) == self.is_client;
        if we_initiated {
            return self.validate_stream_access(id, access);
        }
        if is_uni && matches!(access, StreamAccess::Send)
            || id >> 2 >= self.local_max_streams[usize::from(is_uni)]
        {
            return Err(Error::ProtocolViolation);
        }
        self.peer_opened_streams.open(id);
        Ok(())
    }

    fn validate_stream_operation(
        &self,
        id: u64,
        access: StreamAccess,
    ) -> Result<(), stream::Error> {
        if id > VarInt::MAX {
            return Err(stream::Error::IdOverflow);
        }
        let early_data = self.is_client
            && self.egress.state == State::Handshaking
            && self.egress.zero_rtt_w.is_some()
            && self.peer_transport_params.is_some();
        if self.egress.state != State::Established && !early_data {
            return Err(stream::Error::NotEstablished);
        }
        self.validate_stream_access(id, access)
            .map_err(|_| stream::Error::InvalidStream)?;
        Ok(())
    }

    fn local_initial_stream_credit(&self, id: u64) -> u64 {
        let is_uni = id & 0x2 != 0;
        let initiator_is_client = id & 0x1 == 0;
        let we_initiated = initiator_is_client == self.is_client;
        if is_uni {
            if we_initiated {
                0
            } else {
                self.local_initial_max_stream_data_uni
            }
        } else if we_initiated {
            self.local_initial_max_stream_data_bidi_local
        } else {
            self.local_initial_max_stream_data_bidi_remote
        }
    }

    pub fn stream_recv_eof(&self, stream_id: u64) -> bool {
        self.streams_recv
            .get(&stream_id)
            .is_some_and(RecvStream::is_eof)
            || self.recv_side_closed(stream_id)
    }

    pub fn stream_recv_fin_received(&self, stream_id: u64) -> bool {
        self.streams_recv
            .get(&stream_id)
            .and_then(RecvStream::final_size)
            .is_some()
            || self.recv_side_closed(stream_id)
    }

    fn mutate_send_stream<R>(
        &mut self,
        stream_id: u64,
        mutate: impl FnOnce(&mut SendStream) -> R,
    ) -> R {
        let peer_transport_params = self.peer_transport_params.as_ref();
        let is_client = self.is_client;
        let EgressHot {
            streams_send,
            recycled_send_streams,
            send_schedule,
            ..
        } = &mut self.egress;
        let entry = streams_send.entry(stream_id).or_insert_with(|| {
            send::Entry::new(
                recycled_send_streams.pop().unwrap_or_default(),
                Self::peer_initial_stream_credit(peer_transport_params, is_client, stream_id),
            )
        });
        let result = mutate(&mut entry.stream);
        if entry.has_pending() {
            if let Some(generation) = entry.schedule() {
                send_schedule.activate(stream_id, generation);
            }
        } else if entry.unschedule() {
            send_schedule.deactivate();
        }
        result
    }

    pub fn stream_send(&mut self, stream_id: u64, data: &[u8]) -> Result<(), stream::Error> {
        if self.validate_stream_send(stream_id)? {
            let written = self.mutate_send_stream(stream_id, |stream| stream.write(data));
            if !written {
                return Err(stream::Error::ValueOutOfRange);
            }
        }
        Ok(())
    }

    pub fn stream_send_buffer(
        &mut self,
        stream_id: u64,
        data: SendBuffer,
    ) -> Result<(), stream::Error> {
        if self.validate_stream_send(stream_id)? {
            let written = self.mutate_send_stream(stream_id, |stream| stream.write_buffer(data));
            if !written {
                return Err(stream::Error::ValueOutOfRange);
            }
        }
        Ok(())
    }

    /// Appends a segmented write and its FIN with one stream lookup.
    pub fn stream_send_parts(
        &mut self,
        stream_id: u64,
        first: SendBuffer,
        second: Option<SendBuffer>,
        fin: bool,
    ) -> Result<(), stream::Error> {
        if !self.validate_stream_send(stream_id)? {
            return Ok(());
        }
        let written = self.mutate_send_stream(stream_id, |stream| {
            let written = stream.write_buffer(first)
                && second.is_none_or(|buffer| stream.write_buffer(buffer));
            if written && fin {
                stream.mark_fin();
            }
            written
        });
        if !written {
            return Err(stream::Error::ValueOutOfRange);
        }
        Ok(())
    }

    /// The receive half of `id` was fully consumed and its state dropped;
    /// anything else arriving for it is a stale retransmit.
    fn recv_side_closed(&self, id: u64) -> bool {
        self.retired_streams.recv_contains(id)
    }

    /// The send half of `id` was opened, fully acknowledged, and retired.
    /// Only meaningful once stream access validation has passed.
    fn send_side_closed(&self, id: u64) -> bool {
        let is_uni = id & 0x2 != 0;
        let we_initiated = (id & 0x1 == 0) == self.is_client;
        if we_initiated {
            // Live local streams always hold one entry, created at open and
            // removed only after the send half is acknowledged.
            let opened = if is_uni {
                id < self.next_local_uni_stream
            } else {
                id < self.next_local_bidi_stream
            };
            opened && !self.egress.streams_send.contains_key(&id)
        } else {
            !is_uni && self.retired_streams.peer_bidi_send_contains(id)
        }
    }

    fn validate_stream_send(&self, stream_id: u64) -> Result<bool, stream::Error> {
        self.validate_stream_operation(stream_id, StreamAccess::Send)?;
        if self.send_side_closed(stream_id)
            || self
                .egress
                .streams_send
                .get(&stream_id)
                .is_some_and(|stream| stream.blocked())
        {
            return Ok(false);
        }
        Ok(true)
    }

    pub fn stream_send_fin(&mut self, stream_id: u64) -> Result<(), stream::Error> {
        self.validate_stream_operation(stream_id, StreamAccess::Send)?;
        if self.send_side_closed(stream_id)
            || self
                .egress
                .streams_send
                .get(&stream_id)
                .is_some_and(|stream| stream.blocked())
        {
            return Ok(());
        }
        self.mutate_send_stream(stream_id, SendStream::mark_fin);
        Ok(())
    }

    pub fn stream_reset(&mut self, stream_id: u64, error_code: u64) -> Result<(), stream::Error> {
        self.validate_stream_operation(stream_id, StreamAccess::Send)?;
        if error_code > VarInt::MAX {
            return Err(stream::Error::ValueOutOfRange);
        }
        if self.send_side_closed(stream_id) {
            // Everything was delivered and acknowledged; there is no send
            // state left to reset (RFC 9000 §3.1 "Data Recvd").
            return Ok(());
        }
        let final_size = self
            .egress
            .streams_send
            .get(&stream_id)
            .map(|stream| stream.next_offset())
            .unwrap_or(0);
        self.cancel_stream_deliveries(stream_id);
        self.mutate_send_stream(stream_id, SendStream::mark_reset_sent);
        self.control
            .queue_reset_stream(stream_id, error_code, final_size);
        Ok(())
    }

    pub fn stream_stop_sending(
        &mut self,
        stream_id: u64,
        error_code: u64,
    ) -> Result<(), stream::Error> {
        self.validate_stream_operation(stream_id, StreamAccess::Receive)?;
        if error_code > VarInt::MAX {
            return Err(stream::Error::ValueOutOfRange);
        }
        if self.recv_side_closed(stream_id) {
            return Ok(());
        }
        self.control.queue_stop_sending(stream_id, error_code);
        Ok(())
    }

    pub fn stream_send_stopped(&self, stream_id: u64) -> Option<u64> {
        self.egress
            .streams_send
            .get(&stream_id)
            .and_then(|s| s.stop_sending_error())
    }

    pub fn open_bidi_stream(&mut self) -> Result<u64, stream::Error> {
        self.open_local_stream(false)
    }

    pub fn open_uni_stream(&mut self) -> Result<u64, stream::Error> {
        self.open_local_stream(true)
    }

    pub fn poll_stream_event(&mut self) -> Option<stream::Event> {
        let event = self.stream_events.pop_front()?;
        self.pending_stream_events.remove(&event.key());
        Some(event)
    }

    pub fn has_stream_events(&self) -> bool {
        !self.stream_events.is_empty()
    }

    fn push_stream_event(&mut self, event: stream::Event) -> Result<(), Error> {
        let key = event.key();
        if self.pending_stream_events.contains_key(&key) {
            return Ok(());
        }
        if self.stream_events.len() == self.stream_events_capacity {
            return Err(Error::EventCapacity);
        }
        self.pending_stream_events.insert(key, ());
        self.stream_events.push_back(event);
        Ok(())
    }

    fn open_local_stream(&mut self, uni: bool) -> Result<u64, stream::Error> {
        let early_data = self.is_client
            && self.egress.state == State::Handshaking
            && self.egress.zero_rtt_w.is_some()
            && self.peer_transport_params.is_some();
        if self.egress.state != State::Established && !early_data {
            return Err(stream::Error::NotEstablished);
        }
        if self.peer_transport_params.is_none() {
            return Err(stream::Error::NotEstablished);
        }
        let kind = usize::from(uni);
        let next = if uni {
            &mut self.next_local_uni_stream
        } else {
            &mut self.next_local_bidi_stream
        };
        let opened = &mut self.opened_local_streams[kind];
        let limit = self.peer_max_streams[kind];
        if *opened >= limit {
            return Err(stream::Error::PeerLimit);
        }
        let id = *next;
        *next = next.checked_add(4).ok_or(stream::Error::IdOverflow)?;
        *opened = opened.saturating_add(1);
        self.mutate_send_stream(id, |_| ());
        Ok(id)
    }

    fn recv_initial<R>(&mut self, wire: &mut [u8], now: Instant, read: &mut R) -> Result<(), Error>
    where
        R: FnMut(
            &mut SideKind,
            shin::connection::Epoch,
            &[u8],
            &mut ShinEvents<'_>,
        ) -> Result<(), DriveError<Error>>,
    {
        let Some(initial_r) = self.initial_r.as_ref() else {
            return Ok(());
        };
        let prefix = InitialHeader::decode_pre_hp(wire).map_err(|_| Error::HeaderDecode)?;
        if self.is_client && self.peer_first_scid.is_none() {
            self.peer_first_scid = Some(prefix.scid.clone());
            self.egress.peer_cid = prefix.scid;
        }
        let expected = self.egress.spaces[Epoch::Initial as usize].expected_pn();
        let (pn, body) = initial_r
            .decrypt_long_in_place(wire, prefix.pn_offset, expected)
            .map_err(|_| Error::PacketDecrypt)?;
        self.process_packet_body(Epoch::Initial, pn, &wire[body], now, read)
    }

    fn recv_handshake<R>(
        &mut self,
        wire: &mut [u8],
        now: Instant,
        read: &mut R,
    ) -> Result<(), Error>
    where
        R: FnMut(
            &mut SideKind,
            shin::connection::Epoch,
            &[u8],
            &mut ShinEvents<'_>,
        ) -> Result<(), DriveError<Error>>,
    {
        let Some(hr) = self.handshake_r.as_ref() else {
            return Ok(());
        };
        let prefix = HandshakeHeader::decode_pre_hp(wire).map_err(|_| Error::HeaderDecode)?;
        let expected = self.egress.spaces[Epoch::Handshake as usize].expected_pn();
        let (pn, body) = hr
            .decrypt_long_in_place(wire, prefix.pn_offset, expected)
            .map_err(|_| Error::PacketDecrypt)?;
        self.egress.peer_address_validated = true;
        self.process_packet_body(Epoch::Handshake, pn, &wire[body], now, read)
    }

    fn recv_one_rtt<R>(&mut self, wire: &mut [u8], now: Instant, read: &mut R) -> Result<(), Error>
    where
        R: FnMut(
            &mut SideKind,
            shin::connection::Epoch,
            &[u8],
            &mut ShinEvents<'_>,
        ) -> Result<(), DriveError<Error>>,
    {
        let Some(ar) = self.app_r.as_ref() else {
            return Ok(());
        };
        let pn_offset = ShortHeader::pn_offset_for(self.local_cid.len());
        let expected = self.egress.spaces[Epoch::Application as usize].expected_pn();
        let (pn, body) = ar
            .decrypt_short_in_place(wire, pn_offset, expected)
            .map_err(|_| Error::PacketDecrypt)?;
        self.process_packet_body(Epoch::Application, pn, &wire[body], now, read)
    }

    fn process_packet_body<R>(
        &mut self,
        epoch: Epoch,
        pn: u64,
        body: &[u8],
        now: Instant,
        read: &mut R,
    ) -> Result<(), Error>
    where
        R: FnMut(
            &mut SideKind,
            shin::connection::Epoch,
            &[u8],
            &mut ShinEvents<'_>,
        ) -> Result<(), DriveError<Error>>,
    {
        if self.egress.spaces[epoch as usize].has_received(pn) {
            return Ok(());
        }

        let mut position = 0;
        let mut ack_eliciting = false;
        let body_start = body.as_ptr() as usize;
        let mut parsed_frames = take(&mut self.scratch_parsed_frames);
        parsed_frames.clear();
        let mut parse_error = None;
        while position < body.len() {
            if body[position] == TYPE_PADDING {
                position += body[position..]
                    .iter()
                    .take_while(|&&byte| byte == TYPE_PADDING)
                    .count();
                continue;
            }
            if parsed_frames.len() == MAX_FRAMES_PER_PACKET {
                parse_error = Some(Error::FrameDecode);
                break;
            }
            let decoded = crate::frame::decode::FrameDecoder::new(
                &body[position..],
                |data: &[u8]| {
                    let start = data.as_ptr() as usize - body_start;
                    start..start + data.len()
                },
                |ranges: &[u8], count| {
                    let start = ranges.as_ptr() as usize - body_start;
                    ParsedAckRanges {
                        bytes: start..start + ranges.len(),
                        count,
                    }
                },
            )
            .decode();
            let (frame, consumed) = match decoded {
                Ok(decoded) => decoded,
                Err(_) => {
                    parse_error = Some(Error::FrameDecode);
                    break;
                }
            };
            if consumed == 0 {
                parse_error = Some(Error::FrameDecode);
                break;
            }
            if !matches!(
                &frame,
                Frame::Ack { .. } | Frame::Padding | Frame::ConnectionClose { .. }
            ) {
                ack_eliciting = true;
            }
            parsed_frames.push(frame);
            position += consumed;
        }
        if let Some(error) = parse_error {
            parsed_frames.clear();
            self.scratch_parsed_frames = parsed_frames;
            return Err(error);
        }
        self.egress.spaces[epoch as usize].record_received(pn, ack_eliciting, now);

        let shin_epoch = match epoch {
            Epoch::Initial => shin::connection::Epoch::Plaintext,
            Epoch::Handshake => shin::connection::Epoch::Handshake,
            Epoch::Application => shin::connection::Epoch::Application,
        };
        let result = (|| {
            for parsed in parsed_frames.drain(..) {
                let f = parsed.map(
                    |range| &body[range],
                    |ranges| AckRanges::new(&body[ranges.bytes], ranges.count),
                );
                match f {
                    Frame::Crypto { offset, data } => {
                        let msgs = self.recv_crypto[epoch as usize].accept(offset.get(), data)?;
                        for msg in msgs {
                            if self.pending_synth_eod && epoch == Epoch::Handshake {
                                self.pending_synth_eod = false;
                                self.feed_shin(
                                    shin::connection::Epoch::EarlyData,
                                    &[0x05, 0x00, 0x00, 0x00],
                                    read,
                                )?;
                            }
                            self.feed_shin(shin_epoch, &msg, read)?;
                        }
                    }
                    Frame::Ack {
                        largest,
                        delay,
                        first_range,
                        additional_ranges,
                    } => {
                        let largest = largest.get();
                        let delay = delay.get();
                        let first_range = first_range.get();
                        if largest >= self.egress.spaces[epoch as usize].next_pn {
                            return Err(Error::ProtocolViolation);
                        }
                        let acked = if epoch == Epoch::Application {
                            let space = &mut self.egress.spaces[Epoch::Application as usize];
                            space.largest_acked =
                                Some(space.largest_acked.unwrap_or(0).max(largest));
                            Vec::new()
                        } else {
                            self.egress.spaces[epoch as usize].process_ack(
                                largest,
                                first_range,
                                additional_ranges
                                    .clone()
                                    .map(|(gap, range)| (gap.get(), range.get())),
                            )
                        };
                        self.ack(
                            epoch,
                            AckReceipt {
                                largest,
                                delay_microseconds: delay,
                                first_range,
                                additional_ranges,
                                packets: acked,
                            },
                            now,
                        );
                    }
                    Frame::Datagram { data, .. } if epoch == Epoch::Application => {
                        if self.incoming_datagrams.len() < self.incoming_datagrams_capacity {
                            self.incoming_datagrams.push_back(data.to_vec());
                        }
                    }
                    Frame::HandshakeDone if epoch == Epoch::Application && self.is_client => {
                        self.egress.handshake_confirmed = true;
                        self.discard_initial_keys();
                        self.discard_handshake_keys();
                    }
                    Frame::ConnectionClose { .. } => {
                        self.egress.state = State::Closed;
                    }
                    Frame::NewConnectionId {
                        sequence_number,
                        retire_prior_to,
                        connection_id,
                        stateless_reset_token,
                    } if epoch == Epoch::Application => {
                        let sequence_number = sequence_number.get();
                        let retire_prior_to = retire_prior_to.get();
                        if connection_id.is_empty()
                            || connection_id.len() > 20
                            || retire_prior_to > sequence_number
                        {
                            return Err(Error::ProtocolViolation);
                        }
                        if let Some(existing) = self.peer_cids.get(&sequence_number)
                            && existing != &(connection_id.to_vec(), stateless_reset_token)
                        {
                            return Err(Error::ProtocolViolation);
                        }
                        let to_retire: Vec<u64> = self
                            .peer_cids
                            .keys()
                            .copied()
                            .filter(|&s| s < retire_prior_to)
                            .collect();
                        let additional_retirements = to_retire
                            .iter()
                            .filter(|sequence| !self.control.contains_retirement(**sequence))
                            .count();
                        if self
                            .control
                            .retirement_count()
                            .saturating_add(additional_retirements)
                            > MAX_PENDING_RETIRE_CONNECTION_IDS
                        {
                            return Err(Error::ConnectionIdLimit);
                        }
                        for s in to_retire {
                            self.peer_cids.remove(&s);
                            self.control.retire_connection_id(s);
                        }
                        if !self.peer_cids.contains_key(&sequence_number) {
                            if self.peer_cids.len() as u64 >= self.local_active_connection_id_limit
                            {
                                return Err(Error::ConnectionIdLimit);
                            }
                            self.peer_cids.insert(
                                sequence_number,
                                (connection_id.to_vec(), stateless_reset_token),
                            );
                        }
                    }
                    Frame::RetireConnectionId { sequence_number }
                        if epoch == Epoch::Application =>
                    {
                        self.local_cids.remove(&sequence_number.get());
                    }
                    Frame::PathChallenge { data } if epoch == Epoch::Application => {
                        self.control.queue_path_response(data, MAX_PATH_TOKENS);
                    }
                    Frame::Stream {
                        stream_id,
                        offset,
                        fin,
                        data,
                        ..
                    } if epoch == Epoch::Application => {
                        let stream_id = stream_id.get();
                        let offset = offset.get();
                        self.validate_or_open_peer_stream(stream_id, StreamAccess::Receive)?;
                        // Retransmits for a retired stream must not
                        // resurrect state or re-run flow accounting.
                        if !self.recv_side_closed(stream_id) {
                            let new_end = offset.saturating_add(data.len() as u64);
                            let stream_limit = self.local_stream_recv_limit(stream_id);
                            if new_end > stream_limit {
                                return Err(Error::FlowControl);
                            }
                            let (prev_high, known_final) = self
                                .streams_recv
                                .get(&stream_id)
                                .map(|stream| (stream.highest_offset(), stream.final_size()))
                                .unwrap_or((0, None));
                            if known_final.is_some_and(|final_size| {
                                new_end > final_size || (fin && new_end != final_size)
                            }) || (fin && new_end < prev_high)
                            {
                                return Err(Error::FinalSize);
                            }
                            if new_end > prev_high {
                                let delta = new_end - prev_high;
                                let projected = self.conn_recv_total.saturating_add(delta);
                                if projected > self.local_max_data {
                                    return Err(Error::FlowControl);
                                }
                                self.conn_recv_total = projected;
                            }
                            let rs = self.streams_recv.entry(stream_id).or_default();
                            rs.insert(offset, data, fin)
                                .map_err(|_| Error::StreamBufferExceeded)?;
                            if !data.is_empty() {
                                self.push_stream_event(stream::Event::Data { stream_id })?;
                            }
                            if fin {
                                self.push_stream_event(stream::Event::Finished { stream_id })?;
                            }
                        }
                    }
                    Frame::MaxData { maximum_data }
                        if epoch == Epoch::Application
                            && maximum_data.get() > self.egress.peer_max_data =>
                    {
                        self.egress.peer_max_data = maximum_data.get();
                        self.control.data_credit_raised();
                    }
                    Frame::MaxStreamData {
                        stream_id,
                        maximum_stream_data,
                    } if epoch == Epoch::Application => {
                        let stream_id = stream_id.get();
                        let maximum_stream_data = maximum_stream_data.get();
                        self.validate_or_open_peer_stream(stream_id, StreamAccess::Send)?;
                        // Credit for a retired stream must be ignored, not
                        // re-inserted — otherwise stale MAX_STREAM_DATA
                        // resurrects (and unboundedly grows) the map.
                        if !self.send_side_closed(stream_id) {
                            self.mutate_send_stream(stream_id, |_| ());
                            if let Some(entry) = self.egress.streams_send.get_mut(&stream_id)
                                && entry.credit.raise(maximum_stream_data)
                            {
                                self.control.stream_credit_raised(stream_id);
                            }
                        }
                    }
                    Frame::DataBlocked { .. } if epoch == Epoch::Application => {}
                    Frame::StreamDataBlocked { stream_id, .. } if epoch == Epoch::Application => {
                        self.validate_or_open_peer_stream(stream_id.get(), StreamAccess::Receive)?;
                    }
                    Frame::ResetStream {
                        stream_id,
                        error_code,
                        final_size,
                    } if epoch == Epoch::Application => {
                        let stream_id = stream_id.get();
                        let error_code = error_code.get();
                        let final_size = final_size.get();
                        self.validate_or_open_peer_stream(stream_id, StreamAccess::Receive)?;
                        // A reset for a retired stream is a stale duplicate.
                        if !self.recv_side_closed(stream_id) {
                            if final_size > self.local_stream_recv_limit(stream_id) {
                                return Err(Error::FlowControl);
                            }
                            let (prev_high, known_final) = self
                                .streams_recv
                                .get(&stream_id)
                                .map(|stream| (stream.highest_offset(), stream.final_size()))
                                .unwrap_or((0, None));
                            if final_size < prev_high
                                || known_final.is_some_and(|known| known != final_size)
                            {
                                return Err(Error::FinalSize);
                            }
                            if final_size > prev_high {
                                let delta = final_size - prev_high;
                                let projected = self.conn_recv_total.saturating_add(delta);
                                if projected > self.local_max_data {
                                    return Err(Error::FlowControl);
                                }
                                self.conn_recv_total = projected;
                            }
                            let rs = self.streams_recv.entry(stream_id).or_default();
                            rs.reset(error_code, final_size);
                            self.push_stream_event(stream::Event::Reset {
                                stream_id,
                                error_code,
                            })?;
                            self.retire_recv(stream_id);
                        }
                    }
                    Frame::StopSending {
                        stream_id,
                        error_code,
                    } if epoch == Epoch::Application => {
                        let stream_id = stream_id.get();
                        let error_code = error_code.get();
                        self.validate_or_open_peer_stream(stream_id, StreamAccess::Send)?;
                        // A retired send stream has nothing left to stop;
                        // reviving it here would leak a streams_send entry.
                        if !self.send_side_closed(stream_id) {
                            let final_size = self
                                .egress
                                .streams_send
                                .get(&stream_id)
                                .map(|stream| stream.next_offset())
                                .unwrap_or(0);
                            self.cancel_stream_deliveries(stream_id);
                            let reset_sent = self.mutate_send_stream(stream_id, |stream| {
                                stream.stop(error_code);
                                let reset_sent = stream.reset_sent();
                                if !reset_sent {
                                    stream.mark_reset_sent();
                                }
                                reset_sent
                            });
                            self.push_stream_event(stream::Event::Stopped {
                                stream_id,
                                error_code,
                            })?;
                            if !reset_sent {
                                self.control
                                    .queue_reset_stream(stream_id, error_code, final_size);
                            }
                        }
                    }
                    Frame::MaxStreams {
                        is_uni,
                        max_streams,
                    } if epoch == Epoch::Application => {
                        let maximum = max_streams.get();
                        if maximum > MAX_STREAM_COUNT {
                            return Err(Error::ProtocolViolation);
                        }
                        let limit = &mut self.peer_max_streams[usize::from(is_uni)];
                        *limit = (*limit).max(maximum);
                    }
                    Frame::StreamsBlocked { .. } if epoch == Epoch::Application => {}
                    Frame::PathResponse { data } if epoch == Epoch::Application => {
                        if let Some(idx) = self
                            .outstanding_path_challenges
                            .iter()
                            .position(|t| *t == data)
                        {
                            self.outstanding_path_challenges.swap_remove(idx);
                            if !self.validated_path_tokens.contains(&data) {
                                if self.validated_path_tokens.len() == MAX_PATH_TOKENS {
                                    self.validated_path_tokens.swap_remove(0);
                                }
                                self.validated_path_tokens.push(data);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(())
        })();
        parsed_frames.clear();
        self.scratch_parsed_frames = parsed_frames;
        if result.is_ok() {
            self.egress.last_activity = now;
            self.egress.ack_eliciting_sent_since_last_receive = false;
        }
        result
    }

    fn discard_initial_keys(&mut self) {
        let leaked = self.egress.spaces[Epoch::Initial as usize].in_flight_bytes();
        self.egress.cc.discard(leaked);
        self.discard_epoch_journals(Epoch::Initial);
        self.egress.initial_w = None;
        self.initial_r = None;
        self.egress.spaces[Epoch::Initial as usize] = PnSpace::default();
        self.egress.pending_crypto_initial.clear();
    }

    fn discard_handshake_keys(&mut self) {
        let leaked = self.egress.spaces[Epoch::Handshake as usize].in_flight_bytes();
        self.egress.cc.discard(leaked);
        self.discard_epoch_journals(Epoch::Handshake);
        self.egress.handshake_w = None;
        self.handshake_r = None;
        self.egress.spaces[Epoch::Handshake as usize] = PnSpace::default();
        self.egress.pending_crypto_handshake.clear();
    }

    fn discard_epoch_journals(&mut self, epoch: Epoch) {
        self.egress
            .packet_journals
            .drain_where(|journal| journal.epoch == epoch, |_, _, _| {});
        self.egress
            .crypto_deliveries
            .remove_where(|delivery| delivery.epoch == epoch);
        self.egress
            .stream_deliveries
            .remove_where(|delivery| delivery.epoch == epoch);
    }

    fn ack(&mut self, epoch: Epoch, receipt: AckReceipt<'_>, now: Instant) {
        let AckReceipt {
            largest,
            delay_microseconds,
            first_range,
            additional_ranges,
            packets,
        } = receipt;
        if let Some(p) = packets.iter().find(|p| p.pn == largest) {
            let sample = now.saturating_duration_since(p.sent_time);
            let ack_delay = if matches!(epoch, Epoch::Application) {
                Duration::from_micros(delay_microseconds)
            } else {
                Duration::ZERO
            };
            self.egress.rtt.update(sample, ack_delay);
            self.egress.pto_count = 0;
        }
        for p in &packets {
            self.egress
                .cc
                .packet_acked(p.bytes_sent as u64, p.in_flight);
            if matches!(epoch, Epoch::Application) && Some(p.pn) == self.egress.pmtud_probe_pn {
                self.egress.pmtud.probe_acked();
                self.egress.pmtud_probe_pn = None;
            }
            self.ack_journal(epoch, p.pn);
        }
        if epoch == Epoch::Application {
            self.ack_application_journals(
                largest,
                delay_microseconds,
                first_range,
                additional_ranges,
                now,
            );
        }
        self.run_rack(now);
        self.update_loss_timer();
    }

    fn run_rack(&mut self, now: Instant) {
        let loss_delay = self.egress.rtt.loss_delay();
        for idx in 0..Epoch::Application as usize {
            let (lost, _) = self.egress.spaces[idx].detect_lost(loss_delay, now);
            if lost.is_empty() {
                continue;
            }
            let lost_bytes: u64 = lost.iter().map(|p| p.bytes_sent as u64).sum();
            let Some(latest) = lost.iter().map(|p| p.sent_time).max() else {
                continue;
            };
            for packet in &lost {
                self.lose_journal(Epoch::from_index(idx), packet.pn);
            }
            self.egress.cc.packets_lost(lost_bytes, latest);
            if idx == Epoch::Application as usize
                && let Some(probe_pn) = self.egress.pmtud_probe_pn
                && lost.iter().any(|p| p.pn == probe_pn)
            {
                self.egress.pmtud.probe_lost();
                self.egress.pmtud_probe_pn = None;
            }
        }
        self.detect_lost_application(now);
    }

    fn detect_lost_application(&mut self, now: Instant) -> usize {
        let Some(largest_acked) = self.egress.spaces[Epoch::Application as usize].largest_acked
        else {
            return 0;
        };
        let loss_delay = self.egress.rtt.loss_delay();
        let lost_send_time = now.checked_sub(loss_delay).unwrap_or(now);
        let mut journals = take(&mut self.egress.packet_journals);
        let mut total = 0;
        journals.drain_application_lost(
            largest_acked,
            lost_send_time,
            |journal, controls, streams| {
                total += 1;
                if journal.ack_eliciting && journal.in_flight {
                    self.egress.spaces[Epoch::Application as usize].ack_eliciting_in_flight =
                        self.egress.spaces[Epoch::Application as usize]
                            .ack_eliciting_in_flight
                            .saturating_sub(1);
                }
                self.lose_packet_deliveries(journal, controls, streams);
                self.egress
                    .cc
                    .packets_lost(journal.bytes_sent as u64, journal.sent_time);
                if Some(journal.pn) == self.egress.pmtud_probe_pn {
                    self.egress.pmtud.probe_lost();
                    self.egress.pmtud_probe_pn = None;
                }
            },
        );
        self.egress.packet_journals = journals;
        total
    }

    pub fn path_mtu(&self) -> u64 {
        self.egress.pmtud.current()
    }

    fn update_loss_timer(&mut self) {
        let loss_delay = self.egress.rtt.loss_delay();

        let mut rack_candidate: Option<Instant> = None;
        for space in &self.egress.spaces {
            let Some(largest_acked) = space.largest_acked else {
                continue;
            };
            let lo = largest_acked.saturating_sub(PACKET_THRESHOLD - 1);
            for (&_pn, p) in space.sent.range(lo..=largest_acked) {
                let when = p.sent_time + loss_delay;
                rack_candidate = Some(match rack_candidate {
                    Some(prev) if prev < when => prev,
                    _ => when,
                });
            }
        }
        if let Some(largest_acked) = self.egress.spaces[Epoch::Application as usize].largest_acked
            && let Some(when) = self
                .egress
                .packet_journals
                .application_loss_candidate(largest_acked, loss_delay)
        {
            rack_candidate = Some(rack_candidate.map_or(when, |previous| previous.min(when)));
        }
        if let Some(t) = rack_candidate {
            self.egress.loss_timer = Some(t);
            return;
        }

        let mut pto_base: Option<Instant> = None;
        for space in &self.egress.spaces {
            if space.ack_eliciting_in_flight > 0
                && let Some(t) = space.time_of_last_ack_eliciting
            {
                pto_base = Some(match pto_base {
                    Some(prev) => prev.min(t),
                    None => t,
                });
            }
        }
        self.egress.loss_timer = pto_base.map(|t| {
            let pto = self.egress.rtt.pto_period(Duration::ZERO);
            t + pto * (1u32 << self.egress.pto_count.min(16))
        });
    }

    pub fn next_timer(&self) -> Option<Instant> {
        match (self.egress.loss_timer, self.idle_deadline()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    pub fn check_loss(&mut self, now: Instant) {
        if self.egress.state != State::Closed
            && let Some(idle) = self.idle_deadline()
            && now >= idle
        {
            self.egress.state = State::Closed;
            return;
        }
        let Some(deadline) = self.egress.loss_timer else {
            return;
        };
        if now < deadline {
            return;
        }

        let loss_delay = self.egress.rtt.loss_delay();
        let mut total_lost = 0usize;
        for index in 0..Epoch::Application as usize {
            let (lost, _) = self.egress.spaces[index].detect_lost(loss_delay, now);
            if !lost.is_empty() {
                let lost_bytes: u64 = lost.iter().map(|p| p.bytes_sent as u64).sum();
                let Some(latest) = lost.iter().map(|p| p.sent_time).max() else {
                    continue;
                };
                for packet in &lost {
                    self.lose_journal(Epoch::from_index(index), packet.pn);
                }
                self.egress.cc.packets_lost(lost_bytes, latest);
                total_lost += lost.len();
            }
        }
        total_lost += self.detect_lost_application(now);

        if total_lost == 0 && self.arm_pto_probes() {
            self.egress.pto_count = self.egress.pto_count.saturating_add(1);
        }
        self.update_loss_timer();
    }

    fn arm_pto_probes(&mut self) -> bool {
        let Some(epoch) = self
            .egress
            .spaces
            .iter()
            .position(|space| space.ack_eliciting_in_flight != 0)
            .map(Epoch::from_index)
        else {
            return false;
        };
        self.egress.pto_probe_epoch = Some(epoch);
        self.egress.pto_probe_allowance = 2;
        if epoch == Epoch::Application {
            for journal in self.egress.packet_journals.application_iter_mut() {
                if journal.in_flight {
                    journal.pto_protected = true;
                }
            }
        }
        self.egress.crypto_deliveries.arm_probes(epoch);
        if epoch == Epoch::Application {
            self.control.arm_probes(epoch);
            self.egress.stream_deliveries.arm_probes(epoch);
        }
        true
    }

    fn feed_shin<R>(
        &mut self,
        epoch: shin::connection::Epoch,
        data: &[u8],
        read: &mut R,
    ) -> Result<(), Error>
    where
        R: FnMut(
            &mut SideKind,
            shin::connection::Epoch,
            &[u8],
            &mut ShinEvents<'_>,
        ) -> Result<(), DriveError<Error>>,
    {
        self.drive_shin(|side, events| read(side, epoch, data, events))
    }

    fn drive_shin(
        &mut self,
        run: impl FnOnce(&mut SideKind, &mut ShinEvents<'_>) -> Result<(), DriveError<Error>>,
    ) -> Result<(), Error> {
        let (result, done, reject_early_data) = {
            let Self {
                side,
                is_client,
                egress:
                    EgressHot {
                        pending_crypto_initial,
                        pending_crypto_handshake,
                        pending_crypto_app,
                        handshake_w,
                        app_w,
                        zero_rtt_w,
                        ..
                    },
                handshake_r,
                app_r,
                zero_rtt_r,
                pending_synth_eod,
                peer_transport_params_raw,
                pending_resumption_psk,
                received_tickets,
                received_ticket_bytes,
                ..
            } = self;
            let mut events = ShinEvents {
                pending_crypto_initial,
                pending_crypto_handshake,
                pending_crypto_app,
                handshake_r,
                handshake_w,
                app_r,
                app_w,
                zero_rtt_r,
                zero_rtt_w,
                pending_synth_eod,
                peer_transport_params_raw,
                pending_resumption_psk,
                received_tickets,
                received_ticket_bytes,
                is_client: *is_client,
                done: false,
                reject_early_data: false,
            };
            let result = run(side, &mut events);
            (result, events.done, events.reject_early_data)
        };

        match result {
            Ok(()) => {}
            Err(DriveError::Protocol(_)) => return Err(Error::Tls),
            Err(DriveError::Sink(error)) => return Err(error),
        }
        if reject_early_data {
            self.reject_early_data();
        }
        if done {
            if self.finalize_peer_tp().is_err() {
                self.egress.state = State::Closed;
                return Ok(());
            }
            self.egress.state = State::Established;
            if !self.is_client {
                self.control.handshake_done();
            }
            self.auto_issue_local_cids();
        }
        Ok(())
    }

    fn reject_early_data(&mut self) {
        let mut journals = take(&mut self.egress.packet_journals);
        journals.drain_where(
            |journal| journal.early_data,
            |journal, controls, streams| {
                if journal.ack_eliciting && journal.in_flight {
                    self.egress.spaces[Epoch::Application as usize].ack_eliciting_in_flight =
                        self.egress.spaces[Epoch::Application as usize]
                            .ack_eliciting_in_flight
                            .saturating_sub(1);
                    self.egress.cc.discard(journal.bytes_sent as u64);
                }
                self.lose_packet_deliveries(journal, controls, streams);
            },
        );
        self.egress.packet_journals = journals;
        self.update_loss_timer();
    }

    pub fn take_session_tickets(&mut self) -> Vec<session::Ticket> {
        self.received_ticket_bytes = 0;
        take(&mut self.received_tickets).into_iter().collect()
    }

    fn finalize_peer_tp(&mut self) -> Result<(), Error> {
        let raw = self
            .peer_transport_params_raw
            .as_ref()
            .ok_or(Error::TransportParameterMismatch)?;
        let peer_tp = Params::decode(raw)?;

        let expected_iscid = self
            .peer_first_scid
            .as_ref()
            .ok_or(Error::TransportParameterMismatch)?;
        let peer_iscid = peer_tp
            .initial_source_connection_id
            .as_ref()
            .ok_or(Error::TransportParameterMismatch)?;
        if peer_iscid != expected_iscid {
            return Err(Error::TransportParameterMismatch);
        }

        if self.is_client {
            let peer_odcid = peer_tp
                .original_destination_connection_id
                .as_ref()
                .ok_or(Error::TransportParameterMismatch)?;
            if peer_odcid != &self.original_dcid {
                return Err(Error::TransportParameterMismatch);
            }
        } else if peer_tp.original_destination_connection_id.is_some()
            || peer_tp.retry_source_connection_id.is_some()
        {
            return Err(Error::TransportParameterMismatch);
        }

        if self.is_client
            && let Some(tok) = peer_tp.stateless_reset_token
            && let Some(entry) = self.peer_cids.get_mut(&0)
        {
            entry.1 = tok;
        }
        self.egress.peer_max_data = peer_tp.initial_max_data;
        self.peer_max_streams = [
            peer_tp.initial_max_streams_bidi,
            peer_tp.initial_max_streams_uni,
        ];
        self.peer_transport_params = Some(peer_tp);
        Ok(())
    }

    fn peer_initial_stream_credit(
        peer_transport_params: Option<&Params>,
        is_client: bool,
        id: u64,
    ) -> u64 {
        let Some(tp) = peer_transport_params else {
            return 0;
        };
        let is_uni = id & 0x2 != 0;
        let initiator_is_client = id & 0x1 == 0;
        let we_initiated = initiator_is_client == is_client;
        if is_uni {
            if we_initiated {
                tp.initial_max_stream_data_uni
            } else {
                0
            }
        } else if we_initiated {
            tp.initial_max_stream_data_bidi_remote
        } else {
            tp.initial_max_stream_data_bidi_local
        }
    }

    pub fn send_packets(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out =
            Vec::with_capacity(self.egress.pending_datagrams.len().min(MAX_BATCH_PACKETS));
        self.fill_batch(&mut out, now, MAX_BATCH_PACKETS, MAX_PMTU as usize);
        out
    }

    pub fn send_batch(
        &mut self,
        batch: &mut packet::Batch,
        now: Instant,
        max_packets: usize,
        max_packet_bytes: usize,
    ) {
        self.send_into_batch(batch, now, max_packets, max_packet_bytes);
    }

    pub(crate) fn send_gso_batch(
        &mut self,
        batch: &mut packet::Gso,
        now: Instant,
        max_packets: usize,
        max_packet_bytes: usize,
    ) {
        self.send_into_batch(batch, now, max_packets, max_packet_bytes);
    }

    fn send_into_batch(
        &mut self,
        batch: &mut impl packet::Sink,
        now: Instant,
        max_packets: usize,
        max_packet_bytes: usize,
    ) {
        let packet_bytes = max_packet_bytes.min(self.path_mtu() as usize);
        let packet_slots = max_packets.min(MAX_BATCH_PACKETS);
        batch.reset(packet_slots, packet_bytes);
        // fill_batch takes the caller's raw ceiling: regular packets clamp to
        // the path MTU internally, but PMTU probes must be allowed to exceed
        // it — pre-clamping made every probe re-arm at the current MTU and
        // emit forever.
        self.fill_batch(batch, now, packet_slots, max_packet_bytes);
    }

    pub(crate) fn send_one(
        &mut self,
        packet: &mut Vec<u8>,
        now: Instant,
        max_packet_bytes: usize,
    ) -> bool {
        let mut sink = packet::Slot {
            packet,
            emitted: false,
        };
        self.fill_batch(&mut sink, now, 1, max_packet_bytes);
        sink.emitted
    }

    fn snapshot_pending_streams(&mut self) {
        let EgressHot {
            scratch_pending,
            send_schedule,
            streams_send,
            ..
        } = &mut self.egress;
        send_schedule.snapshot(streams_send, scratch_pending);
    }

    fn fill_batch<S: packet::Sink>(
        &mut self,
        sink: &mut S,
        now: Instant,
        max_packets: usize,
        max_packet_bytes: usize,
    ) {
        if self.control.take_overflowed() && self.egress.pending_close.is_none() {
            self.egress.pending_close = Some(PendingClose {
                is_application: false,
                error_code: INTERNAL_ERROR,
                frame_type: 0,
                reason: CONTROL_CAPACITY_REASON.to_vec(),
            });
        }
        if self.egress.state == State::Closed {
            return;
        }
        let normal_packet_bytes = max_packet_bytes.min(self.path_mtu() as usize);
        let mut remaining = max_packets;
        let mut sent_handshake_packet = false;
        let mut sent_handshake_done = false;

        self.snapshot_pending_streams();

        while remaining != 0 && self.egress.pto_probe_allowance != 0 {
            let Some(packet_ceiling) = self.emission_ceiling(normal_packet_bytes) else {
                break;
            };
            let Some(commit) = sink.emit(packet_ceiling, |dst, packet_ceiling| {
                self.build_pto_probe(dst, packet_ceiling)
            }) else {
                break;
            };
            if !self.commit_packet(commit, now) {
                return;
            }
            remaining -= 1;
        }

        if self.egress.initial_w.is_some() {
            while remaining != 0 {
                if !self.allows_emit_for(packet::Cargo::CryptoOrAck, now) {
                    break;
                }
                let has_crypto = self.has_initial_crypto();
                let has_ack = self.egress.spaces[Epoch::Initial as usize].ack_pending;
                if !has_crypto && !has_ack {
                    break;
                }
                let Some(packet_ceiling) = self.emission_ceiling(normal_packet_bytes) else {
                    break;
                };
                let Some(commit) = sink.emit(packet_ceiling, |dst, packet_ceiling| {
                    self.build_crypto_packet(
                        dst,
                        packet_ceiling,
                        Epoch::Initial,
                        packet::CryptoMode::Regular,
                    )
                }) else {
                    break;
                };
                if !self.commit_packet(commit, now) {
                    return;
                }
                remaining -= 1;
                self.egress.sent_initial = true;
            }
        }

        if remaining != 0 && self.egress.zero_rtt_w.is_some() && self.egress.app_w.is_none() {
            while remaining != 0 && self.allows_emit_for(packet::Cargo::CryptoOrAck, now) {
                let Some(packet_ceiling) = self.emission_ceiling(normal_packet_bytes) else {
                    break;
                };
                let Some(commit) = sink.emit(packet_ceiling, |dst, packet_ceiling| {
                    self.build_zero_rtt(dst, packet_ceiling, false)
                }) else {
                    break;
                };
                if !self.commit_packet(commit, now) {
                    return;
                }
                remaining -= 1;
            }
        }

        if self.egress.handshake_w.is_some() {
            while remaining != 0 {
                if !self.allows_emit_for(packet::Cargo::CryptoOrAck, now) {
                    break;
                }
                let has_crypto = self.has_handshake_crypto();
                let has_ack = self.egress.spaces[Epoch::Handshake as usize].ack_pending;
                if !has_crypto && !has_ack {
                    break;
                }
                let Some(packet_ceiling) = self.emission_ceiling(normal_packet_bytes) else {
                    break;
                };
                let Some(commit) = sink.emit(packet_ceiling, |dst, packet_ceiling| {
                    self.build_crypto_packet(
                        dst,
                        packet_ceiling,
                        Epoch::Handshake,
                        packet::CryptoMode::Regular,
                    )
                }) else {
                    break;
                };
                if !self.commit_packet(commit, now) {
                    return;
                }
                remaining -= 1;
                sent_handshake_packet = true;
            }
        }

        if self.egress.app_w.is_some() {
            if remaining != 0 && self.egress.pending_close.is_some() {
                let commit =
                    self.emission_ceiling(normal_packet_bytes)
                        .and_then(|packet_ceiling| {
                            sink.emit(packet_ceiling, |dst, packet_ceiling| {
                                self.build_one_rtt_close(dst, packet_ceiling)
                            })
                        });
                if let Some(commit) = commit {
                    if !self.commit_packet(commit, now) {
                        return;
                    }
                    return;
                }
            }

            for _ in 0..4096u32 {
                if remaining == 0 {
                    break;
                }
                let has_app_ack = self.egress.spaces[Epoch::Application as usize].ack_pending;
                let has_datagrams = !self.egress.pending_datagrams.is_empty();
                let has_streams = !self.egress.scratch_pending.is_empty();
                let has_lifecycle = !self.egress.pending_crypto_app.is_empty()
                    || !self.egress.spaces[Epoch::Application as usize]
                        .crypto_retransmit
                        .is_empty()
                    || !self.egress.spaces[Epoch::Application as usize]
                        .stream_retransmit
                        .is_empty();

                let one_shot =
                    !self.control.is_empty() || has_lifecycle || (has_app_ack && !has_datagrams);
                if (!one_shot && !has_streams)
                    || !self.allows_emit_for(packet::Cargo::CryptoOrAck, now)
                {
                    break;
                }
                let before = self.egress.cc.bytes_in_flight;
                let Some(packet_ceiling) = self.emission_ceiling(normal_packet_bytes) else {
                    break;
                };
                let Some(commit) = sink.emit(packet_ceiling, |dst, packet_ceiling| {
                    self.build_one_rtt::<false, false>(dst, packet_ceiling)
                }) else {
                    break;
                };
                let did_handshake_done = commit
                    .controls
                    .as_slice()
                    .iter()
                    .any(|delivery| delivery.record == delivery::Control::HandshakeDone);
                if !self.commit_packet(commit, now) {
                    return;
                }
                remaining -= 1;
                if did_handshake_done {
                    sent_handshake_done = true;
                }
                if !one_shot && self.egress.cc.bytes_in_flight == before {
                    break;
                }
            }
            while remaining != 0 && !self.egress.pending_datagrams.is_empty() {
                if !self.allows_emit_for(packet::Cargo::DatagramOnly, now) {
                    break;
                }
                let Some(packet_ceiling) = self.emission_ceiling(normal_packet_bytes) else {
                    break;
                };
                let Some(commit) = sink.emit(packet_ceiling, |dst, packet_ceiling| {
                    if S::FRESH_PACKETS {
                        let data = self.egress.pending_datagrams.front()?;
                        dst.reserve(
                            1 + self.egress.peer_cid.len()
                                + PN_LEN as usize
                                + 1
                                + data.len()
                                + TAG_LEN,
                        );
                    }
                    self.build_one_rtt::<true, false>(dst, packet_ceiling)
                }) else {
                    break;
                };
                if !self.commit_packet(commit, now) {
                    return;
                }
                remaining -= 1;
            }
            if remaining != 0
                && let Some(probe_size) = self.egress.pmtud.next_probe()
                && self.allows_emit_for(packet::Cargo::CryptoOrAck, now)
            {
                let commit = self
                    .emission_ceiling(max_packet_bytes)
                    .and_then(|packet_ceiling| {
                        sink.emit(packet_ceiling, |dst, packet_ceiling| {
                            self.build_one_rtt_probe(dst, probe_size, packet_ceiling)
                        })
                    });
                if let Some(commit) = commit
                    && !self.commit_packet(commit, now)
                {
                    return;
                }
            }
        }

        if sent_handshake_packet && self.egress.initial_w.is_some() {
            self.discard_initial_keys();
        }
        if sent_handshake_done && !self.is_client {
            self.discard_handshake_keys();
        }

        if !sink.is_empty() {
            self.update_loss_timer();
        }
    }

    fn has_initial_crypto(&self) -> bool {
        !self.egress.pending_crypto_initial.is_empty()
            || !self.egress.spaces[Epoch::Initial as usize]
                .crypto_retransmit
                .is_empty()
    }

    fn has_handshake_crypto(&self) -> bool {
        !self.egress.pending_crypto_handshake.is_empty()
            || !self.egress.spaces[Epoch::Handshake as usize]
                .crypto_retransmit
                .is_empty()
    }

    fn append_ack_frame(&mut self, epoch: Epoch, out: &mut Vec<u8>, limit: usize) -> bool {
        let space = &mut self.egress.spaces[epoch as usize];
        if !space.ack_pending {
            return false;
        }
        let Some(ack_ranges) = space.build_ack_ranges() else {
            return false;
        };
        let largest = ack_ranges.largest;
        let first_range = ack_ranges.first_range;
        let mut additional_ranges = ack_ranges.additional;
        let available = limit.saturating_sub(out.len());
        let mut encoded = 1
            + Self::varint_len(largest as usize)
            + 1
            + Self::varint_len(additional_ranges.len())
            + Self::varint_len(first_range as usize)
            + additional_ranges
                .iter()
                .map(|(gap, range)| {
                    Self::varint_len(*gap as usize) + Self::varint_len(*range as usize)
                })
                .sum::<usize>();
        while encoded > available {
            let Some((gap, range)) = additional_ranges.pop() else {
                return false;
            };
            encoded -= Self::varint_len(gap as usize) + Self::varint_len(range as usize);
            let old_count = additional_ranges.len() + 1;
            encoded -= Self::varint_len(old_count);
            encoded += Self::varint_len(additional_ranges.len());
        }
        let Some(largest) = VarInt::new(largest) else {
            return false;
        };
        let Some(first_range) = VarInt::new(first_range) else {
            return false;
        };
        let Some(additional_ranges) = additional_ranges
            .into_iter()
            .map(|(gap, range)| Some((VarInt::new(gap)?, VarInt::new(range)?)))
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        let start = out.len();
        let encoded = Frame::Ack {
            largest,
            delay: VarInt::ZERO,
            first_range,
            additional_ranges,
        }
        .encode(out);
        if encoded.is_ok() {
            true
        } else {
            out.truncate(start);
            false
        }
    }

    fn auto_issue_local_cids(&mut self) {
        if self.auto_issued {
            return;
        }
        self.auto_issued = true;
        let limit = self
            .peer_transport_params
            .as_ref()
            .map(|tp| tp.active_connection_id_limit)
            .unwrap_or(DEFAULT_ACTIVE_CONNECTION_ID_LIMIT);
        let to_issue = limit.saturating_sub(self.local_cids.len() as u64) as usize;
        for _ in 0..to_issue.min(8) {
            let seq = self.next_local_cid_seq;
            self.next_local_cid_seq += 1;
            let cid = self.derive_cid_for_seq(seq);
            let srt = self
                .stateless_reset_secret
                .map(|s| StatelessResetSecret(s).token_for(&cid))
                .unwrap_or([0u8; 16]);
            self.local_cids.insert(seq, cid.clone());
            self.cids_to_register.push(cid.clone());
            self.control.queue_new_connection_id(seq, cid, srt);
        }
    }

    pub fn take_cids_to_register(&mut self) -> Vec<Vec<u8>> {
        take(&mut self.cids_to_register)
    }

    fn derive_cid_for_seq(&self, seq: u64) -> Vec<u8> {
        let seq_bytes = seq.to_be_bytes();
        let mut out: Vec<u8> = self
            .local_cid
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ seq_bytes[i % 8] ^ (i as u8))
            .collect();
        if let Some(p) = self.cid_prefix
            && let Some(first) = out.first_mut()
        {
            *first = p;
        }
        out
    }

    pub fn local_cids(&self) -> &BTreeMap<u64, Vec<u8>> {
        &self.local_cids
    }

    fn varint_len(value: usize) -> usize {
        if value < (1 << 6) {
            1
        } else if value < (1 << 14) {
            2
        } else if value < (1 << 30) {
            4
        } else {
            8
        }
    }

    fn long_payload_limit(fixed_header: usize, max_packet_bytes: usize) -> usize {
        let mut payload = max_packet_bytes.saturating_sub(fixed_header + TAG_LEN + 1);
        loop {
            let length = PN_LEN as usize + payload + TAG_LEN;
            let next =
                max_packet_bytes.saturating_sub(fixed_header + TAG_LEN + Self::varint_len(length));
            if next >= payload {
                return payload;
            }
            payload = next;
        }
    }

    fn initial_payload_limit(&self, max_packet_bytes: usize) -> usize {
        Self::initial_payload_limit_for(
            self.egress.peer_cid.len(),
            self.local_cid.len(),
            self.retry_token.len(),
            max_packet_bytes,
        )
    }

    fn initial_payload_limit_for(
        peer_cid_len: usize,
        local_cid_len: usize,
        token_len: usize,
        max_packet_bytes: usize,
    ) -> usize {
        let fixed_header = 1
            + 4
            + 1
            + peer_cid_len
            + 1
            + local_cid_len
            + Self::varint_len(token_len)
            + token_len
            + PN_LEN as usize;
        Self::long_payload_limit(fixed_header, max_packet_bytes)
    }

    fn handshake_payload_limit(&self, max_packet_bytes: usize) -> usize {
        let fixed_header =
            1 + 4 + 1 + self.egress.peer_cid.len() + 1 + self.local_cid.len() + PN_LEN as usize;
        Self::long_payload_limit(fixed_header, max_packet_bytes)
    }

    fn short_payload_limit(&self, max_packet_bytes: usize) -> usize {
        max_packet_bytes.saturating_sub(1 + self.egress.peer_cid.len() + PN_LEN as usize + TAG_LEN)
    }

    fn append_frame(out: &mut Vec<u8>, limit: usize, frame: &Frame) -> bool {
        let start = out.len();
        if frame.encode(out).is_ok() && out.len() <= limit {
            true
        } else {
            out.truncate(start);
            false
        }
    }

    fn append_stream_frame(
        out: &mut Vec<u8>,
        limit: usize,
        stream_id: u64,
        offset: u64,
        fin: bool,
        stream: &SendStream,
        len: usize,
    ) -> bool {
        let start = out.len();
        let Ok(len_u64) = u64::try_from(len) else {
            return false;
        };
        let Some(stream_id) = VarInt::new(stream_id) else {
            return false;
        };
        let Some(wire_offset) = VarInt::new(offset) else {
            return false;
        };
        if stream.range_available(offset, len_u64)
            && Frame::encode_stream_header(out, stream_id, wire_offset, fin, Some(len)).is_ok()
            && out.len().saturating_add(len) <= limit
            && (len == 0 || stream.append_range(out, offset, len))
        {
            true
        } else {
            out.truncate(start);
            false
        }
    }

    fn can_track_packet(&self) -> bool {
        let pn = self.egress.spaces[Epoch::Application as usize].next_pn;
        self.egress
            .packet_journals
            .has_room_for(Epoch::Application, pn, 2)
            && self
                .egress
                .packet_journals
                .has_carrier_room(PACKET_CONTROL_CAPACITY * 2, PACKET_STREAM_CAPACITY * 2)
            && self.egress.crypto_deliveries.has_room(2)
            && self.control.has_delivery_room(PACKET_CONTROL_CAPACITY * 2)
            && self
                .egress
                .stream_deliveries
                .has_room(PACKET_STREAM_CAPACITY * 2)
    }

    fn can_track_probe(&self, epoch: Epoch) -> bool {
        let pn = self.egress.spaces[epoch as usize].next_pn;
        self.egress.packet_journals.has_room_for(epoch, pn, 1)
            && (epoch != Epoch::Application
                || self
                    .egress
                    .packet_journals
                    .has_carrier_room(PACKET_CONTROL_CAPACITY, PACKET_STREAM_CAPACITY))
    }

    fn cancel_stream_deliveries(&mut self, stream_id: u64) {
        self.egress
            .stream_deliveries
            .remove_where(|delivery| delivery.record.stream_id == stream_id);
        self.egress.spaces[Epoch::Application as usize]
            .stream_retransmit
            .retain(|(candidate, _, _, _)| *candidate != stream_id);
    }

    fn commit_packet(&mut self, commit: commit::Packet, now: Instant) -> bool {
        let epoch = commit.epoch;
        let pn = commit.pn;
        let tracked = commit.in_flight
            || !commit.controls.is_empty()
            || !commit.streams.is_empty()
            || commit.early_data
            || commit.crypto.is_some()
            || commit.crypto_probe.is_some()
            || commit.pmtud_probe.is_some();
        let mut crypto_delivery = commit.crypto_probe;
        let mut journal = journal::Packet {
            epoch,
            pn,
            early_data: commit.early_data,
            sent_time: now,
            ack_eliciting: commit.ack_eliciting,
            in_flight: commit.in_flight,
            bytes_sent: commit.bytes,
            pto_protected: false,
            crypto: None,
        };
        self.egress.spaces[epoch as usize].next_pn = pn.saturating_add(1);
        if commit.ack_included {
            self.egress.spaces[epoch as usize].ack_pending = false;
        }
        if let Some(crypto) = commit.crypto {
            let (offset, mut data) = match crypto {
                commit::Crypto::Pending { offset, len } => {
                    let pending = match epoch {
                        Epoch::Initial => &mut self.egress.pending_crypto_initial,
                        Epoch::Handshake => &mut self.egress.pending_crypto_handshake,
                        Epoch::Application => &mut self.egress.pending_crypto_app,
                    };
                    let take = len.min(pending.len());
                    let data = pending.drain(..take).collect::<Vec<_>>();
                    self.egress.spaces[epoch as usize].crypto_next_offset =
                        offset.saturating_add(take as u64);
                    (offset, data)
                }
                commit::Crypto::Retransmit { index, offset, len } => {
                    let (stored_offset, mut data) = self.egress.spaces[epoch as usize]
                        .crypto_retransmit
                        .remove(index);
                    let take = len.min(data.len());
                    let remainder = data.split_off(take);
                    if !remainder.is_empty() {
                        self.egress.spaces[epoch as usize]
                            .crypto_retransmit
                            .push((stored_offset.saturating_add(take as u64), remainder));
                    }
                    (offset, data)
                }
            };
            crypto_delivery = Some(commit::Delivery {
                record: delivery::Crypto {
                    offset,
                    len: data.len(),
                },
                probe: None,
            });
            self.egress.spaces[epoch as usize]
                .crypto_inflight
                .insert(offset, (take(&mut data), u64::MAX));
        }
        if let Some(delivery) = crypto_delivery {
            let handle = if let Some(handle) = delivery.probe {
                if !self.egress.crypto_deliveries.add_probe_carrier(handle) {
                    self.egress.state = State::Closed;
                    return false;
                }
                handle
            } else {
                let Some(handle) = self.egress.crypto_deliveries.insert(epoch, delivery.record)
                else {
                    self.egress.state = State::Closed;
                    return false;
                };
                handle
            };
            journal.crypto = Some(handle);
        }
        let journal_key = if tracked {
            let Some(key) = self.egress.packet_journals.insert(journal) else {
                self.egress.state = State::Closed;
                return false;
            };
            Some(key)
        } else {
            None
        };
        for delivery in commit.streams.as_slice().iter().copied() {
            let record = delivery.record;
            if delivery.probe.is_none() && record.retransmit {
                if let Some(index) = self.egress.spaces[Epoch::Application as usize]
                    .stream_retransmit
                    .iter()
                    .position(|item| {
                        *item == (record.stream_id, record.offset, record.len, record.fin)
                    })
                {
                    self.egress.spaces[Epoch::Application as usize]
                        .stream_retransmit
                        .swap_remove(index);
                }
            } else if delivery.probe.is_none() {
                let (advanced, unscheduled) = self
                    .egress
                    .streams_send
                    .get_mut(&record.stream_id)
                    .map_or((false, false), |stream| {
                        if stream.next_offset() != record.offset {
                            return (false, false);
                        }
                        stream.advance_sent(record.len as usize, record.fin);
                        (true, !stream.has_pending() && stream.unschedule())
                    });
                if unscheduled {
                    self.egress.send_schedule.deactivate();
                }
                if advanced {
                    self.egress.peer_total_sent =
                        self.egress.peer_total_sent.saturating_add(record.len);
                }
            }
            let handle = if let Some(handle) = delivery.probe {
                if !self.egress.stream_deliveries.add_probe_carrier(handle) {
                    self.egress.state = State::Closed;
                    return false;
                }
                handle
            } else {
                let Some(handle) = self.egress.stream_deliveries.insert(epoch, record) else {
                    self.egress.state = State::Closed;
                    return false;
                };
                handle
            };
            let Some(key) = journal_key else {
                self.egress.state = State::Closed;
                return false;
            };
            if !self.egress.packet_journals.push_stream(key, handle) {
                self.egress.state = State::Closed;
                return false;
            }
        }
        for delivery in commit.controls.as_slice().iter().copied() {
            let record = delivery.record;
            if let delivery::Control::PathChallenge(data) = record
                && !self.outstanding_path_challenges.contains(&data)
            {
                self.outstanding_path_challenges.push(data);
            }
            let handle = if let Some(handle) = delivery.probe {
                self.control.commit(epoch, record, Some(handle))
            } else {
                self.control.commit(epoch, record, None)
            };
            let Some(handle) = handle else {
                self.egress.state = State::Closed;
                return false;
            };
            let Some(key) = journal_key else {
                self.egress.state = State::Closed;
                return false;
            };
            if !self.egress.packet_journals.push_control(key, handle) {
                self.egress.state = State::Closed;
                return false;
            }
        }
        if tracked && epoch == Epoch::Application && commit.ack_eliciting {
            self.egress.spaces[epoch as usize].time_of_last_ack_eliciting = Some(now);
            self.egress.spaces[epoch as usize].ack_eliciting_in_flight += 1;
        }
        if commit.datagram {
            self.egress.pending_datagrams.pop_front();
        }
        self.egress.amplification_sent = self
            .egress
            .amplification_sent
            .saturating_add(commit.bytes as u64);
        self.wire_sent(commit.bytes as u64, commit.in_flight, now);
        if epoch != Epoch::Application {
            self.egress.spaces[epoch as usize].record_sent(SentPacket {
                pn,
                sent_time: now,
                ack_eliciting: commit.ack_eliciting,
                in_flight: commit.in_flight,
                bytes_sent: commit.bytes,
            });
        }
        if let Some(size) = commit.pmtud_probe {
            self.egress.pmtud.arm_probe(size);
            self.egress.pmtud_probe_pn = Some(pn);
        }
        if commit.pto_probe {
            self.egress.pto_probe_allowance = self.egress.pto_probe_allowance.saturating_sub(1);
            if self.egress.pto_probe_allowance == 0 {
                self.egress.pto_probe_epoch = None;
            }
        }
        if commit.ack_eliciting && !self.egress.ack_eliciting_sent_since_last_receive {
            self.egress.last_activity = now;
            self.egress.ack_eliciting_sent_since_last_receive = true;
        }
        if commit.close {
            self.egress.pending_close = None;
            self.egress.state = State::Closed;
        }
        true
    }

    fn ack_control(&mut self, handle: delivery::Handle<delivery::Control>) {
        match self.control.acknowledge(handle) {
            control::Effect::None => {}
            control::Effect::RetireStream(stream_id) => self.retire_send(stream_id),
        }
    }

    fn ack_journal(&mut self, epoch: Epoch, pn: u64) {
        let mut journals = take(&mut self.egress.packet_journals);
        journals.remove(epoch, pn, |journal, controls, streams| {
            self.ack_packet_deliveries(journal, controls, streams);
        });
        self.egress.packet_journals = journals;
    }

    fn ack_application_journals(
        &mut self,
        largest: u64,
        ack_delay_microseconds: u64,
        first_range: u64,
        additional: AckRanges<'_>,
        now: Instant,
    ) {
        let mut journals = take(&mut self.egress.packet_journals);
        journals.drain_application_ack(
            largest,
            first_range,
            additional,
            |journal, controls, streams| {
                if journal.pn == largest {
                    let sample = now.saturating_duration_since(journal.sent_time);
                    self.egress
                        .rtt
                        .update(sample, Duration::from_micros(ack_delay_microseconds));
                }
                if journal.ack_eliciting {
                    self.egress.pto_count = 0;
                }
                self.ack_application_packet(journal, controls, streams);
            },
        );
        self.egress.packet_journals = journals;
    }

    fn ack_application_packet(
        &mut self,
        journal: journal::Packet,
        controls: journal::ControlDrain<'_>,
        streams: journal::StreamDrain<'_>,
    ) {
        self.egress
            .cc
            .packet_acked(journal.bytes_sent as u64, journal.in_flight);
        if Some(journal.pn) == self.egress.pmtud_probe_pn {
            self.egress.pmtud.probe_acked();
            self.egress.pmtud_probe_pn = None;
        }
        if journal.ack_eliciting && journal.in_flight {
            self.egress.spaces[Epoch::Application as usize].ack_eliciting_in_flight =
                self.egress.spaces[Epoch::Application as usize]
                    .ack_eliciting_in_flight
                    .saturating_sub(1);
        }
        self.ack_packet_deliveries(journal, controls, streams);
    }

    fn lose_journal(&mut self, epoch: Epoch, pn: u64) {
        let mut journals = take(&mut self.egress.packet_journals);
        journals.remove(epoch, pn, |journal, controls, streams| {
            self.lose_packet_deliveries(journal, controls, streams);
        });
        self.egress.packet_journals = journals;
    }

    fn ack_packet_deliveries(
        &mut self,
        journal: journal::Packet,
        controls: journal::ControlDrain<'_>,
        streams: journal::StreamDrain<'_>,
    ) {
        if let Some(handle) = journal.crypto
            && let Some(delivery) = self.egress.crypto_deliveries.remove(handle)
        {
            self.egress.spaces[delivery.epoch as usize]
                .crypto_inflight
                .remove(&delivery.record.offset);
        }
        for handle in controls {
            self.ack_control(handle);
        }
        for handle in streams {
            let Some(delivery) = self.egress.stream_deliveries.remove(handle) else {
                continue;
            };
            let record = delivery.record;
            let retire = self
                .egress
                .streams_send
                .get_mut(&record.stream_id)
                .is_some_and(|entry| {
                    entry.ack(record.offset, record.len);
                    if record.fin {
                        entry.mark_fin_acked();
                    }
                    entry.is_fully_acked()
                });
            if retire {
                self.retire_send(record.stream_id);
            }
        }
    }

    fn lose_packet_deliveries(
        &mut self,
        journal: journal::Packet,
        controls: journal::ControlDrain<'_>,
        streams: journal::StreamDrain<'_>,
    ) {
        if let Some(handle) = journal.crypto
            && let Some(delivery) = self.egress.crypto_deliveries.release(handle)
            && let Some((data, _)) = self.egress.spaces[delivery.epoch as usize]
                .crypto_inflight
                .remove(&delivery.record.offset)
        {
            self.egress.spaces[delivery.epoch as usize]
                .crypto_retransmit
                .push((delivery.record.offset, data));
        }
        for handle in controls {
            self.control.lose(handle);
        }
        for handle in streams {
            let Some(delivery) = self.egress.stream_deliveries.release(handle) else {
                continue;
            };
            let record = delivery.record;
            let active = self
                .egress
                .streams_send
                .get(&record.stream_id)
                .is_some_and(|stream| {
                    !stream.reset_sent()
                        && stream.stop_sending_error().is_none()
                        && stream.range_available(record.offset, record.len)
                });
            if active {
                self.egress.spaces[Epoch::Application as usize]
                    .stream_retransmit
                    .push((record.stream_id, record.offset, record.len, record.fin));
            }
        }
    }

    fn crypto_data_limit(offset: u64, frame_room: usize) -> usize {
        let fixed = 1 + Self::varint_len(offset as usize);
        let mut data = frame_room.saturating_sub(fixed + 1);
        loop {
            let next = frame_room.saturating_sub(fixed + Self::varint_len(data));
            if next >= data {
                return data;
            }
            data = next;
        }
    }

    fn peek_crypto_chunk<'a>(
        space: &'a PnSpace,
        pending: &'a [u8],
        frame_room: usize,
    ) -> Option<(commit::Crypto, &'a [u8])> {
        if let Some((index, (offset, data))) =
            space.crypto_retransmit.iter().enumerate().next_back()
        {
            let take = Self::crypto_data_limit(*offset, frame_room).min(data.len());
            if take == 0 {
                return None;
            }
            return Some((
                commit::Crypto::Retransmit {
                    index,
                    offset: *offset,
                    len: take,
                },
                &data[..take],
            ));
        }
        if pending.is_empty() {
            return None;
        }
        let offset = space.crypto_next_offset;
        let take = Self::crypto_data_limit(offset, frame_room).min(pending.len());
        if take == 0 {
            return None;
        }
        Some((
            commit::Crypto::Pending { offset, len: take },
            &pending[..take],
        ))
    }

    fn encode_crypto(out: &mut Vec<u8>, offset: u64, data: &[u8]) -> bool {
        let start = out.len();
        out.push(0x06);
        let Some(offset) = VarInt::new(offset) else {
            out.truncate(start);
            return false;
        };
        let Some(len) = VarInt::from_usize(data.len()) else {
            out.truncate(start);
            return false;
        };
        offset.encode(out);
        len.encode(out);
        out.extend_from_slice(data);
        true
    }

    fn pending_crypto_probe(
        &self,
        epoch: Epoch,
        frame_room: usize,
    ) -> Option<(commit::Delivery<delivery::Crypto>, &[u8])> {
        let (handle, record) = self.egress.crypto_deliveries.next_probe(epoch, |_| false)?;
        let data = self.egress.spaces[epoch as usize]
            .crypto_inflight
            .get(&record.offset)?
            .0
            .as_slice();
        (data.len() == record.len
            && Self::crypto_data_limit(record.offset, frame_room) >= record.len)
            .then_some((
                commit::Delivery {
                    record,
                    probe: Some(handle),
                },
                data,
            ))
    }

    fn append_pending_controls<const MASK: u16, Out>(
        pending: &control::Pending,
        out: &mut Out,
        limit: usize,
        commit: &mut commit::Packet,
        mut cursor: control::Cursor<MASK>,
    ) where
        Out: Deref<Target = Vec<u8>> + DerefMut,
    {
        while !commit.controls.is_full() && pending.has_delivery_room(commit.controls.len() + 1) {
            let Some(record) = cursor.next(pending) else {
                break;
            };
            if !pending.encode_pending::<MASK, _>(out, limit, record) {
                break;
            }
            commit.push_control(record);
            commit.ack_eliciting = true;
        }
    }

    fn append_path_controls<Out>(
        pending: &control::Pending,
        records: impl Iterator<Item = delivery::Control>,
        out: &mut Out,
        limit: usize,
        commit: &mut commit::Packet,
    ) where
        Out: Deref<Target = Vec<u8>> + DerefMut,
    {
        for record in records {
            if commit.controls.is_full() || !pending.has_delivery_room(commit.controls.len() + 1) {
                break;
            }
            if !pending.encode_pending::<{ control::SUFFIX }, _>(out, limit, record) {
                break;
            }
            commit.push_control(record);
            commit.ack_eliciting = true;
        }
    }

    fn build_pto_probe(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
    ) -> Option<(usize, commit::Packet)> {
        let epoch = self.egress.pto_probe_epoch?;
        if !self.can_track_probe(epoch) {
            return None;
        }
        match epoch {
            Epoch::Initial | Epoch::Handshake => self.build_crypto_packet(
                dst,
                max_packet_bytes,
                self.egress.pto_probe_epoch?,
                packet::CryptoMode::PtoProbe,
            ),
            Epoch::Application if self.egress.app_w.is_some() => {
                self.build_one_rtt::<false, true>(dst, max_packet_bytes)
            }
            Epoch::Application => self.build_zero_rtt(dst, max_packet_bytes, true),
        }
    }

    fn seal_crypto_packet(
        &mut self,
        dst: &mut Vec<u8>,
        epoch: Epoch,
        pn: u64,
        frames: &[u8],
    ) -> Option<usize> {
        let packet_type = match epoch {
            Epoch::Initial => LONG_INITIAL,
            Epoch::Handshake => LONG_HANDSHAKE,
            Epoch::Application => return None,
        };
        let mut header = take(&mut self.scratch_header);
        header.clear();
        let token = (epoch == Epoch::Initial).then_some(self.retry_token.as_slice());
        let result = LongHeader {
            version: QUIC_V1,
            packet_type,
            dcid: &self.egress.peer_cid,
            scid: &self.local_cid,
            token,
            packet_number: pn,
            packet_number_len: PN_LEN,
        }
        .encode_into(&mut header, frames.len() + TAG_LEN)
        .ok()
        .and_then(|pn_offset| {
            let protection = match epoch {
                Epoch::Initial => self.egress.initial_w.as_ref(),
                Epoch::Handshake => self.egress.handshake_w.as_ref(),
                Epoch::Application => None,
            }?;
            protection
                .encrypt_long_into(dst, &header, frames, pn, pn_offset, PN_LEN as usize)
                .ok()
        });
        header.clear();
        self.scratch_header = header;
        result
    }

    fn build_crypto_packet(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
        epoch: Epoch,
        mode: packet::CryptoMode,
    ) -> Option<(usize, commit::Packet)> {
        if epoch == Epoch::Application
            || epoch == Epoch::Initial && self.is_client && max_packet_bytes < MIN_INITIAL_LEN
        {
            return None;
        }
        match epoch {
            Epoch::Initial => self.egress.initial_w.as_ref()?,
            Epoch::Handshake => self.egress.handshake_w.as_ref()?,
            Epoch::Application => return None,
        };
        let payload_limit = match epoch {
            Epoch::Initial => self.initial_payload_limit(max_packet_bytes),
            Epoch::Handshake => self.handshake_payload_limit(max_packet_bytes),
            Epoch::Application => return None,
        };
        let pn = self.egress.spaces[epoch as usize].next_pn;

        let mut frames = take(&mut self.scratch_frames);
        frames.clear();
        let ack_included = self.append_ack_frame(epoch, &mut frames, payload_limit);
        let frame_room = payload_limit.saturating_sub(frames.len());
        let mut crypto = None;
        let mut crypto_probe = None;
        match mode {
            packet::CryptoMode::Regular => {
                if self.egress.packet_journals.has_room_for(epoch, pn, 2)
                    && self.egress.crypto_deliveries.has_room(2)
                {
                    let chunk = match epoch {
                        Epoch::Initial => Self::peek_crypto_chunk(
                            &self.egress.spaces[epoch as usize],
                            &self.egress.pending_crypto_initial,
                            frame_room,
                        ),
                        Epoch::Handshake => Self::peek_crypto_chunk(
                            &self.egress.spaces[epoch as usize],
                            &self.egress.pending_crypto_handshake,
                            frame_room,
                        ),
                        Epoch::Application => None,
                    };
                    if let Some((record, data)) = chunk {
                        let offset = match record {
                            commit::Crypto::Pending { offset, .. }
                            | commit::Crypto::Retransmit { offset, .. } => offset,
                        };
                        if Self::encode_crypto(&mut frames, offset, data) {
                            crypto = Some(record);
                        }
                    }
                }
            }
            packet::CryptoMode::PtoProbe => {
                if let Some((delivery, data)) = self.pending_crypto_probe(epoch, frame_room)
                    && Self::encode_crypto(&mut frames, delivery.record.offset, data)
                {
                    crypto_probe = Some(delivery);
                } else {
                    frames.push(TYPE_PING);
                }
            }
        }

        if mode == packet::CryptoMode::Regular && frames.is_empty() {
            self.scratch_frames = frames;
            return None;
        }

        if epoch == Epoch::Initial && self.is_client && frames.len() < payload_limit {
            frames.resize(payload_limit, 0);
        }
        let sealed = self.seal_crypto_packet(dst, epoch, pn, &frames);
        frames.clear();
        self.scratch_frames = frames;
        let n = sealed?;
        let mut commit = commit::Packet::new(epoch, pn);
        commit.bytes = n;
        commit.ack_eliciting = mode == packet::CryptoMode::PtoProbe || crypto.is_some();
        commit.in_flight = commit.ack_eliciting;
        commit.ack_included = ack_included;
        commit.crypto = crypto;
        commit.crypto_probe = crypto_probe;
        commit.pto_probe = mode == packet::CryptoMode::PtoProbe;
        Some((n, commit))
    }

    fn build_one_rtt<const DATAGRAM: bool, const PTO_PROBE: bool>(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
    ) -> Option<(usize, commit::Packet)> {
        const { assert!(!(DATAGRAM && PTO_PROBE)) };
        let pn = self.egress.spaces[Epoch::Application as usize].next_pn;
        let packet_start = dst.len();
        let pn_off = ShortHeaderRef {
            dcid: &self.egress.peer_cid,
            packet_number: pn,
            pn_len: PN_LEN,
        }
        .encode_into(dst)
        .ok()?;
        let payload_start = dst.len();
        let payload_limit =
            payload_start.checked_add(self.short_payload_limit(max_packet_bytes))?;
        let mut frames = packet::Payload::new(dst, payload_start);
        let mut commit = commit::Packet::new(Epoch::Application, pn);
        let track_delivery = self.can_track_packet();
        if DATAGRAM {
            if !track_delivery
                && self.egress.datagram_congestion_control == datagram::CongestionControl::Standard
            {
                return None;
            }
            commit.ack_included =
                self.append_ack_frame(Epoch::Application, &mut frames, payload_limit);
            let data = self.egress.pending_datagrams.front()?;
            if data.len().saturating_add(1) > payload_limit.saturating_sub(frames.len()) {
                if commit.ack_included {
                } else {
                    return None;
                }
            } else {
                frames.push(0x30);
                frames.extend_from_slice(data);
                commit.datagram = true;
                commit.ack_eliciting = true;
            }
            if frames.is_empty() {
                return None;
            }
        } else if PTO_PROBE {
            commit.ack_included =
                self.append_ack_frame(Epoch::Application, &mut frames, payload_limit);
            let frame_room = payload_limit.saturating_sub(frames.len());
            if let Some((delivery, data)) =
                self.pending_crypto_probe(Epoch::Application, frame_room)
                && Self::encode_crypto(&mut frames, delivery.record.offset, data)
            {
                commit.crypto_probe = Some(delivery);
                commit.ack_eliciting = true;
            }
            while !commit.controls.is_full() {
                let next = self.control.next_probe(Epoch::Application, |handle| {
                    commit
                        .controls
                        .as_slice()
                        .iter()
                        .any(|delivery| delivery.probe == Some(handle))
                });
                let Some((handle, record)) = next else {
                    break;
                };
                if !self
                    .control
                    .encode_probe(&mut frames, payload_limit, record)
                {
                    break;
                }
                commit.push_control_delivery(commit::Delivery {
                    record,
                    probe: Some(handle),
                });
                commit.ack_eliciting = true;
            }
            while !commit.streams.is_full() {
                let next = self
                    .egress
                    .stream_deliveries
                    .next_probe(Epoch::Application, |handle| {
                        commit
                            .streams
                            .as_slice()
                            .iter()
                            .any(|delivery| delivery.probe == Some(handle))
                    });
                let Some((handle, record)) = next else {
                    break;
                };
                let room = payload_limit
                    .saturating_sub(frames.len().saturating_add(STREAM_FRAME_OVERHEAD));
                if record.len as usize > room {
                    break;
                }
                let Some(stream) = self.egress.streams_send.get(&record.stream_id) else {
                    self.egress.stream_deliveries.remove(handle);
                    continue;
                };
                let Ok(len) = usize::try_from(record.len) else {
                    continue;
                };
                if !Self::append_stream_frame(
                    &mut frames,
                    payload_limit,
                    record.stream_id,
                    record.offset,
                    record.fin,
                    stream,
                    len,
                ) {
                    break;
                }
                commit.push_stream_delivery(commit::Delivery {
                    record,
                    probe: Some(handle),
                });
                commit.ack_eliciting = true;
            }
            if !commit.ack_eliciting {
                if !Self::append_frame(&mut frames, payload_limit, &Frame::Ping) {
                    return None;
                }
                commit.ack_eliciting = true;
            }
            commit.pto_probe = true;
        } else {
            commit.ack_included =
                self.append_ack_frame(Epoch::Application, &mut frames, payload_limit);
            let has_control = track_delivery && !self.control.is_empty();
            if has_control && let Some(cursor) = self.control.prefix() {
                Self::append_pending_controls(
                    &self.control,
                    &mut frames,
                    payload_limit,
                    &mut commit,
                    cursor,
                );
            }
            let frame_room = payload_limit.saturating_sub(frames.len());
            let crypto = track_delivery
                .then(|| {
                    Self::peek_crypto_chunk(
                        &self.egress.spaces[Epoch::Application as usize],
                        &self.egress.pending_crypto_app,
                        frame_room,
                    )
                })
                .flatten();
            if let Some((crypto, data)) = crypto {
                let offset = match crypto {
                    commit::Crypto::Pending { offset, .. }
                    | commit::Crypto::Retransmit { offset, .. } => offset,
                };
                if Self::encode_crypto(&mut frames, offset, data) {
                    commit.crypto = Some(crypto);
                    commit.ack_eliciting = true;
                }
            }
            if has_control && let Some(records) = self.control.only_path_responses() {
                Self::append_path_controls(
                    &self.control,
                    records,
                    &mut frames,
                    payload_limit,
                    &mut commit,
                );
            } else if has_control && let Some(records) = self.control.only_path_challenges() {
                Self::append_path_controls(
                    &self.control,
                    records,
                    &mut frames,
                    payload_limit,
                    &mut commit,
                );
            } else if has_control && let Some(cursor) = self.control.suffix() {
                Self::append_pending_controls(
                    &self.control,
                    &mut frames,
                    payload_limit,
                    &mut commit,
                    cursor,
                );
            }
            while track_delivery
                && !commit.streams.is_full()
                && self
                    .egress
                    .stream_deliveries
                    .has_room(commit.streams.len() + 1)
            {
                let room = payload_limit
                    .saturating_sub(frames.len().saturating_add(STREAM_FRAME_OVERHEAD));
                let pos = self.egress.spaces[Epoch::Application as usize]
                    .stream_retransmit
                    .iter()
                    .enumerate()
                    .find(|(_, (sid, off, len, fin))| {
                        (*len as usize) <= room
                            && !commit.streams.as_slice().iter().any(|delivery| {
                                let record = delivery.record;
                                (record.stream_id, record.offset, record.len, record.fin)
                                    == (*sid, *off, *len, *fin)
                            })
                    })
                    .map(|(position, _)| position);
                let Some(pos) = pos else {
                    break;
                };
                let (sid, off, len, fin) =
                    self.egress.spaces[Epoch::Application as usize].stream_retransmit[pos];
                let Some(stream) = self.egress.streams_send.get(&sid) else {
                    self.egress.spaces[Epoch::Application as usize]
                        .stream_retransmit
                        .swap_remove(pos);
                    continue;
                };
                let Ok(len_usize) = usize::try_from(len) else {
                    continue;
                };
                if !Self::append_stream_frame(
                    &mut frames,
                    payload_limit,
                    sid,
                    off,
                    fin,
                    stream,
                    len_usize,
                ) {
                    break;
                }
                commit.push_stream(delivery::Stream {
                    stream_id: sid,
                    offset: off,
                    len,
                    fin,
                    retransmit: true,
                });
                commit.ack_eliciting = true;
            }
            let mut idx = 0;
            while track_delivery
                && idx < self.egress.scratch_pending.len()
                && !commit.streams.is_full()
                && self
                    .egress
                    .stream_deliveries
                    .has_room(commit.streams.len() + 1)
            {
                let id = self.egress.scratch_pending[idx];
                let Some(entry) = self.egress.streams_send.get(&id) else {
                    idx += 1;
                    continue;
                };
                let stream_limit = entry.credit.limit();
                let stream = &entry.stream;
                let stream_budget = stream_limit.saturating_sub(stream.next_offset());
                let packet_fresh_bytes = commit
                    .streams
                    .as_slice()
                    .iter()
                    .filter(|delivery| !delivery.record.retransmit)
                    .map(|delivery| delivery.record.len)
                    .sum::<u64>();
                let conn_budget = self.egress.peer_max_data.saturating_sub(
                    self.egress
                        .peer_total_sent
                        .saturating_add(packet_fresh_bytes),
                );
                let flow_take = stream_budget.min(conn_budget);
                let fin_only = stream.unsent_len() == 0 && stream.would_fin(0);
                if flow_take == 0 && !fin_only {
                    let has_pending = stream.has_pending();
                    if conn_budget == 0
                        && !commit.controls.is_full()
                        && self
                            .control
                            .data_blocked_sendable(self.egress.peer_max_data)
                        && !commit.contains_control(delivery::Control::DataBlocked(
                            self.egress.peer_max_data,
                        ))
                        && self.control.has_delivery_room(commit.controls.len() + 1)
                    {
                        let record = delivery::Control::DataBlocked(self.egress.peer_max_data);
                        self.control.queue_data_blocked(self.egress.peer_max_data);
                        if self
                            .control
                            .encode_blocked(&mut frames, payload_limit, record)
                        {
                            commit.push_control(record);
                            commit.ack_eliciting = true;
                        }
                    }
                    if stream_budget == 0
                        && has_pending
                        && !commit.controls.is_full()
                        && self.control.stream_data_blocked_sendable(id, stream_limit)
                        && self.control.has_delivery_room(commit.controls.len() + 1)
                    {
                        let record = delivery::Control::StreamDataBlocked(id, stream_limit);
                        self.control.queue_stream_data_blocked(id, stream_limit);
                        if self
                            .control
                            .encode_blocked(&mut frames, payload_limit, record)
                        {
                            commit.push_control(record);
                            commit.ack_eliciting = true;
                        }
                    }
                    idx += 1;
                    continue;
                }
                let packet_room = payload_limit
                    .saturating_sub(frames.len().saturating_add(STREAM_FRAME_OVERHEAD));
                let take = flow_take.min(packet_room as u64) as usize;
                if take == 0 && !fin_only {
                    break;
                }
                if stream.blocked() {
                    idx += 1;
                    continue;
                }
                let offset = stream.next_offset();
                let n = take.min(stream.unsent_len());
                if n == 0 && !stream.would_fin(0) {
                    idx += 1;
                    continue;
                }
                let fin_now = stream.would_fin(n);
                if !Self::append_stream_frame(
                    &mut frames,
                    payload_limit,
                    id,
                    offset,
                    fin_now,
                    stream,
                    n,
                ) {
                    break;
                }
                commit.push_stream(delivery::Stream {
                    stream_id: id,
                    offset,
                    len: n as u64,
                    fin: fin_now,
                    retransmit: false,
                });
                commit.ack_eliciting = true;
                idx += 1;
            }
        }

        if frames.is_empty() {
            return None;
        }

        let seg = self
            .egress
            .app_w
            .as_ref()?
            .protect_short_in_place(
                frames.out_mut(),
                packet_start,
                payload_start,
                pn,
                pn_off,
                PN_LEN as usize,
            )
            .ok()?;

        commit.bytes = seg;
        commit.in_flight = commit.ack_eliciting
            && !(commit.datagram
                && self.egress.datagram_congestion_control
                    == datagram::CongestionControl::Uncongested);
        Some((seg, commit))
    }

    fn build_zero_rtt(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
        pto_probe: bool,
    ) -> Option<(usize, commit::Packet)> {
        self.egress.zero_rtt_w.as_ref()?;
        if !(if pto_probe {
            self.can_track_probe(Epoch::Application)
        } else {
            self.can_track_packet()
        }) {
            return None;
        }
        let payload_limit = self.handshake_payload_limit(max_packet_bytes);
        let pn = self.egress.spaces[Epoch::Application as usize].next_pn;
        let mut frames = take(&mut self.scratch_frames);
        frames.clear();
        let mut commit = commit::Packet::new(Epoch::Application, pn);
        commit.early_data = true;
        if pto_probe {
            while !commit.streams.is_full() {
                let next = self
                    .egress
                    .stream_deliveries
                    .next_probe(Epoch::Application, |handle| {
                        commit
                            .streams
                            .as_slice()
                            .iter()
                            .any(|delivery| delivery.probe == Some(handle))
                    });
                let Some((handle, record)) = next else {
                    break;
                };
                let room = payload_limit
                    .saturating_sub(frames.len().saturating_add(STREAM_FRAME_OVERHEAD));
                if record.len as usize > room {
                    break;
                }
                let Some(stream) = self.egress.streams_send.get(&record.stream_id) else {
                    self.egress.stream_deliveries.remove(handle);
                    continue;
                };
                let Ok(len) = usize::try_from(record.len) else {
                    continue;
                };
                if !Self::append_stream_frame(
                    &mut frames,
                    payload_limit,
                    record.stream_id,
                    record.offset,
                    record.fin,
                    stream,
                    len,
                ) {
                    break;
                }
                commit.push_stream_delivery(commit::Delivery {
                    record,
                    probe: Some(handle),
                });
                commit.ack_eliciting = true;
            }
            if !commit.ack_eliciting {
                if !Self::append_frame(&mut frames, payload_limit, &Frame::Ping) {
                    self.scratch_frames = frames;
                    return None;
                }
                commit.ack_eliciting = true;
            }
            commit.pto_probe = true;
        }
        let mut packet_fresh_bytes = 0u64;
        for index in 0..if pto_probe {
            0
        } else {
            self.egress.scratch_pending.len()
        } {
            if commit.streams.is_full()
                || !self
                    .egress
                    .stream_deliveries
                    .has_room(commit.streams.len() + 1)
            {
                break;
            }
            let id = self.egress.scratch_pending[index];
            let Some(entry) = self.egress.streams_send.get(&id) else {
                continue;
            };
            let stream_limit = entry.credit.limit();
            let stream = &entry.stream;
            let stream_budget = stream_limit.saturating_sub(stream.next_offset());
            let conn_budget = self.peer_transport_params.as_ref().map_or(u64::MAX, |_| {
                self.egress.peer_max_data.saturating_sub(
                    self.egress
                        .peer_total_sent
                        .saturating_add(packet_fresh_bytes),
                )
            });
            let packet_room =
                payload_limit.saturating_sub(frames.len().saturating_add(STREAM_FRAME_OVERHEAD));
            let take = stream_budget.min(conn_budget).min(packet_room as u64) as usize;
            let fin_only = stream.unsent_len() == 0 && stream.would_fin(0);
            if take == 0 && !fin_only {
                continue;
            }
            if stream.blocked() {
                continue;
            }
            let offset = stream.next_offset();
            let n = take.min(stream.unsent_len());
            if n == 0 && !stream.would_fin(0) {
                continue;
            }
            let fin_now = stream.would_fin(n);
            if !Self::append_stream_frame(
                &mut frames,
                payload_limit,
                id,
                offset,
                fin_now,
                stream,
                n,
            ) {
                break;
            }
            commit.push_stream(delivery::Stream {
                stream_id: id,
                offset,
                len: n as u64,
                fin: fin_now,
                retransmit: false,
            });
            packet_fresh_bytes = packet_fresh_bytes.saturating_add(n as u64);
            commit.ack_eliciting = true;
            if payload_limit.saturating_sub(frames.len()) <= STREAM_FRAME_OVERHEAD {
                break;
            }
        }
        if frames.is_empty() {
            self.scratch_frames = frames;
            return None;
        }
        let body_len_after_pn = frames.len() + TAG_LEN;
        let mut header = take(&mut self.scratch_header);
        header.clear();
        let pn_off = LongHeader {
            version: QUIC_V1,
            packet_type: LONG_ZERO_RTT,
            dcid: &self.egress.peer_cid,
            scid: &self.local_cid,
            token: None,
            packet_number: pn,
            packet_number_len: PN_LEN,
        }
        .encode_into(&mut header, body_len_after_pn)
        .ok()?;
        let n = self
            .egress
            .zero_rtt_w
            .as_ref()?
            .encrypt_long_into(dst, &header, &frames, pn, pn_off, PN_LEN as usize)
            .ok()?;
        header.clear();
        self.scratch_header = header;
        frames.clear();
        self.scratch_frames = frames;
        commit.bytes = n;
        commit.in_flight = true;
        Some((n, commit))
    }

    fn build_one_rtt_probe(
        &mut self,
        dst: &mut Vec<u8>,
        target_size: u64,
        max_packet_bytes: usize,
    ) -> Option<(usize, commit::Packet)> {
        if !self.can_track_packet() {
            return None;
        }
        let target_size = target_size.min(u64::try_from(max_packet_bytes).unwrap_or(u64::MAX));
        let pn = self.egress.spaces[Epoch::Application as usize].next_pn;

        let mut frames = take(&mut self.scratch_frames);
        frames.clear();
        frames.push(TYPE_PING);
        let header_overhead = 1 + self.egress.peer_cid.len() + PN_LEN as usize;
        let payload_target = (target_size as usize).saturating_sub(header_overhead + TAG_LEN);
        if payload_target == 0 {
            self.scratch_frames = frames;
            return None;
        }
        while frames.len() < payload_target {
            frames.push(TYPE_PADDING);
        }

        let mut header = take(&mut self.scratch_header);
        header.clear();
        let pn_off = ShortHeaderRef {
            dcid: &self.egress.peer_cid,
            packet_number: pn,
            pn_len: PN_LEN,
        }
        .encode_into(&mut header)
        .ok()?;
        let n = self
            .egress
            .app_w
            .as_ref()?
            .encrypt_short_into(dst, &header, &frames, pn, pn_off, PN_LEN as usize)
            .ok()?;

        header.clear();
        self.scratch_header = header;
        frames.clear();
        self.scratch_frames = frames;
        let mut commit = commit::Packet::new(Epoch::Application, pn);
        commit.bytes = n;
        commit.ack_eliciting = true;
        commit.in_flight = true;
        commit.pmtud_probe = Some(target_size);
        Some((n, commit))
    }

    fn build_one_rtt_close(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
    ) -> Option<(usize, commit::Packet)> {
        let close = self.egress.pending_close.as_ref()?;
        let payload_limit = self.short_payload_limit(max_packet_bytes);
        let pn = self.egress.spaces[Epoch::Application as usize].next_pn;

        let fixed = 1
            + Self::varint_len(close.error_code as usize)
            + if close.is_application {
                0
            } else {
                Self::varint_len(close.frame_type as usize)
            };
        if fixed + 1 > payload_limit {
            return None;
        }
        let mut reason_len = close.reason.len();
        while fixed + Self::varint_len(reason_len) + reason_len > payload_limit {
            let encoded = fixed + Self::varint_len(reason_len) + reason_len;
            reason_len = reason_len.saturating_sub((encoded - payload_limit).max(1));
        }
        let mut frames = take(&mut self.scratch_frames);
        frames.clear();
        frames.push(if close.is_application { 0x1d } else { 0x1c });
        VarInt::new(close.error_code)?.encode(&mut frames);
        if !close.is_application {
            VarInt::new(close.frame_type)?.encode(&mut frames);
        }
        VarInt::from_usize(reason_len)?.encode(&mut frames);
        frames.extend_from_slice(&close.reason[..reason_len]);

        let mut header = take(&mut self.scratch_header);
        header.clear();
        let pn_off = ShortHeaderRef {
            dcid: &self.egress.peer_cid,
            packet_number: pn,
            pn_len: PN_LEN,
        }
        .encode_into(&mut header)
        .ok()?;
        let n = self
            .egress
            .app_w
            .as_ref()?
            .encrypt_short_into(dst, &header, &frames, pn, pn_off, PN_LEN as usize)
            .ok()?;

        header.clear();
        self.scratch_header = header;
        frames.clear();
        self.scratch_frames = frames;
        let mut commit = commit::Packet::new(Epoch::Application, pn);
        commit.bytes = n;
        commit.close = true;
        Some((n, commit))
    }

    fn allows_emit_for(&self, cargo: packet::Cargo, now: Instant) -> bool {
        if !self.anti_amp_allows() {
            return false;
        }
        match cargo {
            packet::Cargo::CryptoOrAck => {
                self.egress.cc.allows_send() && self.egress.pacer.allows_send(now)
            }
            packet::Cargo::DatagramOnly => match self.egress.datagram_congestion_control {
                datagram::CongestionControl::Standard => {
                    self.egress.cc.allows_send() && self.egress.pacer.allows_send(now)
                }
                datagram::CongestionControl::Uncongested => true,
            },
        }
    }

    pub fn next_send_time(&self) -> Instant {
        self.egress.pacer.next_release_time()
    }

    pub(crate) fn has_pending_output(&self) -> bool {
        if self.egress.state == State::Closed {
            return false;
        }
        if self.egress.pto_probe_allowance != 0 {
            return true;
        }
        if self.egress.initial_w.is_some()
            && (self.has_initial_crypto()
                || self.egress.spaces[Epoch::Initial as usize].ack_pending)
        {
            return true;
        }
        if self.egress.zero_rtt_w.is_some()
            && self.egress.app_w.is_none()
            && !self.egress.send_schedule.is_empty()
        {
            return true;
        }
        if self.egress.handshake_w.is_some()
            && (self.has_handshake_crypto()
                || self.egress.spaces[Epoch::Handshake as usize].ack_pending)
        {
            return true;
        }
        self.egress.app_w.is_some()
            && (self.egress.pending_close.is_some()
                || self.control.overflowed()
                || self.egress.spaces[Epoch::Application as usize].ack_pending
                || !self.egress.pending_datagrams.is_empty()
                || !self.control.is_empty()
                || !self.egress.pending_crypto_app.is_empty()
                || !self.egress.spaces[Epoch::Application as usize]
                    .crypto_retransmit
                    .is_empty()
                || !self.egress.spaces[Epoch::Application as usize]
                    .stream_retransmit
                    .is_empty()
                || !self.egress.send_schedule.is_empty()
                || self.egress.pmtud.next_probe().is_some())
    }

    fn has_sendable_control(&self) -> bool {
        self.control.has_sendable()
    }

    fn has_sendable_stream(&self) -> bool {
        if !self.egress.spaces[Epoch::Application as usize]
            .stream_retransmit
            .is_empty()
        {
            return true;
        }
        let conn_budget = self
            .egress
            .peer_max_data
            .saturating_sub(self.egress.peer_total_sent);
        self.egress.send_schedule.iter().any(|scheduled| {
            let stream_id = scheduled.stream_id();
            let Some(entry) = self.egress.streams_send.get(&stream_id) else {
                return false;
            };
            let stream = &entry.stream;
            if !stream.is_scheduled(scheduled.generation())
                || !stream.has_pending()
                || stream.blocked()
            {
                return false;
            }
            if stream.unsent_len() == 0 && stream.would_fin(0) {
                return true;
            }
            let stream_limit = entry.credit.limit();
            let stream_budget = stream_limit.saturating_sub(stream.next_offset());
            (conn_budget != 0 && stream_budget != 0)
                || (conn_budget == 0
                    && self
                        .control
                        .data_blocked_sendable(self.egress.peer_max_data))
                || (stream_budget == 0
                    && self
                        .control
                        .stream_data_blocked_sendable(stream_id, stream_limit))
        })
    }

    fn has_sendable_output(&self) -> bool {
        self.egress.pto_probe_allowance != 0
            || (self.egress.initial_w.is_some()
                && (self.has_initial_crypto()
                    || self.egress.spaces[Epoch::Initial as usize].ack_pending))
            || (self.egress.zero_rtt_w.is_some()
                && self.egress.app_w.is_none()
                && self.has_sendable_stream())
            || (self.egress.handshake_w.is_some()
                && (self.has_handshake_crypto()
                    || self.egress.spaces[Epoch::Handshake as usize].ack_pending))
            || (self.egress.app_w.is_some()
                && (self.egress.pending_close.is_some()
                    || self.control.overflowed()
                    || self.egress.spaces[Epoch::Application as usize].ack_pending
                    || !self.egress.pending_datagrams.is_empty()
                    || self.has_sendable_control()
                    || !self.egress.pending_crypto_app.is_empty()
                    || !self.egress.spaces[Epoch::Application as usize]
                        .crypto_retransmit
                        .is_empty()
                    || self.has_sendable_stream()
                    || self.egress.pmtud.next_probe().is_some()))
    }

    pub(crate) fn send_deadline(&self, now: Instant) -> Option<Instant> {
        if !self.has_pending_output() {
            return None;
        }
        if self.egress.pto_probe_allowance != 0 {
            return self.anti_amp_allows().then_some(now);
        }
        if !self.has_sendable_output() {
            return self.next_timer();
        }
        if !self.egress.pending_datagrams.is_empty()
            && self.egress.datagram_congestion_control == datagram::CongestionControl::Uncongested
        {
            return Some(now);
        }
        if !self.anti_amp_allows() || !self.egress.cc.allows_send() {
            return self.next_timer();
        }
        Some(self.next_send_time().max(now))
    }

    fn wire_sent(&mut self, bytes: u64, ack_eliciting: bool, now: Instant) {
        self.egress.cc.packet_sent(bytes, ack_eliciting);
        let srtt = self.egress.rtt.smoothed_rtt.unwrap_or(INITIAL_RTT);
        self.egress
            .pacer
            .packet_sent(bytes, now, self.egress.cc.cwnd, srtt);
    }

    pub fn try_send_datagram(&mut self, data: Vec<u8>) -> Result<(), TrySendError<Vec<u8>>> {
        if self.egress.state == State::Closed {
            return Err(TrySendError::Closed(data));
        }
        let Some(max) = self.max_datagram_payload() else {
            return Err(TrySendError::Unsupported(data));
        };
        if data.len() > max {
            return Err(TrySendError::TooLarge(data));
        }
        if self.egress.pending_datagrams.len() >= self.egress.pending_datagrams_capacity {
            return Err(TrySendError::Full(data));
        }
        self.egress.pending_datagrams.push_back(data);
        Ok(())
    }

    pub fn max_datagram_payload(&self) -> Option<usize> {
        let peer = self
            .peer_transport_params
            .as_ref()
            .and_then(|tp| tp.max_datagram_frame_size)?;
        if peer == 0 {
            return None;
        }
        let by_peer = (peer as usize).saturating_sub(1);
        let overhead = 1 + self.egress.peer_cid.len() + PN_LEN as usize + 16;
        let by_pmtu = (MAX_DATAGRAM_SIZE as usize).saturating_sub(overhead);
        let by_pmtu_payload = by_pmtu.saturating_sub(1);
        Some(by_peer.min(by_pmtu_payload))
    }

    pub fn recv_datagram(&mut self) -> Option<Vec<u8>> {
        self.incoming_datagrams.pop_front()
    }

    pub fn is_handshaking(&self) -> bool {
        self.egress.state == State::Handshaking
    }

    pub fn is_established(&self) -> bool {
        self.egress.state == State::Established
    }

    pub fn is_closed(&self) -> bool {
        self.egress.state == State::Closed
    }

    pub fn peer_transport_params(&self) -> Option<&transport_params::Params> {
        self.peer_transport_params.as_ref()
    }

    pub fn handshake_confirmed(&self) -> bool {
        self.egress.handshake_confirmed
    }

    pub fn peer_address_validated(&self) -> bool {
        self.egress.peer_address_validated
    }

    fn anti_amp_allows(&self) -> bool {
        self.egress.peer_address_validated || self.anti_amp_remaining() != 0
    }

    fn anti_amp_remaining(&self) -> u64 {
        if self.egress.peer_address_validated {
            return u64::MAX;
        }
        self.egress
            .amplification_received
            .saturating_mul(3)
            .saturating_sub(self.egress.amplification_sent)
    }

    fn emission_ceiling(&self, requested: usize) -> Option<usize> {
        let remaining = usize::try_from(self.anti_amp_remaining()).unwrap_or(usize::MAX);
        let ceiling = requested.min(remaining);
        (ceiling != 0).then_some(ceiling)
    }

    pub fn amplification_received(&self) -> u64 {
        self.egress.amplification_received
    }

    pub fn cwnd(&self) -> u64 {
        self.egress.cc.cwnd
    }
    pub fn bytes_in_flight(&self) -> u64 {
        self.egress.cc.bytes_in_flight
    }
    pub fn ssthresh(&self) -> u64 {
        self.egress.cc.ssthresh
    }

    pub fn close(&mut self, error_code: u64, reason: Vec<u8>) {
        if self.egress.state != State::Closed && self.egress.pending_close.is_none() {
            self.egress.pending_close = Some(PendingClose {
                is_application: true,
                error_code,
                frame_type: 0,
                reason,
            });
        }
    }

    fn effective_idle_timeout(&self) -> Option<Duration> {
        let local_ms = self.local_max_idle_timeout.as_millis() as u64;
        let peer_ms = self
            .peer_transport_params
            .as_ref()
            .map(|tp| tp.max_idle_timeout_ms)
            .unwrap_or(0);
        let effective = match (local_ms, peer_ms) {
            (0, 0) => return None,
            (0, p) => p,
            (l, 0) => l,
            (l, p) => l.min(p),
        };
        let peer_max_ack_delay = if self.egress.state == State::Established {
            self.peer_transport_params
                .as_ref()
                .map(|tp| Duration::from_millis(tp.max_ack_delay_ms))
                .unwrap_or(Duration::ZERO)
        } else {
            Duration::ZERO
        };
        let minimum = self
            .egress
            .rtt
            .pto_period(peer_max_ack_delay)
            .saturating_mul(3);
        Some(Duration::from_millis(effective).max(minimum))
    }

    fn idle_deadline(&self) -> Option<Instant> {
        self.effective_idle_timeout()
            .map(|d| self.egress.last_activity + d)
    }

    pub fn unacked_count(&self, epoch_ix: usize) -> usize {
        if epoch_ix == Epoch::Application as usize {
            self.egress.packet_journals.count_epoch(Epoch::Application)
        } else {
            self.egress.spaces[epoch_ix].sent.len()
        }
    }

    pub fn smoothed_rtt(&self) -> Option<Duration> {
        self.egress.rtt.smoothed_rtt
    }

    pub fn min_rtt(&self) -> Option<Duration> {
        self.egress.rtt.min_rtt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: fn() = || {
        fn assert_send<T: Send>() {}
        assert_send::<journal::Table>();
    };

    #[test]
    fn packet_journal_core_fits_one_cache_line() {
        assert_eq!(std::mem::size_of::<journal::Packet>(), 48);
    }

    #[test]
    fn packet_commit_has_no_drop_glue() {
        assert!(!std::mem::needs_drop::<commit::Packet>());
    }

    #[test]
    fn max_stream_data_opens_peer_bidi_and_its_lower_streams() {
        let signing = SigningKey::from_seed(&[0x71; 32]).unwrap();
        let public_key = *signing.pubkey().unwrap();
        let mut conn =
            Connection::new_client(vec![1; 8], vec![2; 8], public_key, Config::default())
                .expect("valid client");
        conn.egress.state = State::Established;
        conn.local_max_streams = [3, 3];
        conn.peer_transport_params = Some(Params::default());

        let frame: Frame = Frame::MaxStreamData {
            stream_id: VarInt::new(9).unwrap(),
            maximum_stream_data: VarInt::new(37).unwrap(),
        };
        let mut body = Vec::new();
        frame.encode(&mut body).unwrap();
        let mut read = |_: &mut SideKind,
                        _: shin::connection::Epoch,
                        _: &[u8],
                        _: &mut ShinEvents<'_>|
         -> Result<(), DriveError<Error>> { Ok(()) };

        conn.process_packet_body(Epoch::Application, 0, &body, Instant::now(), &mut read)
            .unwrap();

        assert!(conn.peer_opened_streams.contains(9));
        assert_eq!(conn.egress.streams_send[&9].credit.limit(), 37);
        assert!(conn.stream_send(1, b"implicitly opened").is_ok());
    }
}
