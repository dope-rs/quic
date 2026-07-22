use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Bound::{Excluded, Unbounded};
use std::ops::Range;
use std::time::{Duration, Instant};

use shin::Event;
use shin::sig::SigningKey;
use subtle::ConstantTimeEq;

use crate::ConnectError;
use crate::TrySendError;
use crate::clock::WallClock;
use crate::early_data::EarlyDataReplayGuard;
use crate::early_data::SharedEarlyDataReplayCache;
use crate::frame::{AckRanges, Frame, TYPE_PADDING, TYPE_PING};
use crate::new_reno::{MAX_DATAGRAM_SIZE, NewReno};
use crate::pacer::Pacer;
use crate::packet::RetryPacket;
use crate::packet::ZeroRttHeader;
use crate::packet::{
    HandshakeHeader, InitialHeader, LONG_HANDSHAKE, LONG_INITIAL, LONG_ZERO_RTT, LongHeader,
    QUIC_V1, ShortHeader, encode_long_header_into, encode_short_header_into,
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
use crate::stream::SendStream;
use crate::transport_params;
use crate::transport_params::DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;
use crate::transport_params::Params;
use crate::transport_params::TransportParameterError;
use crate::varint::VarInt;
use core::array::from_fn;
use shin::client;
use shin::client::Client;
use shin::client::ClientCertSource;
use shin::client::Resumption;
use shin::client::Verifier;
use shin::record::CipherSuite;
use shin::server;
use shin::server::CertSource;
use shin::server::ClientAuth;
use shin::server::ClientCertVerifier;
use shin::server::ClientIdentity;
use shin::server::Server;
use shin::ticket::TicketKeys;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::mem::take;
use std::rc::Rc;

mod batch;
mod commit;
mod delivery;
mod journal;
mod reassembly;

pub use batch::PacketBatch;
use batch::{PacketSink, PacketSlot};
use commit::*;
use delivery::*;
use journal::*;
use reassembly::*;

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
const MAX_QUEUE_CAPACITY: usize = 65_536;
const MAX_STREAMS: u64 = 65_536;
const MAX_FLOW_CONTROL_CREDIT: u64 = 1 << 30;
const MAX_ACTIVE_CONNECTION_IDS: u64 = 8;
const MAX_PENDING_RETIRE_CONNECTION_IDS: usize = 64;
const MAX_SESSION_TICKETS: usize = 8;
const MAX_SESSION_TICKET_BYTES: usize = 256 * 1024;

struct AckReceipt<'a> {
    largest: u64,
    delay_microseconds: u64,
    first_range: u64,
    additional_ranges: AckRanges<'a>,
    packets: Vec<SentPacket>,
}

struct ParsedAckRanges {
    bytes: Range<usize>,
    count: u64,
}

type ParsedFrame = Frame<Range<usize>, ParsedAckRanges>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnHandle(pub u64);

impl ConnHandle {
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
pub enum ConnError {
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

impl_error!(ConnError {
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

impl From<TransportParameterError> for ConnError {
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

struct DynVerifier(Rc<dyn ClientCertVerifier>);

impl ClientCertVerifier for DynVerifier {
    fn verify(&self, identity: &ClientIdentity<'_>) -> bool {
        self.0.verify(identity)
    }
}

enum ServerSide {
    Plain(Server<TlsClock, EarlyDataReplayGuard>),
    Mtls(Server<TlsClock, EarlyDataReplayGuard, DynVerifier>),
}

impl ServerSide {
    fn read(&mut self, epoch: shin::Epoch, data: &[u8]) -> Result<Vec<Event>, shin::Error> {
        match self {
            Self::Plain(s) => s.read(epoch, data),
            Self::Mtls(s) => s.read(epoch, data),
        }
    }

    fn negotiated_cipher_suite(&self) -> Option<CipherSuite> {
        match self {
            Self::Plain(s) => s.negotiated_cipher_suite(),
            Self::Mtls(s) => s.negotiated_cipher_suite(),
        }
    }
}

enum SideKind {
    Client(Box<Client<TlsClock>>),
    Server(Box<ServerSide>),
}

impl SideKind {
    fn read(&mut self, epoch: shin::Epoch, data: &[u8]) -> Result<Vec<Event>, shin::Error> {
        match self {
            Self::Client(c) => c.read(epoch, data),
            Self::Server(s) => s.read(epoch, data),
        }
    }

    fn negotiated_cipher_suite(&self) -> Option<CipherSuite> {
        match self {
            Self::Client(c) => c.negotiated_cipher_suite(),
            Self::Server(s) => s.negotiated_cipher_suite(),
        }
    }
}

pub struct Conn {
    side: SideKind,
    is_client: bool,
    local_cid: Vec<u8>,
    peer_cid: Vec<u8>,
    original_dcid: Vec<u8>,
    peer_first_scid: Option<Vec<u8>>,

    initial_w: Option<PacketProtection>,
    initial_r: Option<PacketProtection>,
    handshake_w: Option<PacketProtection>,
    handshake_r: Option<PacketProtection>,
    app_w: Option<PacketProtection>,
    app_r: Option<PacketProtection>,
    zero_rtt_w: Option<PacketProtection>,
    zero_rtt_r: Option<PacketProtection>,
    pending_synth_eod: bool,

    spaces: [PnSpace; 3],
    rtt: RttTracker,
    pto_count: u32,
    loss_timer: Option<Instant>,
    pto_probe_allowance: u8,
    pto_probe_epoch: Option<Epoch>,

    scratch_frames: Vec<u8>,
    scratch_pending: Vec<u64>,
    scratch_header: Vec<u8>,
    scratch_parsed_frames: Vec<ParsedFrame>,
    decrypt_wire: Vec<u8>,
    packet_journals: PacketJournalTable,
    crypto_deliveries: DeliveryTable<CryptoRecord>,
    control_deliveries: DeliveryTable<ControlRecord>,
    stream_deliveries: DeliveryTable<StreamRecord>,
    scratch_stream_cleanup: Vec<u64>,
    stream_schedule_cursor: Option<u64>,

    pending_crypto_initial: Vec<u8>,
    pending_crypto_handshake: Vec<u8>,
    pending_datagrams: VecDeque<Vec<u8>>,
    incoming_datagrams: VecDeque<Vec<u8>>,
    incoming_datagrams_capacity: usize,
    peer_transport_params_raw: Option<Vec<u8>>,
    peer_transport_params: Option<transport_params::Params>,
    state: State,
    sent_initial: bool,

    handshake_done_pending: bool,
    handshake_confirmed: bool,

    pending_close: Option<PendingClose>,

    last_activity: Instant,
    local_max_idle_timeout: Duration,

    peer_address_validated: bool,
    amplification_received: u64,
    amplification_sent: u64,

    cc: NewReno,
    pacer: Pacer,
    pmtud: Pmtud,
    packet_ceiling: usize,
    pmtud_probe_pn: Option<u64>,
    datagram_congestion_control: DatagramCongestionControl,
    pending_datagrams_capacity: usize,
    cid_prefix: Option<u8>,
    stateless_reset_secret: Option<[u8; 32]>,
    stateless_reset_received: bool,
    pending_path_responses: Vec<[u8; 8]>,
    pending_path_challenges: Vec<[u8; 8]>,
    outstanding_path_challenges: Vec<[u8; 8]>,
    validated_path_tokens: Vec<[u8; 8]>,

    local_cids: BTreeMap<u64, Vec<u8>>,
    peer_cids: BTreeMap<u64, (Vec<u8>, [u8; 16])>,
    local_active_connection_id_limit: u64,
    next_local_cid_seq: u64,
    new_cid_pending: Vec<(u64, Vec<u8>, [u8; 16])>,
    retire_pending: BTreeSet<u64>,
    cids_to_register: Vec<Vec<u8>>,
    auto_issued: bool,

    retry_token: Vec<u8>,
    retry_processed: bool,

    streams_recv: BTreeMap<u64, RecvStream>,
    streams_send: BTreeMap<u64, SendStream>,
    stream_events: VecDeque<StreamEvent>,
    pending_stream_events: BTreeMap<(u64, u8), ()>,
    stream_events_capacity: usize,
    next_local_bidi_stream: u64,
    local_max_streams_bidi: u64,
    initial_max_streams_bidi: u64,
    peer_bidi_closed: u64,
    max_streams_bidi_pending: bool,
    next_local_uni_stream: u64,
    local_max_streams_uni: u64,
    opened_local_bidi_streams: u64,
    opened_local_uni_streams: u64,

    peer_max_data: u64,
    peer_total_sent: u64,
    peer_max_stream_data: BTreeMap<u64, PeerStreamSendState>,
    blocked_data_emitted: bool,
    blocked_stream_emitted: BTreeMap<u64, ()>,

    local_max_data: u64,
    conn_recv_total: u64,
    local_max_stream_data: BTreeMap<u64, u64>,
    local_max_data_pending: bool,
    local_max_stream_data_pending: BTreeMap<u64, ()>,
    local_initial_max_stream_data_bidi_local: u64,
    local_initial_max_stream_data_bidi_remote: u64,
    local_initial_max_stream_data_uni: u64,

    pending_resets: BTreeMap<u64, (u64, u64)>,
    pending_stop_sending: BTreeMap<u64, u64>,

    pending_crypto_app: Vec<u8>,
    received_tickets: VecDeque<SessionTicket>,
    received_ticket_bytes: usize,
    pending_resumption_psk: Option<[u8; 32]>,
    recv_crypto: [CryptoReassembly; 3],
}

#[derive(Debug, Clone)]
pub struct SessionTicket {
    pub ticket_lifetime: u32,
    pub ticket_age_add: u32,
    pub ticket_nonce: Vec<u8>,
    pub ticket: Vec<u8>,
    pub psk: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    NotEstablished,
    PeerLimit,
    IdOverflow,
    InvalidStream,
    ValueOutOfRange,
}

impl_error!(StreamError {
    Self::NotEstablished => "connection is not established",
    Self::PeerLimit => "peer stream limit reached",
    Self::IdOverflow => "stream ID space exhausted",
    Self::InvalidStream => "invalid stream operation",
    Self::ValueOutOfRange => "stream value is out of range",
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    Data { stream_id: u64 },
    Finished { stream_id: u64 },
    Reset { stream_id: u64, error_code: u64 },
    Stopped { stream_id: u64, error_code: u64 },
}

impl StreamEvent {
    fn key(&self) -> (u64, u8) {
        match *self {
            Self::Data { stream_id } => (stream_id, 0),
            Self::Finished { stream_id } => (stream_id, 1),
            Self::Reset { stream_id, .. } => (stream_id, 2),
            Self::Stopped { stream_id, .. } => (stream_id, 3),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DatagramCongestionControl {
    #[default]
    Standard,
    Uncongested,
}

#[derive(Clone)]
pub struct ClientAuthentication {
    pub mode: ClientAuth,
    pub verifier: Rc<dyn ClientCertVerifier>,
}

#[derive(Clone)]
pub struct Config {
    pub transport_params: transport_params::Params,
    pub datagram_congestion_control: DatagramCongestionControl,
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
    pub accept_early_data: bool,
    pub resumption_peer_tp: Option<transport_params::Params>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub server_cert_chain: Option<Vec<Vec<u8>>>,
    pub early_data_replay_cache: Option<SharedEarlyDataReplayCache>,
    pub client_authentication: Option<ClientAuthentication>,
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
            .field("accept_early_data", &self.accept_early_data)
            .field("resumption_peer_tp", &self.resumption_peer_tp)
            .field("alpn_protocols", &self.alpn_protocols)
            .field("server_cert_chain", &self.server_cert_chain.is_some())
            .field(
                "client_authentication",
                &self.client_authentication.is_some(),
            )
            .field("client_cert", &self.client_cert.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            transport_params: Params::default(),
            datagram_congestion_control: DatagramCongestionControl::Standard,
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
            accept_early_data: false,
            resumption_peer_tp: None,
            alpn_protocols: Vec::new(),
            server_cert_chain: None,
            early_data_replay_cache: None,
            client_authentication: None,
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
}

impl From<transport_params::Params> for Config {
    fn from(params: transport_params::Params) -> Self {
        Self {
            transport_params: params,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketCargo {
    CryptoOrAck,
    DatagramOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CryptoPacketMode {
    Regular,
    PtoProbe,
}

#[derive(Debug, Clone)]
struct PendingClose {
    is_application: bool,
    error_code: u64,
    frame_type: u64,
    reason: Vec<u8>,
}

enum SideSetup {
    Client {
        server_pubkey: [u8; 32],
    },
    Server {
        peer_cid: Vec<u8>,
        signing_key: Box<SigningKey>,
    },
}

impl Conn {
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
    ) -> Result<Self, ConnectError> {
        config.validate()?;
        let tp_original_dcid = initial_dcid.clone();
        Self::new_with(
            initial_dcid,
            local_cid,
            tp_original_dcid,
            None,
            config,
            SideSetup::Server {
                peer_cid,
                signing_key: Box::new(signing_key),
            },
        )
    }

    pub fn new_server_retry(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        peer_cid: Vec<u8>,
        original_dcid: Vec<u8>,
        retry_scid: Vec<u8>,
        signing_key: SigningKey,
        config: Config,
    ) -> Result<Self, ConnectError> {
        config.validate()?;
        Self::new_with(
            initial_dcid,
            local_cid,
            original_dcid,
            Some(retry_scid),
            config,
            SideSetup::Server {
                peer_cid,
                signing_key: Box::new(signing_key),
            },
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
            ticket_secret,
            resumption,
            enable_early_data,
            accept_early_data,
            resumption_peer_tp,
            alpn_protocols,
            server_cert_chain,
            early_data_replay_cache,
            client_authentication,
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
                let cfg = client::Config {
                    verifier: Verifier::RawPublicKey {
                        expected_pubkey: server_pubkey,
                    },
                    transport_params: tp_bytes,
                    alpn_protocols,
                    resumption,
                    enable_early_data,
                };
                let mut client = Client::new(cfg, WallClock::now_millis as TlsClock);
                if let Some(source) = client_cert {
                    client.set_client_cert(source);
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
            SideSetup::Server {
                peer_cid,
                signing_key,
            } => {
                user_tp.stateless_reset_token =
                    stateless_reset_secret.map(|s| StatelessResetSecret(s).token_for(&local_cid));
                let tp_bytes = Self::local_tp_bytes(
                    false,
                    &local_cid,
                    &tp_original_dcid,
                    retry_scid.as_deref(),
                    user_tp,
                )?;
                let cfg = server::Config {
                    source: match server_cert_chain {
                        Some(chain_der) => CertSource::X509 {
                            chain_der,
                            signing_key: *signing_key,
                        },
                        None => CertSource::RawPublicKey {
                            signing_key: *signing_key,
                        },
                    },
                    transport_params: tp_bytes,
                    alpn_protocols,
                    ticket_keys: ticket_secret.map(TicketKeys::single),
                    accept_early_data,
                };
                let store = early_data_replay_cache.unwrap_or_default();
                let guard = EarlyDataReplayGuard::new(store);
                let clock = WallClock::now_millis as TlsClock;
                let server = match client_authentication {
                    Some(ca) => ServerSide::Mtls(Server::with_early_data_guard_and_client_auth(
                        cfg,
                        clock,
                        guard,
                        ca.mode,
                        DynVerifier(ca.verifier),
                    )),
                    None => ServerSide::Plain(Server::with_early_data_guard(cfg, clock, guard)),
                };
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

        let mut conn = Self {
            side,
            is_client,
            scratch_frames: Vec::with_capacity(MAX_DATAGRAM_SIZE as usize),
            scratch_pending: Vec::with_capacity(STREAM_SCHEDULE_CAPACITY),
            scratch_header: Vec::with_capacity(128),
            scratch_parsed_frames: Vec::with_capacity(32),
            decrypt_wire: Vec::with_capacity(max_pmtu as usize),
            packet_journals: PacketJournalTable::new(packet_journal_capacity),
            crypto_deliveries: DeliveryTable::new(crypto_journal_capacity),
            control_deliveries: DeliveryTable::new(control_journal_capacity),
            stream_deliveries: DeliveryTable::new(stream_journal_capacity),
            scratch_stream_cleanup: Vec::new(),
            stream_schedule_cursor: None,
            peer_cid,
            local_cid,
            original_dcid: initial_dcid,
            peer_first_scid,
            initial_w: Some(initial_w),
            initial_r: Some(initial_r),
            handshake_w: None,
            handshake_r: None,
            app_w: None,
            app_r: None,
            zero_rtt_w: None,
            zero_rtt_r: None,
            pending_synth_eod: false,
            spaces,
            rtt: RttTracker::default(),
            pto_count: 0,
            loss_timer: None,
            pto_probe_allowance: 0,
            pto_probe_epoch: None,
            pending_crypto_initial: Vec::new(),
            pending_crypto_handshake: Vec::new(),
            pending_datagrams: VecDeque::new(),
            incoming_datagrams: VecDeque::new(),
            incoming_datagrams_capacity,
            peer_transport_params_raw: None,
            peer_transport_params: None,
            state: State::Handshaking,
            sent_initial: false,
            handshake_done_pending: false,
            handshake_confirmed: false,
            pending_close: None,
            last_activity: Instant::now(),
            local_max_idle_timeout: local_idle,
            peer_address_validated,
            amplification_received: 0,
            amplification_sent: 0,
            cc: NewReno::default(),
            pacer: Pacer::new(Instant::now()),
            pmtud: Pmtud::new(max_pmtu),
            packet_ceiling: usize::try_from(max_pmtu).unwrap_or(usize::MAX),
            pmtud_probe_pn: None,
            datagram_congestion_control,
            pending_datagrams_capacity,
            cid_prefix,
            stateless_reset_secret,
            stateless_reset_received: false,
            pending_path_responses: Vec::new(),
            pending_path_challenges: Vec::new(),
            outstanding_path_challenges: Vec::new(),
            validated_path_tokens: Vec::new(),
            local_cids,
            peer_cids,
            local_active_connection_id_limit,
            next_local_cid_seq: 1,
            new_cid_pending: Vec::new(),
            retire_pending: BTreeSet::new(),
            cids_to_register: Vec::new(),
            auto_issued: false,
            retry_token: Vec::new(),
            retry_processed: false,
            streams_recv: BTreeMap::new(),
            streams_send: BTreeMap::new(),
            stream_events: VecDeque::new(),
            pending_stream_events: BTreeMap::new(),
            stream_events_capacity,
            next_local_bidi_stream: if is_client { 0 } else { 1 },
            local_max_streams_bidi: local_initial_max_streams_bidi,
            initial_max_streams_bidi: local_initial_max_streams_bidi,
            peer_bidi_closed: 0,
            max_streams_bidi_pending: false,
            next_local_uni_stream: if is_client { 2 } else { 3 },
            local_max_streams_uni: local_initial_max_streams_uni,
            opened_local_bidi_streams: 0,
            opened_local_uni_streams: 0,
            peer_max_data: 0,
            peer_total_sent: 0,
            peer_max_stream_data: BTreeMap::new(),
            blocked_data_emitted: false,
            blocked_stream_emitted: BTreeMap::new(),
            local_max_data,
            conn_recv_total: 0,
            local_max_stream_data: BTreeMap::new(),
            local_max_data_pending: false,
            local_max_stream_data_pending: BTreeMap::new(),
            local_initial_max_stream_data_bidi_local,
            local_initial_max_stream_data_bidi_remote,
            local_initial_max_stream_data_uni,
            pending_resets: BTreeMap::new(),
            pending_stop_sending: BTreeMap::new(),
            pending_crypto_app: Vec::new(),
            received_tickets: VecDeque::new(),
            received_ticket_bytes: 0,
            pending_resumption_psk: None,
            recv_crypto: from_fn(|_| CryptoReassembly::default()),
        };
        if let Some(tp) = resumption_peer_tp {
            conn.peer_max_data = tp.initial_max_data;
            conn.peer_transport_params = Some(tp);
        }
        Ok(conn)
    }

    fn start_client_handshake(&mut self) -> Result<(), ConnectError> {
        if let SideKind::Client(c) = &mut self.side {
            let evs = c.start().map_err(|_| ConnectError::Tls)?;
            self.absorb_shin_events(evs)
                .map_err(|_| ConnectError::Tls)?;
        }
        Ok(())
    }

    pub fn recv_packet(&mut self, wire: &[u8], now: Instant) -> Result<(), ConnError> {
        if !self.peer_address_validated {
            self.amplification_received = self
                .amplification_received
                .saturating_add(wire.len() as u64);
        }
        if self.state == State::Established
            && wire.first().copied().unwrap_or(0) & 0x80 == 0
            && self.is_stateless_reset(wire)
        {
            self.state = State::Closed;
            self.stateless_reset_received = true;
            return Ok(());
        }
        let mut rest = wire;
        while !rest.is_empty() {
            let first = *rest.first().ok_or(ConnError::HeaderDecode)?;
            if first & 0x80 == 0 {
                if first & 0x40 == 0 {
                    break;
                }
                self.recv_one_rtt(rest, now)?;
                break;
            }
            if first & 0x30 == 0x30 {
                self.recv_retry(rest)?;
                break;
            }
            let plen = match first & 0x30 {
                0x00 => {
                    let p =
                        InitialHeader::decode_pre_hp(rest).map_err(|_| ConnError::HeaderDecode)?;
                    p.pn_offset + p.length
                }
                0x10 => {
                    let p =
                        ZeroRttHeader::decode_pre_hp(rest).map_err(|_| ConnError::HeaderDecode)?;
                    p.pn_offset + p.length
                }
                _ => {
                    let p = HandshakeHeader::decode_pre_hp(rest)
                        .map_err(|_| ConnError::HeaderDecode)?;
                    p.pn_offset + p.length
                }
            };
            if plen == 0 || plen > rest.len() {
                return Err(ConnError::HeaderDecode);
            }
            let pkt = &rest[..plen];
            match first & 0x30 {
                0x00 => self.recv_initial(pkt, now)?,
                0x10 => self.recv_zero_rtt(pkt, now)?,
                _ => self.recv_handshake(pkt, now)?,
            }
            rest = &rest[plen..];
        }
        Ok(())
    }

    fn recv_zero_rtt(&mut self, wire: &[u8], now: Instant) -> Result<(), ConnError> {
        let Some(zr) = self.zero_rtt_r.as_ref() else {
            return Ok(());
        };
        let prefix = ZeroRttHeader::decode_pre_hp(wire).map_err(|_| ConnError::HeaderDecode)?;
        let mut buf = take(&mut self.decrypt_wire);
        buf.clear();
        buf.extend_from_slice(wire);
        let expected = self.spaces[Epoch::Application as usize].expected_pn();
        let decrypted = zr
            .decrypt_long_in_place(&mut buf, prefix.pn_offset, expected)
            .map_err(|_| ConnError::PacketDecrypt);
        let result = match decrypted {
            Ok((pn, body)) => self.process_packet_body(Epoch::Application, pn, &buf[body], now),
            Err(error) => Err(error),
        };
        buf.clear();
        self.decrypt_wire = buf;
        result
    }

    fn recv_retry(&mut self, wire: &[u8]) -> Result<(), ConnError> {
        if !self.is_client || self.retry_processed {
            return Ok(());
        }
        if self.handshake_r.is_some() || self.peer_first_scid.is_some() {
            return Ok(());
        }
        let pkt = RetryPacket::decode(wire).map_err(|_| ConnError::HeaderDecode)?;
        if !pkt.verify_integrity(&self.original_dcid) {
            return Ok(());
        }
        let active_ceiling = self
            .packet_ceiling
            .min(usize::try_from(self.path_mtu()).unwrap_or(usize::MAX));
        let payload_limit = Self::initial_payload_limit_for(
            pkt.scid.len(),
            self.local_cid.len(),
            pkt.token.len(),
            active_ceiling,
        );
        let ch_bytes: Vec<u8> = {
            let space = &self.spaces[Epoch::Initial as usize];
            let mut ranges =
                Vec::with_capacity(space.crypto_inflight.len() + space.crypto_retransmit.len() + 1);
            for (&offset, (data, _pn)) in &space.crypto_inflight {
                ranges.push((offset, data.as_slice()));
            }
            for (offset, data) in &space.crypto_retransmit {
                ranges.push((*offset, data.as_slice()));
            }
            if !self.pending_crypto_initial.is_empty() {
                ranges.push((
                    space.crypto_next_offset,
                    self.pending_crypto_initial.as_slice(),
                ));
            }
            ranges.sort_unstable_by_key(|range| range.0);
            let total = ranges.iter().fold(0u64, |end, (offset, data)| {
                end.max(offset.saturating_add(data.len() as u64))
            });
            let Ok(total) = usize::try_from(total) else {
                self.state = State::Closed;
                return Err(ConnError::PacketCeiling);
            };
            let mut acc = Vec::with_capacity(total);
            for (offset, data) in ranges {
                let Ok(offset) = usize::try_from(offset) else {
                    self.state = State::Closed;
                    return Err(ConnError::PacketCeiling);
                };
                if offset > acc.len() {
                    self.state = State::Closed;
                    return Err(ConnError::Tls);
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
            self.state = State::Closed;
            return Err(ConnError::PacketCeiling);
        }
        let new_secrets = InitialSecrets::from_dcid(&pkt.scid).map_err(|_| ConnError::Tls)?;
        self.discard_initial_keys();
        self.initial_w = Some(
            PacketProtection::aes_128(
                &PacketKeys::aes_128(&new_secrets.client).map_err(|_| ConnError::Tls)?,
            )
            .map_err(|_| ConnError::Tls)?,
        );
        self.initial_r = Some(
            PacketProtection::aes_128(
                &PacketKeys::aes_128(&new_secrets.server).map_err(|_| ConnError::Tls)?,
            )
            .map_err(|_| ConnError::Tls)?,
        );
        self.peer_cid = pkt.scid.clone();
        if let Some(entry) = self.peer_cids.get_mut(&0) {
            entry.0 = pkt.scid;
        }
        self.pending_crypto_initial = ch_bytes;
        self.retry_token = pkt.token;
        self.retry_processed = true;
        self.sent_initial = false;
        Ok(())
    }

    fn is_stateless_reset(&self, wire: &[u8]) -> bool {
        if wire.len() < 22 {
            return false;
        }
        let tail = &wire[wire.len() - 16..];
        let mut buf = [0u8; 16];
        buf.copy_from_slice(tail);
        for (_cid, token) in self.peer_cids.values() {
            if *token == [0u8; 16] {
                continue;
            }
            if bool::from(buf[..].ct_eq(&token[..])) {
                return true;
            }
        }
        false
    }

    pub fn was_stateless_reset(&self) -> bool {
        self.stateless_reset_received
    }

    pub fn send_path_challenge(&mut self, data: [u8; 8]) {
        if self.state == State::Established
            && self.pending_path_challenges.len() < MAX_PATH_TOKENS
            && !self.pending_path_challenges.contains(&data)
            && !self.outstanding_path_challenges.contains(&data)
        {
            self.pending_path_challenges.push(data);
        }
    }

    pub fn path_validated(&self, token: &[u8; 8]) -> bool {
        self.validated_path_tokens.contains(token)
    }

    pub fn stream_recv(&mut self, stream_id: u64, dst: &mut Vec<u8>) -> usize {
        let n = match self.streams_recv.get_mut(&stream_id) {
            Some(rs) => rs.read(dst),
            None => 0,
        };
        if n > 0 {
            let bump = n as u64;
            self.local_max_data = self.local_max_data.saturating_add(bump);
            let initial = self.local_initial_stream_credit(stream_id);
            let entry = self
                .local_max_stream_data
                .entry(stream_id)
                .or_insert(initial);
            *entry = entry.saturating_add(bump);
            self.local_max_data_pending = true;
            self.local_max_stream_data_pending.insert(stream_id, ());
        }
        n
    }

    fn local_stream_recv_limit(&self, id: u64) -> u64 {
        match self.local_max_stream_data.get(&id) {
            Some(limit) => *limit,
            None => self.local_initial_stream_credit(id),
        }
    }

    fn validate_stream_access(&self, id: u64, access: StreamAccess) -> Result<(), ConnError> {
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
                return Err(ConnError::ProtocolViolation);
            }
        } else {
            let opened = id / 4
                < if is_uni {
                    self.local_max_streams_uni
                } else {
                    self.local_max_streams_bidi
                };
            if !opened || is_uni && matches!(access, StreamAccess::Send) {
                return Err(ConnError::ProtocolViolation);
            }
        }
        Ok(())
    }

    fn validate_stream_operation(&self, id: u64, access: StreamAccess) -> Result<(), StreamError> {
        if id > VarInt::MAX {
            return Err(StreamError::IdOverflow);
        }
        let early_data = self.is_client
            && self.state == State::Handshaking
            && self.zero_rtt_w.is_some()
            && self.peer_transport_params.is_some();
        if self.state != State::Established && !early_data {
            return Err(StreamError::NotEstablished);
        }
        self.validate_stream_access(id, access)
            .map_err(|_| StreamError::InvalidStream)?;
        let initiated_by_client = id & 0x1 == 0;
        if initiated_by_client != self.is_client && !self.streams_recv.contains_key(&id) {
            return Err(StreamError::InvalidStream);
        }
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
            .map(|rs| rs.is_eof())
            .unwrap_or(false)
    }

    pub fn stream_recv_fin_received(&self, stream_id: u64) -> bool {
        self.streams_recv
            .get(&stream_id)
            .and_then(|rs| rs.final_size())
            .is_some()
    }

    pub fn stream_send(&mut self, stream_id: u64, data: &[u8]) -> Result<(), StreamError> {
        self.validate_stream_operation(stream_id, StreamAccess::Send)?;
        if self
            .peer_max_stream_data
            .get(&stream_id)
            .is_some_and(|state| state.final_offset.is_some())
            || self
                .streams_send
                .get(&stream_id)
                .is_some_and(|stream| stream.blocked())
        {
            return Ok(());
        }
        self.streams_send.entry(stream_id).or_default().write(data);
        Ok(())
    }

    pub fn stream_send_fin(&mut self, stream_id: u64) -> Result<(), StreamError> {
        self.validate_stream_operation(stream_id, StreamAccess::Send)?;
        if self
            .peer_max_stream_data
            .get(&stream_id)
            .is_some_and(|state| state.final_offset.is_some())
            || self
                .streams_send
                .get(&stream_id)
                .is_some_and(|stream| stream.blocked())
        {
            return Ok(());
        }
        self.streams_send.entry(stream_id).or_default().mark_fin();
        if stream_id & 0x3 == 0
            && self
                .streams_recv
                .get(&stream_id)
                .is_some_and(|rs| rs.is_eof())
        {
            self.peer_bidi_closed = self.peer_bidi_closed.saturating_add(1);
            let threshold = (self.initial_max_streams_bidi / 2).max(1);
            if self.peer_bidi_closed >= threshold {
                self.local_max_streams_bidi = self
                    .local_max_streams_bidi
                    .saturating_add(self.peer_bidi_closed);
                self.peer_bidi_closed = 0;
                self.max_streams_bidi_pending = true;
            }
        }
        Ok(())
    }

    pub fn stream_reset(&mut self, stream_id: u64, error_code: u64) -> Result<(), StreamError> {
        self.validate_stream_operation(stream_id, StreamAccess::Send)?;
        if error_code > VarInt::MAX {
            return Err(StreamError::ValueOutOfRange);
        }
        let final_size = self
            .streams_send
            .get(&stream_id)
            .map(|stream| stream.next_offset())
            .or_else(|| {
                self.peer_max_stream_data
                    .get(&stream_id)
                    .and_then(|state| state.final_offset)
            })
            .unwrap_or(0);
        self.cancel_stream_deliveries(stream_id);
        self.streams_send
            .entry(stream_id)
            .or_default()
            .mark_reset_sent();
        self.pending_resets
            .insert(stream_id, (error_code, final_size));
        Ok(())
    }

    pub fn stream_stop_sending(
        &mut self,
        stream_id: u64,
        error_code: u64,
    ) -> Result<(), StreamError> {
        self.validate_stream_operation(stream_id, StreamAccess::Receive)?;
        if error_code > VarInt::MAX {
            return Err(StreamError::ValueOutOfRange);
        }
        self.pending_stop_sending.insert(stream_id, error_code);
        Ok(())
    }

    pub fn stream_recv_reset(&self, stream_id: u64) -> Option<u64> {
        self.streams_recv
            .get(&stream_id)
            .and_then(|rs| rs.reset_error())
    }

    pub fn stream_send_stopped(&self, stream_id: u64) -> Option<u64> {
        self.streams_send
            .get(&stream_id)
            .and_then(|s| s.stop_sending_error())
    }

    pub fn open_bidi_stream(&mut self) -> Result<u64, StreamError> {
        self.open_local_stream(false)
    }

    pub fn open_uni_stream(&mut self) -> Result<u64, StreamError> {
        self.open_local_stream(true)
    }

    pub fn poll_stream_event(&mut self) -> Option<StreamEvent> {
        let event = self.stream_events.pop_front()?;
        self.pending_stream_events.remove(&event.key());
        Some(event)
    }

    pub fn has_stream_events(&self) -> bool {
        !self.stream_events.is_empty()
    }

    fn push_stream_event(&mut self, event: StreamEvent) -> Result<(), ConnError> {
        let key = event.key();
        if self.pending_stream_events.contains_key(&key) {
            return Ok(());
        }
        if self.stream_events.len() == self.stream_events_capacity {
            return Err(ConnError::EventCapacity);
        }
        self.pending_stream_events.insert(key, ());
        self.stream_events.push_back(event);
        Ok(())
    }

    fn open_local_stream(&mut self, uni: bool) -> Result<u64, StreamError> {
        let early_data = self.is_client
            && self.state == State::Handshaking
            && self.zero_rtt_w.is_some()
            && self.peer_transport_params.is_some();
        if self.state != State::Established && !early_data {
            return Err(StreamError::NotEstablished);
        }
        let Some(tp) = &self.peer_transport_params else {
            return Err(StreamError::NotEstablished);
        };
        let (next, opened, limit) = if uni {
            (
                &mut self.next_local_uni_stream,
                &mut self.opened_local_uni_streams,
                tp.initial_max_streams_uni,
            )
        } else {
            (
                &mut self.next_local_bidi_stream,
                &mut self.opened_local_bidi_streams,
                tp.initial_max_streams_bidi,
            )
        };
        if *opened >= limit {
            return Err(StreamError::PeerLimit);
        }
        let id = *next;
        *next = next.checked_add(4).ok_or(StreamError::IdOverflow)?;
        *opened = opened.saturating_add(1);
        self.streams_send.entry(id).or_default();
        self.ensure_peer_stream_credit(id);
        Ok(id)
    }

    fn recv_initial(&mut self, wire: &[u8], now: Instant) -> Result<(), ConnError> {
        let Some(initial_r) = self.initial_r.as_ref() else {
            return Ok(());
        };
        let prefix = InitialHeader::decode_pre_hp(wire).map_err(|_| ConnError::HeaderDecode)?;
        if self.is_client && self.peer_first_scid.is_none() {
            self.peer_first_scid = Some(prefix.scid.clone());
            self.peer_cid = prefix.scid;
        }
        let mut buf = take(&mut self.decrypt_wire);
        buf.clear();
        buf.extend_from_slice(wire);
        let expected = self.spaces[Epoch::Initial as usize].expected_pn();
        let decrypted = initial_r
            .decrypt_long_in_place(&mut buf, prefix.pn_offset, expected)
            .map_err(|_| ConnError::PacketDecrypt);
        let result = match decrypted {
            Ok((pn, body)) => self.process_packet_body(Epoch::Initial, pn, &buf[body], now),
            Err(error) => Err(error),
        };
        buf.clear();
        self.decrypt_wire = buf;
        result
    }

    fn recv_handshake(&mut self, wire: &[u8], now: Instant) -> Result<(), ConnError> {
        let Some(hr) = self.handshake_r.as_ref() else {
            return Ok(());
        };
        let prefix = HandshakeHeader::decode_pre_hp(wire).map_err(|_| ConnError::HeaderDecode)?;
        let mut buf = take(&mut self.decrypt_wire);
        buf.clear();
        buf.extend_from_slice(wire);
        let expected = self.spaces[Epoch::Handshake as usize].expected_pn();
        let decrypted = hr
            .decrypt_long_in_place(&mut buf, prefix.pn_offset, expected)
            .map_err(|_| ConnError::PacketDecrypt);
        let result = match decrypted {
            Ok((pn, body)) => {
                self.peer_address_validated = true;
                self.process_packet_body(Epoch::Handshake, pn, &buf[body], now)
            }
            Err(error) => Err(error),
        };
        buf.clear();
        self.decrypt_wire = buf;
        result
    }

    fn recv_one_rtt(&mut self, wire: &[u8], now: Instant) -> Result<(), ConnError> {
        let Some(ar) = self.app_r.as_ref() else {
            return Ok(());
        };
        let pn_offset = ShortHeader::pn_offset_for(self.local_cid.len());
        let mut buf = take(&mut self.decrypt_wire);
        buf.clear();
        buf.extend_from_slice(wire);
        let expected = self.spaces[Epoch::Application as usize].expected_pn();
        let decrypted = ar
            .decrypt_short_in_place(&mut buf, pn_offset, expected)
            .map_err(|_| ConnError::PacketDecrypt);
        let result = match decrypted {
            Ok((pn, body)) => self.process_packet_body(Epoch::Application, pn, &buf[body], now),
            Err(error) => Err(error),
        };
        buf.clear();
        self.decrypt_wire = buf;
        result
    }

    fn process_packet_body(
        &mut self,
        epoch: Epoch,
        pn: u64,
        body: &[u8],
        now: Instant,
    ) -> Result<(), ConnError> {
        if self.spaces[epoch as usize].has_received(pn) {
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
                parse_error = Some(ConnError::FrameDecode);
                break;
            }
            let decoded = Frame::decode_mapped(
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
            );
            let (frame, consumed) = match decoded {
                Ok(decoded) => decoded,
                Err(_) => {
                    parse_error = Some(ConnError::FrameDecode);
                    break;
                }
            };
            if consumed == 0 {
                parse_error = Some(ConnError::FrameDecode);
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
        self.spaces[epoch as usize].record_received(pn, ack_eliciting, now);
        self.last_activity = now;

        let shin_epoch = match epoch {
            Epoch::Initial => shin::Epoch::Plaintext,
            Epoch::Handshake => shin::Epoch::Handshake,
            Epoch::Application => shin::Epoch::Application,
        };
        let result = (|| {
            for parsed in parsed_frames.drain(..) {
                let f = parsed.map(
                    |range| &body[range],
                    |ranges| AckRanges::new(&body[ranges.bytes], ranges.count),
                );
                match f {
                    Frame::Crypto { offset, data } => {
                        let msgs = self.recv_crypto[epoch as usize].accept(offset, data)?;
                        for msg in msgs {
                            if self.pending_synth_eod && epoch == Epoch::Handshake {
                                self.pending_synth_eod = false;
                                let evs = self
                                    .feed_shin(shin::Epoch::EarlyData, &[0x05, 0x00, 0x00, 0x00])?;
                                self.absorb_shin_events(evs)?;
                            }
                            let evs = self.feed_shin(shin_epoch, &msg)?;
                            self.absorb_shin_events(evs)?;
                        }
                    }
                    Frame::Ack {
                        largest,
                        delay,
                        first_range,
                        additional_ranges,
                    } => {
                        if largest >= self.spaces[epoch as usize].next_pn {
                            return Err(ConnError::ProtocolViolation);
                        }
                        let acked = if epoch == Epoch::Application {
                            let space = &mut self.spaces[Epoch::Application as usize];
                            space.largest_acked =
                                Some(space.largest_acked.unwrap_or(0).max(largest));
                            Vec::new()
                        } else {
                            self.spaces[epoch as usize].process_ack(
                                largest,
                                first_range,
                                additional_ranges.clone(),
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
                        self.handshake_confirmed = true;
                        self.discard_initial_keys();
                        self.discard_handshake_keys();
                    }
                    Frame::ConnectionClose { .. } => {
                        self.state = State::Closed;
                    }
                    Frame::NewConnectionId {
                        sequence_number,
                        retire_prior_to,
                        connection_id,
                        stateless_reset_token,
                    } if epoch == Epoch::Application => {
                        if connection_id.is_empty()
                            || connection_id.len() > 20
                            || retire_prior_to > sequence_number
                        {
                            return Err(ConnError::ProtocolViolation);
                        }
                        if let Some(existing) = self.peer_cids.get(&sequence_number)
                            && existing != &(connection_id.to_vec(), stateless_reset_token)
                        {
                            return Err(ConnError::ProtocolViolation);
                        }
                        let to_retire: Vec<u64> = self
                            .peer_cids
                            .keys()
                            .copied()
                            .filter(|&s| s < retire_prior_to)
                            .collect();
                        let additional_retirements = to_retire
                            .iter()
                            .filter(|sequence| !self.retire_pending.contains(sequence))
                            .count();
                        if self
                            .retire_pending
                            .len()
                            .saturating_add(additional_retirements)
                            > MAX_PENDING_RETIRE_CONNECTION_IDS
                        {
                            return Err(ConnError::ConnectionIdLimit);
                        }
                        for s in to_retire {
                            self.peer_cids.remove(&s);
                            self.retire_pending.insert(s);
                        }
                        if !self.peer_cids.contains_key(&sequence_number) {
                            if self.peer_cids.len() as u64 >= self.local_active_connection_id_limit
                            {
                                return Err(ConnError::ConnectionIdLimit);
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
                        self.local_cids.remove(&sequence_number);
                    }
                    Frame::PathChallenge { data } if epoch == Epoch::Application => {
                        if self.pending_path_responses.len() < MAX_PATH_TOKENS
                            && !self.pending_path_responses.contains(&data)
                        {
                            self.pending_path_responses.push(data);
                        }
                    }
                    Frame::Stream {
                        stream_id,
                        offset,
                        fin,
                        data,
                        ..
                    } if epoch == Epoch::Application => {
                        self.validate_stream_access(stream_id, StreamAccess::Receive)?;
                        let new_end = offset.saturating_add(data.len() as u64);
                        let stream_limit = self.local_stream_recv_limit(stream_id);
                        if new_end > stream_limit {
                            return Err(ConnError::FlowControl);
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
                            return Err(ConnError::FinalSize);
                        }
                        if new_end > prev_high {
                            let delta = new_end - prev_high;
                            let projected = self.conn_recv_total.saturating_add(delta);
                            if projected > self.local_max_data {
                                return Err(ConnError::FlowControl);
                            }
                            self.conn_recv_total = projected;
                        }
                        let rs = self.streams_recv.entry(stream_id).or_default();
                        rs.insert(offset, data, fin)
                            .map_err(|_| ConnError::StreamBufferExceeded)?;
                        if !data.is_empty() {
                            self.push_stream_event(StreamEvent::Data { stream_id })?;
                        }
                        if fin {
                            self.push_stream_event(StreamEvent::Finished { stream_id })?;
                        }
                    }
                    Frame::MaxData { maximum_data }
                        if epoch == Epoch::Application && maximum_data > self.peer_max_data =>
                    {
                        self.peer_max_data = maximum_data;
                        self.blocked_data_emitted = false;
                    }
                    Frame::MaxStreamData {
                        stream_id,
                        maximum_stream_data,
                    } if epoch == Epoch::Application => {
                        self.validate_stream_access(stream_id, StreamAccess::Send)?;
                        let entry = self.peer_max_stream_data.entry(stream_id).or_insert(
                            PeerStreamSendState {
                                limit: 0,
                                final_offset: None,
                                deliveries: 0,
                                retransmits: 0,
                            },
                        );
                        if maximum_stream_data > entry.limit {
                            entry.limit = maximum_stream_data;
                            self.blocked_stream_emitted.remove(&stream_id);
                        }
                    }
                    Frame::DataBlocked { .. } if epoch == Epoch::Application => {}
                    Frame::StreamDataBlocked { stream_id, .. } if epoch == Epoch::Application => {
                        self.validate_stream_access(stream_id, StreamAccess::Receive)?;
                    }
                    Frame::ResetStream {
                        stream_id,
                        error_code,
                        final_size,
                    } if epoch == Epoch::Application => {
                        self.validate_stream_access(stream_id, StreamAccess::Receive)?;
                        if final_size > self.local_stream_recv_limit(stream_id) {
                            return Err(ConnError::FlowControl);
                        }
                        let (prev_high, known_final) = self
                            .streams_recv
                            .get(&stream_id)
                            .map(|stream| (stream.highest_offset(), stream.final_size()))
                            .unwrap_or((0, None));
                        if final_size < prev_high
                            || known_final.is_some_and(|known| known != final_size)
                        {
                            return Err(ConnError::FinalSize);
                        }
                        if final_size > prev_high {
                            let delta = final_size - prev_high;
                            let projected = self.conn_recv_total.saturating_add(delta);
                            if projected > self.local_max_data {
                                return Err(ConnError::FlowControl);
                            }
                            self.conn_recv_total = projected;
                        }
                        let rs = self.streams_recv.entry(stream_id).or_default();
                        rs.reset(error_code, final_size);
                        self.push_stream_event(StreamEvent::Reset {
                            stream_id,
                            error_code,
                        })?;
                    }
                    Frame::StopSending {
                        stream_id,
                        error_code,
                    } if epoch == Epoch::Application => {
                        self.validate_stream_access(stream_id, StreamAccess::Send)?;
                        let final_size = self
                            .streams_send
                            .get(&stream_id)
                            .map(|stream| stream.next_offset())
                            .or_else(|| {
                                self.peer_max_stream_data
                                    .get(&stream_id)
                                    .and_then(|state| state.final_offset)
                            })
                            .unwrap_or(0);
                        self.cancel_stream_deliveries(stream_id);
                        let reset_sent = {
                            let stream = self.streams_send.entry(stream_id).or_default();
                            stream.stop(error_code);
                            let reset_sent = stream.reset_sent();
                            if !reset_sent {
                                stream.mark_reset_sent();
                            }
                            reset_sent
                        };
                        self.push_stream_event(StreamEvent::Stopped {
                            stream_id,
                            error_code,
                        })?;
                        if !reset_sent {
                            self.pending_resets
                                .insert(stream_id, (error_code, final_size));
                        }
                    }
                    Frame::MaxStreams { .. } | Frame::StreamsBlocked { .. }
                        if epoch == Epoch::Application => {}
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
        result
    }

    fn discard_initial_keys(&mut self) {
        let leaked = self.spaces[Epoch::Initial as usize].in_flight_bytes();
        self.cc.discard(leaked);
        self.discard_epoch_journals(Epoch::Initial);
        self.initial_w = None;
        self.initial_r = None;
        self.spaces[Epoch::Initial as usize] = PnSpace::default();
        self.pending_crypto_initial.clear();
    }

    fn discard_handshake_keys(&mut self) {
        let leaked = self.spaces[Epoch::Handshake as usize].in_flight_bytes();
        self.cc.discard(leaked);
        self.discard_epoch_journals(Epoch::Handshake);
        self.handshake_w = None;
        self.handshake_r = None;
        self.spaces[Epoch::Handshake as usize] = PnSpace::default();
        self.pending_crypto_handshake.clear();
    }

    fn discard_epoch_journals(&mut self, epoch: Epoch) {
        self.packet_journals
            .drain_where(|journal| journal.epoch == epoch, |_| {});
        self.crypto_deliveries
            .remove_where(|delivery| delivery.epoch == epoch);
        self.control_deliveries
            .remove_where(|delivery| delivery.epoch == epoch);
        self.stream_deliveries
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
            self.rtt.update(sample, ack_delay);
            self.pto_count = 0;
        }
        for p in &packets {
            self.cc.packet_acked(p.bytes_sent as u64, p.in_flight);
            if matches!(epoch, Epoch::Application) && Some(p.pn) == self.pmtud_probe_pn {
                self.pmtud.probe_acked();
                self.pmtud_probe_pn = None;
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
        self.cleanup_acked_streams();
        self.run_rack(now);
        self.update_loss_timer();
    }

    fn cleanup_acked_streams(&mut self) {
        let mut stream_ids = take(&mut self.scratch_stream_cleanup);
        for stream_id in stream_ids.drain(..) {
            let tracked = self
                .peer_max_stream_data
                .get(&stream_id)
                .is_some_and(|state| state.deliveries == 0 && state.retransmits == 0);
            let fully_acked = self
                .streams_send
                .get(&stream_id)
                .is_some_and(SendStream::is_fully_acked);
            if !tracked || !fully_acked {
                continue;
            }
            if let Some(final_offset) = self
                .streams_send
                .get(&stream_id)
                .map(|stream| stream.next_offset())
                && let Some(state) = self.peer_max_stream_data.get_mut(&stream_id)
            {
                state.final_offset = Some(final_offset);
            }
            self.streams_send.remove(&stream_id);
            if self
                .streams_recv
                .get(&stream_id)
                .is_none_or(|stream| stream.is_eof())
            {
                self.streams_recv.remove(&stream_id);
            }
        }
        self.scratch_stream_cleanup = stream_ids;
    }

    fn run_rack(&mut self, now: Instant) {
        let loss_delay = self.rtt.loss_delay();
        for idx in 0..Epoch::Application as usize {
            let (lost, _) = self.spaces[idx].detect_lost(loss_delay, now);
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
            self.cc.packets_lost(lost_bytes, latest);
            if idx == Epoch::Application as usize
                && let Some(probe_pn) = self.pmtud_probe_pn
                && lost.iter().any(|p| p.pn == probe_pn)
            {
                self.pmtud.probe_lost();
                self.pmtud_probe_pn = None;
            }
        }
        self.detect_lost_application(now);
    }

    fn detect_lost_application(&mut self, now: Instant) -> usize {
        let Some(largest_acked) = self.spaces[Epoch::Application as usize].largest_acked else {
            return 0;
        };
        let loss_delay = self.rtt.loss_delay();
        let lost_send_time = now.checked_sub(loss_delay).unwrap_or(now);
        let mut journals = take(&mut self.packet_journals);
        let mut total = 0;
        journals.drain_application_lost(largest_acked, lost_send_time, |journal| {
            total += 1;
            if journal.ack_eliciting && journal.in_flight {
                self.spaces[Epoch::Application as usize].ack_eliciting_in_flight = self.spaces
                    [Epoch::Application as usize]
                    .ack_eliciting_in_flight
                    .saturating_sub(1);
            }
            self.lose_packet_deliveries(journal);
            self.cc
                .packets_lost(journal.bytes_sent as u64, journal.sent_time);
            if Some(journal.pn) == self.pmtud_probe_pn {
                self.pmtud.probe_lost();
                self.pmtud_probe_pn = None;
            }
        });
        self.packet_journals = journals;
        total
    }

    pub fn path_mtu(&self) -> u64 {
        self.pmtud.current()
    }

    fn update_loss_timer(&mut self) {
        let loss_delay = self.rtt.loss_delay();

        let mut rack_candidate: Option<Instant> = None;
        for space in &self.spaces {
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
        if let Some(largest_acked) = self.spaces[Epoch::Application as usize].largest_acked
            && let Some(when) = self
                .packet_journals
                .application_loss_candidate(largest_acked, loss_delay)
        {
            rack_candidate = Some(rack_candidate.map_or(when, |previous| previous.min(when)));
        }
        if let Some(t) = rack_candidate {
            self.loss_timer = Some(t);
            return;
        }

        let mut pto_base: Option<Instant> = None;
        for space in &self.spaces {
            if space.ack_eliciting_in_flight > 0
                && let Some(t) = space.time_of_last_ack_eliciting
            {
                pto_base = Some(match pto_base {
                    Some(prev) => prev.min(t),
                    None => t,
                });
            }
        }
        self.loss_timer = pto_base.map(|t| {
            let pto = self.rtt.pto_period(Duration::ZERO);
            t + pto * (1u32 << self.pto_count.min(16))
        });
    }

    pub fn next_timer(&self) -> Option<Instant> {
        match (self.loss_timer, self.idle_deadline()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    pub fn check_loss(&mut self, now: Instant) {
        if self.state != State::Closed
            && let Some(idle) = self.idle_deadline()
            && now >= idle
        {
            self.state = State::Closed;
            return;
        }
        let Some(deadline) = self.loss_timer else {
            return;
        };
        if now < deadline {
            return;
        }

        let loss_delay = self.rtt.loss_delay();
        let mut total_lost = 0usize;
        for index in 0..Epoch::Application as usize {
            let (lost, _) = self.spaces[index].detect_lost(loss_delay, now);
            if !lost.is_empty() {
                let lost_bytes: u64 = lost.iter().map(|p| p.bytes_sent as u64).sum();
                let Some(latest) = lost.iter().map(|p| p.sent_time).max() else {
                    continue;
                };
                for packet in &lost {
                    self.lose_journal(Epoch::from_index(index), packet.pn);
                }
                self.cc.packets_lost(lost_bytes, latest);
                total_lost += lost.len();
            }
        }
        total_lost += self.detect_lost_application(now);

        if total_lost == 0 && self.arm_pto_probes() {
            self.pto_count = self.pto_count.saturating_add(1);
        }
        self.update_loss_timer();
    }

    fn arm_pto_probes(&mut self) -> bool {
        let Some(epoch) = self
            .spaces
            .iter()
            .position(|space| space.ack_eliciting_in_flight != 0)
            .map(Epoch::from_index)
        else {
            return false;
        };
        self.pto_probe_epoch = Some(epoch);
        self.pto_probe_allowance = 2;
        if epoch == Epoch::Application {
            for journal in self.packet_journals.application_iter_mut() {
                if journal.in_flight {
                    journal.pto_protected = true;
                }
            }
        }
        self.crypto_deliveries.arm_probes(epoch);
        if epoch == Epoch::Application {
            self.control_deliveries.arm_probes(epoch);
            self.stream_deliveries.arm_probes(epoch);
        }
        true
    }

    fn feed_shin(&mut self, epoch: shin::Epoch, data: &[u8]) -> Result<Vec<Event>, ConnError> {
        let events = self.side.read(epoch, data).map_err(|_| ConnError::Tls)?;
        if self.state != State::Established
            && let Some(suite) = self.side.negotiated_cipher_suite()
            && suite != CipherSuite::Aes128GcmSha256
        {
            return Err(ConnError::Tls);
        }
        Ok(events)
    }

    fn reject_early_data(&mut self) {
        let mut journals = take(&mut self.packet_journals);
        journals.drain_where(
            |journal| journal.early_data,
            |journal| {
                if journal.ack_eliciting && journal.in_flight {
                    self.spaces[Epoch::Application as usize].ack_eliciting_in_flight = self.spaces
                        [Epoch::Application as usize]
                        .ack_eliciting_in_flight
                        .saturating_sub(1);
                    self.cc.discard(journal.bytes_sent as u64);
                }
                self.lose_packet_deliveries(journal);
            },
        );
        self.packet_journals = journals;
        self.update_loss_timer();
    }

    fn absorb_shin_events(&mut self, events: Vec<Event>) -> Result<(), ConnError> {
        for e in events {
            match e {
                Event::Send { epoch, data } => match epoch {
                    shin::Epoch::Plaintext => self.pending_crypto_initial.extend_from_slice(&data),
                    shin::Epoch::Handshake => {
                        self.pending_crypto_handshake.extend_from_slice(&data)
                    }
                    shin::Epoch::Application => self.pending_crypto_app.extend_from_slice(&data),
                    shin::Epoch::EarlyData => {}
                },
                Event::KeysReady {
                    epoch,
                    read_secret,
                    write_secret,
                } => {
                    let read_keys =
                        PacketKeys::aes_128(read_secret.as_slice()).map_err(|_| ConnError::Tls)?;
                    let write_keys =
                        PacketKeys::aes_128(write_secret.as_slice()).map_err(|_| ConnError::Tls)?;
                    let r = PacketProtection::aes_128(&read_keys).map_err(|_| ConnError::Tls)?;
                    let w = PacketProtection::aes_128(&write_keys).map_err(|_| ConnError::Tls)?;
                    match epoch {
                        shin::Epoch::Handshake => {
                            self.handshake_r = Some(r);
                            self.handshake_w = Some(w);
                        }
                        shin::Epoch::Application => {
                            self.app_r = Some(r);
                            self.app_w = Some(w);
                        }
                        shin::Epoch::Plaintext => {}
                        shin::Epoch::EarlyData => {}
                    }
                }
                Event::PeerExtension { ty: _, data } => {
                    self.peer_transport_params_raw = Some(data);
                }
                Event::Done => {
                    if let Err(_e) = self.finalize_peer_tp() {
                        self.state = State::Closed;
                        continue;
                    }
                    self.state = State::Established;
                    if !self.is_client {
                        self.handshake_done_pending = true;
                    }
                    self.auto_issue_local_cids();
                }
                Event::KeyUpdate { .. } => {}
                Event::ZeroRttKeysReady { secret } => {
                    let keys =
                        PacketKeys::aes_128(secret.as_slice()).map_err(|_| ConnError::Tls)?;
                    if self.is_client {
                        self.zero_rtt_w =
                            Some(PacketProtection::aes_128(&keys).map_err(|_| ConnError::Tls)?);
                    } else {
                        self.zero_rtt_r =
                            Some(PacketProtection::aes_128(&keys).map_err(|_| ConnError::Tls)?);
                        self.pending_synth_eod = true;
                    }
                }
                Event::EarlyDataAccepted => {}
                Event::EarlyDataRejected => {
                    self.zero_rtt_w = None;
                    self.reject_early_data();
                }
                Event::NewSessionTicket {
                    ticket_lifetime,
                    ticket_age_add,
                    ticket_nonce,
                    ticket,
                    max_early_data: _,
                } => {
                    let psk = self.pending_resumption_psk.take().unwrap_or([0u8; 32]);
                    let ticket_bytes = ticket_nonce.len().saturating_add(ticket.len());
                    if ticket_bytes > MAX_SESSION_TICKET_BYTES {
                        continue;
                    }
                    while self.received_tickets.len() >= MAX_SESSION_TICKETS
                        || self.received_ticket_bytes.saturating_add(ticket_bytes)
                            > MAX_SESSION_TICKET_BYTES
                    {
                        let Some(expired) = self.received_tickets.pop_front() else {
                            break;
                        };
                        self.received_ticket_bytes = self
                            .received_ticket_bytes
                            .saturating_sub(expired.ticket_nonce.len() + expired.ticket.len());
                    }
                    self.received_tickets.push_back(SessionTicket {
                        ticket_lifetime,
                        ticket_age_add,
                        ticket_nonce,
                        ticket,
                        psk,
                    });
                    self.received_ticket_bytes += ticket_bytes;
                }
                Event::ResumptionSecret { psk } => {
                    self.pending_resumption_psk = Some(psk);
                }
            }
        }
        Ok(())
    }

    pub fn take_session_tickets(&mut self) -> Vec<SessionTicket> {
        self.received_ticket_bytes = 0;
        take(&mut self.received_tickets).into_iter().collect()
    }

    fn finalize_peer_tp(&mut self) -> Result<(), ConnError> {
        let raw = self
            .peer_transport_params_raw
            .as_ref()
            .ok_or(ConnError::TransportParameterMismatch)?;
        let peer_tp = Params::decode(raw)?;

        let expected_iscid = self
            .peer_first_scid
            .as_ref()
            .ok_or(ConnError::TransportParameterMismatch)?;
        let peer_iscid = peer_tp
            .initial_source_connection_id
            .as_ref()
            .ok_or(ConnError::TransportParameterMismatch)?;
        if peer_iscid != expected_iscid {
            return Err(ConnError::TransportParameterMismatch);
        }

        if self.is_client {
            let peer_odcid = peer_tp
                .original_destination_connection_id
                .as_ref()
                .ok_or(ConnError::TransportParameterMismatch)?;
            if peer_odcid != &self.original_dcid {
                return Err(ConnError::TransportParameterMismatch);
            }
        } else if peer_tp.original_destination_connection_id.is_some()
            || peer_tp.retry_source_connection_id.is_some()
        {
            return Err(ConnError::TransportParameterMismatch);
        }

        if self.is_client
            && let Some(tok) = peer_tp.stateless_reset_token
            && let Some(entry) = self.peer_cids.get_mut(&0)
        {
            entry.1 = tok;
        }
        self.peer_max_data = peer_tp.initial_max_data;
        self.peer_transport_params = Some(peer_tp);
        Ok(())
    }

    fn ensure_peer_stream_credit(&mut self, id: u64) {
        if self.peer_max_stream_data.contains_key(&id) {
            return;
        }
        let Some(tp) = &self.peer_transport_params else {
            return;
        };
        let is_uni = id & 0x2 != 0;
        let initiator_is_client = id & 0x1 == 0;
        let we_initiated = initiator_is_client == self.is_client;
        let limit = if is_uni {
            if we_initiated {
                tp.initial_max_stream_data_uni
            } else {
                0
            }
        } else if we_initiated {
            tp.initial_max_stream_data_bidi_remote
        } else {
            tp.initial_max_stream_data_bidi_local
        };
        self.peer_max_stream_data.insert(
            id,
            PeerStreamSendState {
                limit,
                final_offset: None,
                deliveries: 0,
                retransmits: 0,
            },
        );
    }

    pub fn send_packets(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        self.fill_batch(&mut out, now, MAX_BATCH_PACKETS, MAX_PMTU as usize);
        out
    }

    pub fn send_batch(
        &mut self,
        batch: &mut PacketBatch,
        now: Instant,
        max_packets: usize,
        max_packet_bytes: usize,
    ) {
        batch.clear();
        let packet_bytes = max_packet_bytes.min(self.path_mtu() as usize);
        let packet_slots = max_packets.min(MAX_BATCH_PACKETS);
        batch.buf.reserve(packet_slots.saturating_mul(packet_bytes));
        batch.segs.reserve(packet_slots);
        self.fill_batch(batch, now, packet_slots, packet_bytes);
    }

    pub(crate) fn send_one(
        &mut self,
        packet: &mut Vec<u8>,
        now: Instant,
        max_packet_bytes: usize,
    ) -> bool {
        let mut sink = PacketSlot {
            packet,
            emitted: false,
        };
        self.fill_batch(&mut sink, now, 1, max_packet_bytes);
        sink.emitted
    }

    fn snapshot_pending_streams(&mut self) {
        self.scratch_pending.clear();
        let mut visited = 0;
        let mut last_visited = None;
        if let Some(cursor) = self.stream_schedule_cursor {
            for (&stream_id, stream) in self.streams_send.range((Excluded(cursor), Unbounded)) {
                if visited == STREAM_SCHEDULE_WORK_LIMIT {
                    break;
                }
                visited += 1;
                last_visited = Some(stream_id);
                if stream.has_pending() {
                    self.scratch_pending.push(stream_id);
                }
            }
            if visited < STREAM_SCHEDULE_WORK_LIMIT {
                for (&stream_id, stream) in self.streams_send.range(..=cursor) {
                    if visited == STREAM_SCHEDULE_WORK_LIMIT {
                        break;
                    }
                    visited += 1;
                    last_visited = Some(stream_id);
                    if stream.has_pending() {
                        self.scratch_pending.push(stream_id);
                    }
                }
            }
        } else {
            for (&stream_id, stream) in &self.streams_send {
                if visited == STREAM_SCHEDULE_WORK_LIMIT {
                    break;
                }
                visited += 1;
                last_visited = Some(stream_id);
                if stream.has_pending() {
                    self.scratch_pending.push(stream_id);
                }
            }
        }
        self.stream_schedule_cursor = last_visited;
    }

    fn fill_batch<S: PacketSink>(
        &mut self,
        sink: &mut S,
        now: Instant,
        max_packets: usize,
        max_packet_bytes: usize,
    ) {
        if self.state == State::Closed {
            return;
        }
        let normal_packet_bytes = max_packet_bytes.min(self.path_mtu() as usize);
        let mut remaining = max_packets;
        let mut sent_handshake_packet = false;
        let mut sent_handshake_done = false;

        self.snapshot_pending_streams();

        while remaining != 0 && self.pto_probe_allowance != 0 {
            let Some(packet_ceiling) = self.emission_ceiling(normal_packet_bytes) else {
                break;
            };
            let Some(commit) = sink.emit(packet_ceiling, |dst| {
                self.build_pto_probe(dst, packet_ceiling)
            }) else {
                break;
            };
            if !self.commit_packet(commit, now) {
                return;
            }
            remaining -= 1;
        }

        if self.initial_w.is_some() {
            while remaining != 0 {
                if !self.allows_emit_for(PacketCargo::CryptoOrAck, now) {
                    break;
                }
                let has_crypto = self.has_initial_crypto();
                let has_ack = self.spaces[Epoch::Initial as usize].ack_pending;
                if !has_crypto && !has_ack {
                    break;
                }
                let Some(packet_ceiling) = self.emission_ceiling(normal_packet_bytes) else {
                    break;
                };
                let Some(commit) = sink.emit(packet_ceiling, |dst| {
                    self.build_crypto_packet(
                        dst,
                        packet_ceiling,
                        Epoch::Initial,
                        CryptoPacketMode::Regular,
                    )
                }) else {
                    break;
                };
                if !self.commit_packet(commit, now) {
                    return;
                }
                remaining -= 1;
                self.sent_initial = true;
            }
        }

        if remaining != 0 && self.zero_rtt_w.is_some() && self.app_w.is_none() {
            while remaining != 0 && self.allows_emit_for(PacketCargo::CryptoOrAck, now) {
                let Some(packet_ceiling) = self.emission_ceiling(normal_packet_bytes) else {
                    break;
                };
                let Some(commit) = sink.emit(packet_ceiling, |dst| {
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

        if self.handshake_w.is_some() {
            while remaining != 0 {
                if !self.allows_emit_for(PacketCargo::CryptoOrAck, now) {
                    break;
                }
                let has_crypto = self.has_handshake_crypto();
                let has_ack = self.spaces[Epoch::Handshake as usize].ack_pending;
                if !has_crypto && !has_ack {
                    break;
                }
                let Some(packet_ceiling) = self.emission_ceiling(normal_packet_bytes) else {
                    break;
                };
                let Some(commit) = sink.emit(packet_ceiling, |dst| {
                    self.build_crypto_packet(
                        dst,
                        packet_ceiling,
                        Epoch::Handshake,
                        CryptoPacketMode::Regular,
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

        if self.app_w.is_some() {
            if remaining != 0 && self.pending_close.is_some() {
                let commit =
                    self.emission_ceiling(normal_packet_bytes)
                        .and_then(|packet_ceiling| {
                            sink.emit(packet_ceiling, |dst| {
                                self.build_one_rtt_close(dst, packet_ceiling)
                            })
                        });
                if let Some(commit) = commit {
                    if !self.commit_packet(commit, now) {
                        return;
                    }
                    self.last_activity = now;
                    return;
                }
            }

            for _ in 0..4096u32 {
                if remaining == 0 {
                    break;
                }
                let want_handshake_done = self.handshake_done_pending;
                let has_app_ack = self.spaces[Epoch::Application as usize].ack_pending;
                let has_datagrams = !self.pending_datagrams.is_empty();
                let has_cid_admin =
                    !self.new_cid_pending.is_empty() || !self.retire_pending.is_empty();
                let has_path_response = !self.pending_path_responses.is_empty();
                let has_path_challenge = !self.pending_path_challenges.is_empty();
                let has_streams = !self.scratch_pending.is_empty();
                let has_flow_control = self.local_max_data_pending
                    || !self.local_max_stream_data_pending.is_empty()
                    || self.max_streams_bidi_pending;
                let has_lifecycle = !self.pending_resets.is_empty()
                    || !self.pending_stop_sending.is_empty()
                    || !self.pending_crypto_app.is_empty()
                    || !self.spaces[Epoch::Application as usize]
                        .crypto_retransmit
                        .is_empty()
                    || !self.spaces[Epoch::Application as usize]
                        .stream_retransmit
                        .is_empty();

                let one_shot = want_handshake_done
                    || has_cid_admin
                    || has_path_response
                    || has_path_challenge
                    || has_flow_control
                    || has_lifecycle
                    || (has_app_ack && !has_datagrams);
                if (!one_shot && !has_streams)
                    || !self.allows_emit_for(PacketCargo::CryptoOrAck, now)
                {
                    break;
                }
                let before = self.cc.bytes_in_flight;
                let Some(packet_ceiling) = self.emission_ceiling(normal_packet_bytes) else {
                    break;
                };
                let Some(commit) = sink.emit(packet_ceiling, |dst| {
                    self.build_one_rtt(dst, false, want_handshake_done, false, packet_ceiling)
                }) else {
                    break;
                };
                let did_handshake_done = commit.controls[..commit.control_len]
                    .iter()
                    .flatten()
                    .any(|delivery| delivery.record == ControlRecord::HandshakeDone);
                if !self.commit_packet(commit, now) {
                    return;
                }
                remaining -= 1;
                if did_handshake_done {
                    sent_handshake_done = true;
                }
                if !one_shot && self.cc.bytes_in_flight == before {
                    break;
                }
            }
            while remaining != 0 && !self.pending_datagrams.is_empty() {
                if !self.allows_emit_for(PacketCargo::DatagramOnly, now) {
                    break;
                }
                let Some(packet_ceiling) = self.emission_ceiling(normal_packet_bytes) else {
                    break;
                };
                let Some(commit) = sink.emit(packet_ceiling, |dst| {
                    self.build_one_rtt(dst, true, false, false, packet_ceiling)
                }) else {
                    break;
                };
                if !self.commit_packet(commit, now) {
                    return;
                }
                remaining -= 1;
            }
            if remaining != 0
                && let Some(probe_size) = self.pmtud.next_probe()
                && self.allows_emit_for(PacketCargo::CryptoOrAck, now)
            {
                let commit = self
                    .emission_ceiling(max_packet_bytes)
                    .and_then(|packet_ceiling| {
                        sink.emit(packet_ceiling, |dst| {
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

        if sent_handshake_packet && self.initial_w.is_some() {
            self.discard_initial_keys();
        }
        if sent_handshake_done && !self.is_client {
            self.discard_handshake_keys();
        }

        if !sink.is_empty() {
            self.last_activity = now;
            self.update_loss_timer();
        }
    }

    fn has_initial_crypto(&self) -> bool {
        !self.pending_crypto_initial.is_empty()
            || !self.spaces[Epoch::Initial as usize]
                .crypto_retransmit
                .is_empty()
    }

    fn has_handshake_crypto(&self) -> bool {
        !self.pending_crypto_handshake.is_empty()
            || !self.spaces[Epoch::Handshake as usize]
                .crypto_retransmit
                .is_empty()
    }

    fn append_ack_frame(&mut self, epoch: Epoch, out: &mut Vec<u8>, limit: usize) -> bool {
        let space = &mut self.spaces[epoch as usize];
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
        let start = out.len();
        let encoded = Frame::Ack {
            largest,
            delay: 0,
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
            self.new_cid_pending.push((seq, cid, srt));
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
            self.peer_cid.len(),
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
            1 + 4 + 1 + self.peer_cid.len() + 1 + self.local_cid.len() + PN_LEN as usize;
        Self::long_payload_limit(fixed_header, max_packet_bytes)
    }

    fn short_payload_limit(&self, max_packet_bytes: usize) -> usize {
        max_packet_bytes.saturating_sub(1 + self.peer_cid.len() + PN_LEN as usize + TAG_LEN)
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
        data: &[u8],
    ) -> bool {
        let start = out.len();
        if Frame::encode_stream(out, stream_id, offset, fin, true, data).is_ok()
            && out.len() <= limit
        {
            true
        } else {
            out.truncate(start);
            false
        }
    }

    fn can_track_packet(&self) -> bool {
        let pn = self.spaces[Epoch::Application as usize].next_pn;
        self.packet_journals.has_room_for(Epoch::Application, pn, 2)
            && self.crypto_deliveries.has_room(2)
            && self
                .control_deliveries
                .has_room(PACKET_CONTROL_CAPACITY * 2)
            && self.stream_deliveries.has_room(PACKET_STREAM_CAPACITY * 2)
    }

    fn can_track_probe(&self) -> bool {
        let pn = self.spaces[Epoch::Application as usize].next_pn;
        self.packet_journals.has_room_for(Epoch::Application, pn, 1)
    }

    fn control_inflight(&self, record: ControlRecord) -> bool {
        self.control_deliveries.contains(Epoch::Application, record)
    }

    fn cancel_stream_deliveries(&mut self, stream_id: u64) {
        self.stream_deliveries
            .remove_where(|delivery| delivery.record.stream_id == stream_id);
        self.spaces[Epoch::Application as usize]
            .stream_retransmit
            .retain(|(candidate, _, _, _)| *candidate != stream_id);
        self.spaces[Epoch::Application as usize]
            .stream_inflight
            .retain(|(candidate, _), _| *candidate != stream_id);
        if let Some(state) = self.peer_max_stream_data.get_mut(&stream_id) {
            state.deliveries = 0;
            state.retransmits = 0;
        }
    }

    fn commit_packet(&mut self, commit: PacketCommit, now: Instant) -> bool {
        let epoch = commit.epoch;
        let pn = commit.pn;
        let mut crypto_delivery = commit.crypto_probe;
        let mut journal = PacketJournal {
            epoch,
            pn,
            early_data: commit.early_data,
            sent_time: now,
            ack_eliciting: commit.ack_eliciting,
            in_flight: commit.in_flight,
            bytes_sent: commit.bytes,
            pto_protected: false,
            crypto: None,
            controls: [None; PACKET_CONTROL_CAPACITY],
            control_len: 0,
            streams: [None; PACKET_STREAM_CAPACITY],
            stream_len: 0,
        };
        self.spaces[epoch as usize].next_pn = pn.saturating_add(1);
        if commit.ack_included {
            self.spaces[epoch as usize].ack_pending = false;
        }
        if let Some(crypto) = commit.crypto {
            let (offset, mut data) = match crypto {
                CryptoCommit::Pending { offset, len } => {
                    let pending = match epoch {
                        Epoch::Initial => &mut self.pending_crypto_initial,
                        Epoch::Handshake => &mut self.pending_crypto_handshake,
                        Epoch::Application => &mut self.pending_crypto_app,
                    };
                    let take = len.min(pending.len());
                    let data = pending.drain(..take).collect::<Vec<_>>();
                    self.spaces[epoch as usize].crypto_next_offset =
                        offset.saturating_add(take as u64);
                    (offset, data)
                }
                CryptoCommit::Retransmit { index, offset, len } => {
                    let (stored_offset, mut data) =
                        self.spaces[epoch as usize].crypto_retransmit.remove(index);
                    let take = len.min(data.len());
                    let remainder = data.split_off(take);
                    if !remainder.is_empty() {
                        self.spaces[epoch as usize]
                            .crypto_retransmit
                            .push((stored_offset.saturating_add(take as u64), remainder));
                    }
                    (offset, data)
                }
            };
            crypto_delivery = Some(DeliveryCommit {
                record: CryptoRecord {
                    offset,
                    len: data.len(),
                },
                probe: None,
            });
            self.spaces[epoch as usize]
                .crypto_inflight
                .insert(offset, (take(&mut data), u64::MAX));
        }
        if let Some(delivery) = crypto_delivery {
            let handle = if let Some(handle) = delivery.probe {
                if !self.crypto_deliveries.add_probe_carrier(handle) {
                    self.state = State::Closed;
                    return false;
                }
                handle
            } else {
                let Some(handle) = self.crypto_deliveries.insert(epoch, delivery.record) else {
                    self.state = State::Closed;
                    return false;
                };
                handle
            };
            journal.crypto = Some(handle);
        }
        for delivery in commit.streams[..commit.stream_len]
            .iter()
            .flatten()
            .copied()
        {
            let record = delivery.record;
            if delivery.probe.is_none() && record.retransmit {
                if let Some(index) = self.spaces[Epoch::Application as usize]
                    .stream_retransmit
                    .iter()
                    .position(|item| {
                        *item == (record.stream_id, record.offset, record.len, record.fin)
                    })
                {
                    self.spaces[Epoch::Application as usize]
                        .stream_retransmit
                        .swap_remove(index);
                    if let Some(state) = self.peer_max_stream_data.get_mut(&record.stream_id) {
                        state.retransmits = state.retransmits.saturating_sub(1);
                    }
                }
            } else if delivery.probe.is_none()
                && let Some(stream) = self.streams_send.get_mut(&record.stream_id)
                && stream.next_offset() == record.offset
            {
                stream.advance_sent(record.len as usize, record.fin);
                self.peer_total_sent = self.peer_total_sent.saturating_add(record.len);
            }
            let handle = if let Some(handle) = delivery.probe {
                if !self.stream_deliveries.add_probe_carrier(handle) {
                    self.state = State::Closed;
                    return false;
                }
                handle
            } else {
                let Some(handle) = self.stream_deliveries.insert(epoch, record) else {
                    self.state = State::Closed;
                    return false;
                };
                if let Some(state) = self.peer_max_stream_data.get_mut(&record.stream_id) {
                    state.deliveries = state.deliveries.saturating_add(1);
                }
                handle
            };
            journal.streams[journal.stream_len] = Some(handle);
            journal.stream_len += 1;
        }
        for delivery in commit.controls[..commit.control_len]
            .iter()
            .flatten()
            .copied()
        {
            let record = delivery.record;
            if let ControlRecord::PathChallenge(data) = record
                && !self.outstanding_path_challenges.contains(&data)
            {
                self.outstanding_path_challenges.push(data);
            }
            let handle = if let Some(handle) = delivery.probe {
                if !self.control_deliveries.add_probe_carrier(handle) {
                    self.state = State::Closed;
                    return false;
                }
                handle
            } else {
                let Some(handle) = self.control_deliveries.insert(epoch, record) else {
                    self.state = State::Closed;
                    return false;
                };
                handle
            };
            journal.controls[journal.control_len] = Some(handle);
            journal.control_len += 1;
        }
        if commit.in_flight
            || commit.control_len != 0
            || commit.stream_len != 0
            || commit.early_data
            || commit.crypto.is_some()
            || commit.crypto_probe.is_some()
            || commit.pmtud_probe.is_some()
        {
            if !self.packet_journals.insert(journal) {
                self.state = State::Closed;
                return false;
            }
            if epoch == Epoch::Application && commit.ack_eliciting {
                self.spaces[epoch as usize].time_of_last_ack_eliciting = Some(now);
                self.spaces[epoch as usize].ack_eliciting_in_flight += 1;
            }
        }
        if commit.datagram {
            self.pending_datagrams.pop_front();
        }
        self.amplification_sent = self.amplification_sent.saturating_add(commit.bytes as u64);
        self.wire_sent(commit.bytes as u64, commit.in_flight, now);
        if epoch != Epoch::Application {
            self.spaces[epoch as usize].record_sent(SentPacket {
                pn,
                sent_time: now,
                ack_eliciting: commit.ack_eliciting,
                in_flight: commit.in_flight,
                bytes_sent: commit.bytes,
            });
        }
        if let Some(size) = commit.pmtud_probe {
            self.pmtud.arm_probe(size);
            self.pmtud_probe_pn = Some(pn);
        }
        if commit.pto_probe {
            self.pto_probe_allowance = self.pto_probe_allowance.saturating_sub(1);
            if self.pto_probe_allowance == 0 {
                self.pto_probe_epoch = None;
            }
        }
        if commit.close {
            self.pending_close = None;
            self.state = State::Closed;
        }
        true
    }

    fn ack_control(&mut self, record: ControlRecord) {
        match record {
            ControlRecord::HandshakeDone => self.handshake_done_pending = false,
            ControlRecord::NewConnectionId(sequence) => {
                if let Some(index) = self
                    .new_cid_pending
                    .iter()
                    .position(|(pending, _, _)| *pending == sequence)
                {
                    self.new_cid_pending.swap_remove(index);
                }
            }
            ControlRecord::RetireConnectionId(sequence) => {
                self.retire_pending.remove(&sequence);
            }
            ControlRecord::StopSending(stream_id, error_code) => {
                if self.pending_stop_sending.get(&stream_id) == Some(&error_code) {
                    self.pending_stop_sending.remove(&stream_id);
                }
            }
            ControlRecord::ResetStream(stream_id, error_code, final_size) => {
                if self.pending_resets.get(&stream_id) == Some(&(error_code, final_size)) {
                    self.pending_resets.remove(&stream_id);
                }
            }
            ControlRecord::MaxData(maximum) => {
                if self.local_max_data <= maximum {
                    self.local_max_data_pending = false;
                }
            }
            ControlRecord::MaxStreamData(stream_id, maximum) => {
                if self
                    .local_max_stream_data
                    .get(&stream_id)
                    .copied()
                    .unwrap_or(0)
                    <= maximum
                {
                    self.local_max_stream_data_pending.remove(&stream_id);
                }
            }
            ControlRecord::MaxStreamsBidi(maximum) => {
                if self.local_max_streams_bidi <= maximum {
                    self.max_streams_bidi_pending = false;
                }
            }
            ControlRecord::PathResponse(data) => {
                if let Some(index) = self.pending_path_responses.iter().position(|v| *v == data) {
                    self.pending_path_responses.swap_remove(index);
                }
            }
            ControlRecord::PathChallenge(data) => {
                if let Some(index) = self.pending_path_challenges.iter().position(|v| *v == data) {
                    self.pending_path_challenges.swap_remove(index);
                }
            }
            ControlRecord::DataBlocked(maximum) => {
                if self.peer_max_data == maximum {
                    self.blocked_data_emitted = true;
                }
            }
            ControlRecord::StreamDataBlocked(stream_id, maximum) => {
                if self
                    .peer_max_stream_data
                    .get(&stream_id)
                    .is_some_and(|state| state.limit == maximum)
                {
                    self.blocked_stream_emitted.insert(stream_id, ());
                }
            }
        }
    }

    fn ack_journal(&mut self, epoch: Epoch, pn: u64) {
        if let Some(journal) = self.packet_journals.remove(epoch, pn) {
            self.ack_packet_deliveries(journal);
        }
    }

    fn ack_application_journals(
        &mut self,
        largest: u64,
        ack_delay_microseconds: u64,
        first_range: u64,
        additional: AckRanges<'_>,
        now: Instant,
    ) {
        let mut journals = take(&mut self.packet_journals);
        journals.drain_application_ack(largest, first_range, additional, |journal| {
            if journal.pn == largest {
                let sample = now.saturating_duration_since(journal.sent_time);
                self.rtt
                    .update(sample, Duration::from_micros(ack_delay_microseconds));
            }
            if journal.ack_eliciting {
                self.pto_count = 0;
            }
            self.ack_application_packet(journal);
        });
        self.packet_journals = journals;
    }

    fn ack_application_packet(&mut self, journal: PacketJournal) {
        self.cc
            .packet_acked(journal.bytes_sent as u64, journal.in_flight);
        if Some(journal.pn) == self.pmtud_probe_pn {
            self.pmtud.probe_acked();
            self.pmtud_probe_pn = None;
        }
        if journal.ack_eliciting && journal.in_flight {
            self.spaces[Epoch::Application as usize].ack_eliciting_in_flight = self.spaces
                [Epoch::Application as usize]
                .ack_eliciting_in_flight
                .saturating_sub(1);
        }
        self.ack_packet_deliveries(journal);
    }

    fn lose_journal(&mut self, epoch: Epoch, pn: u64) {
        if let Some(journal) = self.packet_journals.remove(epoch, pn) {
            self.lose_packet_deliveries(journal);
        }
    }

    fn ack_packet_deliveries(&mut self, journal: PacketJournal) {
        if let Some(handle) = journal.crypto
            && let Some(delivery) = self.crypto_deliveries.remove(handle)
        {
            self.spaces[delivery.epoch as usize]
                .crypto_inflight
                .remove(&delivery.record.offset);
        }
        for handle in journal.controls[..journal.control_len]
            .iter()
            .flatten()
            .copied()
        {
            if let Some(delivery) = self.control_deliveries.remove(handle) {
                self.ack_control(delivery.record);
            }
        }
        for handle in journal.streams[..journal.stream_len]
            .iter()
            .flatten()
            .copied()
        {
            let Some(delivery) = self.stream_deliveries.remove(handle) else {
                continue;
            };
            let record = delivery.record;
            if let Some(state) = self.peer_max_stream_data.get_mut(&record.stream_id) {
                state.deliveries = state.deliveries.saturating_sub(1);
            }
            if let Some(stream) = self.streams_send.get_mut(&record.stream_id) {
                stream.ack(record.offset, record.len);
                if record.fin {
                    stream.mark_fin_acked();
                }
            }
            self.scratch_stream_cleanup.push(record.stream_id);
        }
    }

    fn lose_packet_deliveries(&mut self, journal: PacketJournal) {
        if let Some(handle) = journal.crypto
            && let Some(delivery) = self.crypto_deliveries.release(handle)
            && let Some((data, _)) = self.spaces[delivery.epoch as usize]
                .crypto_inflight
                .remove(&delivery.record.offset)
        {
            self.spaces[delivery.epoch as usize]
                .crypto_retransmit
                .push((delivery.record.offset, data));
        }
        for handle in journal.controls[..journal.control_len]
            .iter()
            .flatten()
            .copied()
        {
            self.control_deliveries.release(handle);
        }
        for handle in journal.streams[..journal.stream_len]
            .iter()
            .flatten()
            .copied()
        {
            let Some(delivery) = self.stream_deliveries.release(handle) else {
                continue;
            };
            let record = delivery.record;
            if let Some(state) = self.peer_max_stream_data.get_mut(&record.stream_id) {
                state.deliveries = state.deliveries.saturating_sub(1);
            }
            let active = self
                .streams_send
                .get(&record.stream_id)
                .is_some_and(|stream| {
                    !stream.reset_sent()
                        && stream.stop_sending_error().is_none()
                        && stream.chunk_at(record.offset, record.len).is_some()
                });
            if active {
                self.spaces[Epoch::Application as usize]
                    .stream_retransmit
                    .push((record.stream_id, record.offset, record.len, record.fin));
                if let Some(state) = self.peer_max_stream_data.get_mut(&record.stream_id) {
                    state.retransmits = state.retransmits.saturating_add(1);
                }
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
    ) -> Option<(CryptoCommit, &'a [u8])> {
        if let Some((index, (offset, data))) =
            space.crypto_retransmit.iter().enumerate().next_back()
        {
            let take = Self::crypto_data_limit(*offset, frame_room).min(data.len());
            if take == 0 {
                return None;
            }
            return Some((
                CryptoCommit::Retransmit {
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
            CryptoCommit::Pending { offset, len: take },
            &pending[..take],
        ))
    }

    fn encode_crypto(out: &mut Vec<u8>, offset: u64, data: &[u8]) -> bool {
        let start = out.len();
        out.push(0x06);
        let encoded = u64::try_from(data.len())
            .ok()
            .filter(|_| VarInt::encode(offset, out).is_ok())
            .is_some_and(|len| VarInt::encode(len, out).is_ok());
        if !encoded {
            out.truncate(start);
            return false;
        }
        out.extend_from_slice(data);
        true
    }

    fn pending_crypto_probe(
        &self,
        epoch: Epoch,
        frame_room: usize,
    ) -> Option<(DeliveryCommit<CryptoRecord>, &[u8])> {
        let (handle, record) = self.crypto_deliveries.next_probe(epoch, |_| false)?;
        let data = self.spaces[epoch as usize]
            .crypto_inflight
            .get(&record.offset)?
            .0
            .as_slice();
        (data.len() == record.len
            && Self::crypto_data_limit(record.offset, frame_room) >= record.len)
            .then_some((
                DeliveryCommit {
                    record,
                    probe: Some(handle),
                },
                data,
            ))
    }

    fn append_control_record(
        &self,
        out: &mut Vec<u8>,
        limit: usize,
        record: ControlRecord,
    ) -> bool {
        match record {
            ControlRecord::HandshakeDone => Self::append_frame(out, limit, &Frame::HandshakeDone),
            ControlRecord::NewConnectionId(sequence_number) => {
                let Some((_, cid, reset_token)) = self
                    .new_cid_pending
                    .iter()
                    .find(|item| item.0 == sequence_number)
                else {
                    return false;
                };
                let start = out.len();
                out.push(0x18);
                if VarInt::encode(sequence_number, out).is_err() || VarInt::encode(0, out).is_err()
                {
                    out.truncate(start);
                    return false;
                }
                out.push(cid.len() as u8);
                out.extend_from_slice(cid);
                out.extend_from_slice(reset_token);
                if out.len() <= limit {
                    true
                } else {
                    out.truncate(start);
                    false
                }
            }
            ControlRecord::RetireConnectionId(sequence_number) => {
                Self::append_frame(out, limit, &Frame::RetireConnectionId { sequence_number })
            }
            ControlRecord::StopSending(stream_id, error_code) => Self::append_frame(
                out,
                limit,
                &Frame::StopSending {
                    stream_id,
                    error_code,
                },
            ),
            ControlRecord::ResetStream(stream_id, error_code, final_size) => Self::append_frame(
                out,
                limit,
                &Frame::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                },
            ),
            ControlRecord::MaxData(maximum_data) => {
                Self::append_frame(out, limit, &Frame::MaxData { maximum_data })
            }
            ControlRecord::MaxStreamData(stream_id, maximum_stream_data) => Self::append_frame(
                out,
                limit,
                &Frame::MaxStreamData {
                    stream_id,
                    maximum_stream_data,
                },
            ),
            ControlRecord::MaxStreamsBidi(max_streams) => Self::append_frame(
                out,
                limit,
                &Frame::MaxStreams {
                    is_uni: false,
                    max_streams,
                },
            ),
            ControlRecord::PathResponse(data) => {
                Self::append_frame(out, limit, &Frame::PathResponse { data })
            }
            ControlRecord::PathChallenge(data) => {
                Self::append_frame(out, limit, &Frame::PathChallenge { data })
            }
            ControlRecord::DataBlocked(maximum_data) => {
                Self::append_frame(out, limit, &Frame::DataBlocked { maximum_data })
            }
            ControlRecord::StreamDataBlocked(stream_id, maximum_stream_data) => Self::append_frame(
                out,
                limit,
                &Frame::StreamDataBlocked {
                    stream_id,
                    maximum_stream_data,
                },
            ),
        }
    }

    fn build_pto_probe(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
    ) -> Option<(usize, PacketCommit)> {
        if !self.can_track_probe() {
            return None;
        }
        match self.pto_probe_epoch? {
            Epoch::Initial | Epoch::Handshake => self.build_crypto_packet(
                dst,
                max_packet_bytes,
                self.pto_probe_epoch?,
                CryptoPacketMode::PtoProbe,
            ),
            Epoch::Application if self.app_w.is_some() => {
                self.build_one_rtt(dst, false, false, true, max_packet_bytes)
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
        let result = encode_long_header_into(
            &mut header,
            LongHeader {
                version: QUIC_V1,
                packet_type,
                dcid: &self.peer_cid,
                scid: &self.local_cid,
                token,
                packet_number: pn,
                packet_number_len: PN_LEN,
            },
            frames.len() + TAG_LEN,
        )
        .ok()
        .and_then(|pn_offset| {
            let protection = match epoch {
                Epoch::Initial => self.initial_w.as_ref(),
                Epoch::Handshake => self.handshake_w.as_ref(),
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
        mode: CryptoPacketMode,
    ) -> Option<(usize, PacketCommit)> {
        if epoch == Epoch::Application
            || epoch == Epoch::Initial && self.is_client && max_packet_bytes < MIN_INITIAL_LEN
        {
            return None;
        }
        match epoch {
            Epoch::Initial => self.initial_w.as_ref()?,
            Epoch::Handshake => self.handshake_w.as_ref()?,
            Epoch::Application => return None,
        };
        let payload_limit = match epoch {
            Epoch::Initial => self.initial_payload_limit(max_packet_bytes),
            Epoch::Handshake => self.handshake_payload_limit(max_packet_bytes),
            Epoch::Application => return None,
        };
        let pn = self.spaces[epoch as usize].next_pn;

        let mut frames = take(&mut self.scratch_frames);
        frames.clear();
        let ack_included = self.append_ack_frame(epoch, &mut frames, payload_limit);
        let frame_room = payload_limit.saturating_sub(frames.len());
        let mut crypto = None;
        let mut crypto_probe = None;
        match mode {
            CryptoPacketMode::Regular => {
                if self.packet_journals.has_room_for(epoch, pn, 2)
                    && self.crypto_deliveries.has_room(2)
                {
                    let chunk = match epoch {
                        Epoch::Initial => Self::peek_crypto_chunk(
                            &self.spaces[epoch as usize],
                            &self.pending_crypto_initial,
                            frame_room,
                        ),
                        Epoch::Handshake => Self::peek_crypto_chunk(
                            &self.spaces[epoch as usize],
                            &self.pending_crypto_handshake,
                            frame_room,
                        ),
                        Epoch::Application => None,
                    };
                    if let Some((record, data)) = chunk {
                        let offset = match record {
                            CryptoCommit::Pending { offset, .. }
                            | CryptoCommit::Retransmit { offset, .. } => offset,
                        };
                        if Self::encode_crypto(&mut frames, offset, data) {
                            crypto = Some(record);
                        }
                    }
                }
            }
            CryptoPacketMode::PtoProbe => {
                if let Some((delivery, data)) = self.pending_crypto_probe(epoch, frame_room)
                    && Self::encode_crypto(&mut frames, delivery.record.offset, data)
                {
                    crypto_probe = Some(delivery);
                } else {
                    frames.push(TYPE_PING);
                }
            }
        }

        if mode == CryptoPacketMode::Regular && frames.is_empty() {
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
        let mut commit = PacketCommit::new(epoch, pn);
        commit.bytes = n;
        commit.ack_eliciting = mode == CryptoPacketMode::PtoProbe || crypto.is_some();
        commit.in_flight = commit.ack_eliciting;
        commit.ack_included = ack_included;
        commit.crypto = crypto;
        commit.crypto_probe = crypto_probe;
        commit.pto_probe = mode == CryptoPacketMode::PtoProbe;
        Some((n, commit))
    }

    fn build_one_rtt(
        &mut self,
        dst: &mut Vec<u8>,
        dgram: bool,
        emit_handshake_done: bool,
        pto_probe: bool,
        max_packet_bytes: usize,
    ) -> Option<(usize, PacketCommit)> {
        let payload_limit = self.short_payload_limit(max_packet_bytes);
        let pn = self.spaces[Epoch::Application as usize].next_pn;

        let mut frames = take(&mut self.scratch_frames);
        frames.clear();
        let mut commit = PacketCommit::new(Epoch::Application, pn);
        let track_delivery = self.can_track_packet();
        if dgram {
            if !track_delivery
                && self.datagram_congestion_control == DatagramCongestionControl::Standard
            {
                self.scratch_frames = frames;
                return None;
            }
            commit.ack_included =
                self.append_ack_frame(Epoch::Application, &mut frames, payload_limit);
            let data = self.pending_datagrams.front()?;
            if data.len().saturating_add(1) > payload_limit.saturating_sub(frames.len()) {
                if commit.ack_included {
                } else {
                    self.scratch_frames = frames;
                    return None;
                }
            } else {
                frames.push(0x30);
                frames.extend_from_slice(data);
                commit.datagram = true;
                commit.ack_eliciting = true;
            }
            if frames.is_empty() {
                self.scratch_frames = frames;
                return None;
            }
        } else if pto_probe {
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
            while commit.control_len < PACKET_CONTROL_CAPACITY {
                let next = self
                    .control_deliveries
                    .next_probe(Epoch::Application, |handle| {
                        commit.controls[..commit.control_len]
                            .iter()
                            .flatten()
                            .any(|delivery| delivery.probe == Some(handle))
                    });
                let Some((handle, record)) = next else {
                    break;
                };
                if !self.append_control_record(&mut frames, payload_limit, record) {
                    break;
                }
                commit.push_control_delivery(DeliveryCommit {
                    record,
                    probe: Some(handle),
                });
                commit.ack_eliciting = true;
            }
            while commit.stream_len < PACKET_STREAM_CAPACITY {
                let next = self
                    .stream_deliveries
                    .next_probe(Epoch::Application, |handle| {
                        commit.streams[..commit.stream_len]
                            .iter()
                            .flatten()
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
                let Some(chunk) = self
                    .streams_send
                    .get(&record.stream_id)
                    .and_then(|stream| stream.chunk_at(record.offset, record.len))
                else {
                    if self.stream_deliveries.remove(handle).is_some()
                        && let Some(state) = self.peer_max_stream_data.get_mut(&record.stream_id)
                    {
                        state.deliveries = state.deliveries.saturating_sub(1);
                    }
                    continue;
                };
                if !Self::append_stream_frame(
                    &mut frames,
                    payload_limit,
                    record.stream_id,
                    record.offset,
                    record.fin,
                    chunk,
                ) {
                    break;
                }
                commit.push_stream_delivery(DeliveryCommit {
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
        } else {
            commit.ack_included =
                self.append_ack_frame(Epoch::Application, &mut frames, payload_limit);
            if emit_handshake_done
                && track_delivery
                && !self.control_inflight(ControlRecord::HandshakeDone)
                && self
                    .control_deliveries
                    .has_room(commit.control_len.saturating_add(1))
                && Self::append_frame(&mut frames, payload_limit, &Frame::HandshakeDone)
            {
                commit.push_control(ControlRecord::HandshakeDone);
                commit.ack_eliciting = true;
            }
            if let Some((seq, cid, token)) = self
                .new_cid_pending
                .iter()
                .rev()
                .find(|item| !self.control_inflight(ControlRecord::NewConnectionId(item.0)))
            {
                let start = frames.len();
                frames.push(0x18);
                if VarInt::encode(*seq, &mut frames).is_err()
                    || VarInt::encode(0, &mut frames).is_err()
                {
                    frames.truncate(start);
                    self.scratch_frames = frames;
                    return None;
                }
                frames.push(cid.len() as u8);
                frames.extend_from_slice(cid);
                frames.extend_from_slice(token);
                if track_delivery
                    && frames.len() <= payload_limit
                    && self
                        .control_deliveries
                        .has_room(commit.control_len.saturating_add(1))
                {
                    commit.push_control(ControlRecord::NewConnectionId(*seq));
                    commit.ack_eliciting = true;
                } else {
                    frames.truncate(start);
                }
            }
            if let Some(&seq) = self.retire_pending.iter().rev().find(|&&sequence| {
                !self.control_inflight(ControlRecord::RetireConnectionId(sequence))
            }) {
                let frame = Frame::RetireConnectionId {
                    sequence_number: seq,
                };
                if track_delivery
                    && self
                        .control_deliveries
                        .has_room(commit.control_len.saturating_add(1))
                    && Self::append_frame(&mut frames, payload_limit, &frame)
                {
                    commit.push_control(ControlRecord::RetireConnectionId(seq));
                    commit.ack_eliciting = true;
                }
            }
            let frame_room = payload_limit.saturating_sub(frames.len());
            let crypto = track_delivery
                .then(|| {
                    Self::peek_crypto_chunk(
                        &self.spaces[Epoch::Application as usize],
                        &self.pending_crypto_app,
                        frame_room,
                    )
                })
                .flatten();
            if let Some((crypto, data)) = crypto {
                let offset = match crypto {
                    CryptoCommit::Pending { offset, .. }
                    | CryptoCommit::Retransmit { offset, .. } => offset,
                };
                if Self::encode_crypto(&mut frames, offset, data) {
                    commit.crypto = Some(crypto);
                    commit.ack_eliciting = true;
                }
            }
            if let Some((&id, &error_code)) =
                self.pending_stop_sending.iter().find(|(id, error)| {
                    !self.control_inflight(ControlRecord::StopSending(**id, **error))
                })
            {
                let frame = Frame::StopSending {
                    stream_id: id,
                    error_code,
                };
                if track_delivery
                    && self
                        .control_deliveries
                        .has_room(commit.control_len.saturating_add(1))
                    && Self::append_frame(&mut frames, payload_limit, &frame)
                {
                    commit.push_control(ControlRecord::StopSending(id, error_code));
                    commit.ack_eliciting = true;
                }
            }
            if let Some((&id, &(error_code, final_size))) =
                self.pending_resets
                    .iter()
                    .find(|(id, (error, final_size))| {
                        !self.control_inflight(ControlRecord::ResetStream(
                            **id,
                            *error,
                            *final_size,
                        ))
                    })
            {
                let frame = Frame::ResetStream {
                    stream_id: id,
                    error_code,
                    final_size,
                };
                if track_delivery
                    && self
                        .control_deliveries
                        .has_room(commit.control_len.saturating_add(1))
                    && Self::append_frame(&mut frames, payload_limit, &frame)
                {
                    commit.push_control(ControlRecord::ResetStream(id, error_code, final_size));
                    commit.ack_eliciting = true;
                }
            }
            let max_data = ControlRecord::MaxData(self.local_max_data);
            if self.local_max_data_pending
                && track_delivery
                && !self.control_inflight(max_data)
                && self
                    .control_deliveries
                    .has_room(commit.control_len.saturating_add(1))
                && Self::append_frame(
                    &mut frames,
                    payload_limit,
                    &Frame::MaxData {
                        maximum_data: self.local_max_data,
                    },
                )
            {
                commit.push_control(max_data);
                commit.ack_eliciting = true;
            }
            if let Some((&id, _)) = self.local_max_stream_data_pending.iter().find(|(id, _)| {
                let maximum = self.local_max_stream_data.get(id).copied().unwrap_or(0);
                !self.control_inflight(ControlRecord::MaxStreamData(**id, maximum))
            }) {
                let maximum = *self.local_max_stream_data.get(&id).unwrap_or(&0);
                let frame = Frame::MaxStreamData {
                    stream_id: id,
                    maximum_stream_data: maximum,
                };
                if track_delivery
                    && self
                        .control_deliveries
                        .has_room(commit.control_len.saturating_add(1))
                    && Self::append_frame(&mut frames, payload_limit, &frame)
                {
                    commit.push_control(ControlRecord::MaxStreamData(id, maximum));
                    commit.ack_eliciting = true;
                }
            }
            let max_streams = ControlRecord::MaxStreamsBidi(self.local_max_streams_bidi);
            if self.max_streams_bidi_pending
                && track_delivery
                && !self.control_inflight(max_streams)
                && self
                    .control_deliveries
                    .has_room(commit.control_len.saturating_add(1))
                && Self::append_frame(
                    &mut frames,
                    payload_limit,
                    &Frame::MaxStreams {
                        is_uni: false,
                        max_streams: self.local_max_streams_bidi,
                    },
                )
            {
                commit.push_control(max_streams);
                commit.ack_eliciting = true;
            }
            while track_delivery
                && self
                    .control_deliveries
                    .has_room(commit.control_len.saturating_add(1))
                && commit.control_len < PACKET_CONTROL_CAPACITY
            {
                let next = self.pending_path_responses.iter().rev().find(|&&data| {
                    let record = ControlRecord::PathResponse(data);
                    !self.control_inflight(record)
                        && !commit.controls[..commit.control_len]
                            .iter()
                            .flatten()
                            .any(|pending| pending.record == record)
                });
                let Some(&data) = next else {
                    break;
                };
                if !Self::append_frame(&mut frames, payload_limit, &Frame::PathResponse { data }) {
                    break;
                }
                commit.push_control(ControlRecord::PathResponse(data));
                commit.ack_eliciting = true;
            }
            while track_delivery
                && self
                    .control_deliveries
                    .has_room(commit.control_len.saturating_add(1))
                && commit.control_len < PACKET_CONTROL_CAPACITY
            {
                let next = self.pending_path_challenges.iter().rev().find(|&&data| {
                    let record = ControlRecord::PathChallenge(data);
                    !self.control_inflight(record)
                        && !commit.controls[..commit.control_len]
                            .iter()
                            .flatten()
                            .any(|pending| pending.record == record)
                });
                let Some(&data) = next else {
                    break;
                };
                if !Self::append_frame(&mut frames, payload_limit, &Frame::PathChallenge { data }) {
                    break;
                }
                commit.push_control(ControlRecord::PathChallenge(data));
                commit.ack_eliciting = true;
            }
            while track_delivery
                && self
                    .stream_deliveries
                    .has_room(commit.stream_len.saturating_add(1))
                && commit.stream_len < PACKET_STREAM_CAPACITY
            {
                let room = payload_limit
                    .saturating_sub(frames.len().saturating_add(STREAM_FRAME_OVERHEAD));
                let pos = self.spaces[Epoch::Application as usize]
                    .stream_retransmit
                    .iter()
                    .enumerate()
                    .find(|(_, (sid, off, len, fin))| {
                        (*len as usize) <= room
                            && !commit.streams[..commit.stream_len].iter().flatten().any(
                                |delivery| {
                                    let record = delivery.record;
                                    (record.stream_id, record.offset, record.len, record.fin)
                                        == (*sid, *off, *len, *fin)
                                },
                            )
                    })
                    .map(|(position, _)| position);
                let Some(pos) = pos else {
                    break;
                };
                let (sid, off, len, fin) =
                    self.spaces[Epoch::Application as usize].stream_retransmit[pos];
                let Some(chunk) = self
                    .streams_send
                    .get(&sid)
                    .and_then(|s| s.chunk_at(off, len))
                else {
                    self.spaces[Epoch::Application as usize]
                        .stream_retransmit
                        .swap_remove(pos);
                    if let Some(state) = self.peer_max_stream_data.get_mut(&sid) {
                        state.retransmits = state.retransmits.saturating_sub(1);
                    }
                    continue;
                };
                if !Self::append_stream_frame(&mut frames, payload_limit, sid, off, fin, chunk) {
                    break;
                }
                commit.push_stream(StreamRecord {
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
                && idx < self.scratch_pending.len()
                && self
                    .stream_deliveries
                    .has_room(commit.stream_len.saturating_add(1))
                && commit.stream_len < PACKET_STREAM_CAPACITY
            {
                let id = self.scratch_pending[idx];
                self.ensure_peer_stream_credit(id);
                let stream_limit = self
                    .peer_max_stream_data
                    .get(&id)
                    .map(|state| state.limit)
                    .unwrap_or(0);
                let Some(stream) = self.streams_send.get(&id) else {
                    idx += 1;
                    continue;
                };
                let stream_budget = stream_limit.saturating_sub(stream.next_offset());
                let packet_fresh_bytes = commit.streams[..commit.stream_len]
                    .iter()
                    .flatten()
                    .filter(|delivery| !delivery.record.retransmit)
                    .map(|delivery| delivery.record.len)
                    .sum::<u64>();
                let conn_budget = self
                    .peer_max_data
                    .saturating_sub(self.peer_total_sent.saturating_add(packet_fresh_bytes));
                let flow_take = stream_budget.min(conn_budget);
                if flow_take == 0 {
                    let has_pending = stream.has_pending();
                    if conn_budget == 0
                        && !self.blocked_data_emitted
                        && !self.control_inflight(ControlRecord::DataBlocked(self.peer_max_data))
                        && self
                            .control_deliveries
                            .has_room(commit.control_len.saturating_add(1))
                        && Self::append_frame(
                            &mut frames,
                            payload_limit,
                            &Frame::DataBlocked {
                                maximum_data: self.peer_max_data,
                            },
                        )
                    {
                        commit.push_control(ControlRecord::DataBlocked(self.peer_max_data));
                        commit.ack_eliciting = true;
                    }
                    if stream_budget == 0
                        && !self.blocked_stream_emitted.contains_key(&id)
                        && has_pending
                        && !self
                            .control_inflight(ControlRecord::StreamDataBlocked(id, stream_limit))
                        && self
                            .control_deliveries
                            .has_room(commit.control_len.saturating_add(1))
                        && Self::append_frame(
                            &mut frames,
                            payload_limit,
                            &Frame::StreamDataBlocked {
                                stream_id: id,
                                maximum_stream_data: stream_limit,
                            },
                        )
                    {
                        commit.push_control(ControlRecord::StreamDataBlocked(id, stream_limit));
                        commit.ack_eliciting = true;
                    }
                    idx += 1;
                    continue;
                }
                let packet_room = payload_limit
                    .saturating_sub(frames.len().saturating_add(STREAM_FRAME_OVERHEAD));
                let take = flow_take.min(packet_room as u64) as usize;
                if take == 0 {
                    break;
                }
                if stream.blocked() {
                    idx += 1;
                    continue;
                }
                let (offset, slice) = stream.unsent();
                let n = take.min(slice.len());
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
                    &slice[..n],
                ) {
                    break;
                }
                commit.push_stream(StreamRecord {
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
            self.scratch_frames = frames;
            return None;
        }

        let mut header = take(&mut self.scratch_header);
        header.clear();
        let pn_off = encode_short_header_into(&mut header, &self.peer_cid, pn, PN_LEN).ok()?;
        let seg = self
            .app_w
            .as_ref()?
            .encrypt_short_into(dst, &header, &frames, pn, pn_off, PN_LEN as usize)
            .ok()?;

        header.clear();
        self.scratch_header = header;
        frames.clear();
        self.scratch_frames = frames;
        commit.bytes = seg;
        commit.in_flight = commit.ack_eliciting
            && !(commit.datagram
                && self.datagram_congestion_control == DatagramCongestionControl::Uncongested);
        Some((seg, commit))
    }

    fn build_zero_rtt(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
        pto_probe: bool,
    ) -> Option<(usize, PacketCommit)> {
        self.zero_rtt_w.as_ref()?;
        if !(if pto_probe {
            self.can_track_probe()
        } else {
            self.can_track_packet()
        }) {
            return None;
        }
        let payload_limit = self.handshake_payload_limit(max_packet_bytes);
        let pn = self.spaces[Epoch::Application as usize].next_pn;
        let mut frames = take(&mut self.scratch_frames);
        frames.clear();
        let mut commit = PacketCommit::new(Epoch::Application, pn);
        commit.early_data = true;
        if pto_probe {
            while commit.stream_len < PACKET_STREAM_CAPACITY {
                let next = self
                    .stream_deliveries
                    .next_probe(Epoch::Application, |handle| {
                        commit.streams[..commit.stream_len]
                            .iter()
                            .flatten()
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
                let Some(chunk) = self
                    .streams_send
                    .get(&record.stream_id)
                    .and_then(|stream| stream.chunk_at(record.offset, record.len))
                else {
                    if self.stream_deliveries.remove(handle).is_some()
                        && let Some(state) = self.peer_max_stream_data.get_mut(&record.stream_id)
                    {
                        state.deliveries = state.deliveries.saturating_sub(1);
                    }
                    continue;
                };
                if !Self::append_stream_frame(
                    &mut frames,
                    payload_limit,
                    record.stream_id,
                    record.offset,
                    record.fin,
                    chunk,
                ) {
                    break;
                }
                commit.push_stream_delivery(DeliveryCommit {
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
            self.scratch_pending.len()
        } {
            if commit.stream_len == PACKET_STREAM_CAPACITY
                || !self
                    .stream_deliveries
                    .has_room(commit.stream_len.saturating_add(1))
            {
                break;
            }
            let id = self.scratch_pending[index];
            self.ensure_peer_stream_credit(id);
            let stream_limit = self
                .peer_max_stream_data
                .get(&id)
                .map(|state| state.limit)
                .unwrap_or(u64::MAX);
            let Some(stream) = self.streams_send.get(&id) else {
                continue;
            };
            let stream_budget = stream_limit.saturating_sub(stream.next_offset());
            let conn_budget = self.peer_transport_params.as_ref().map_or(u64::MAX, |_| {
                self.peer_max_data
                    .saturating_sub(self.peer_total_sent.saturating_add(packet_fresh_bytes))
            });
            let packet_room =
                payload_limit.saturating_sub(frames.len().saturating_add(STREAM_FRAME_OVERHEAD));
            let take = stream_budget.min(conn_budget).min(packet_room as u64) as usize;
            if take == 0 {
                continue;
            }
            if stream.blocked() {
                continue;
            }
            let (offset, slice) = stream.unsent();
            let n = take.min(slice.len());
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
                &slice[..n],
            ) {
                break;
            }
            commit.push_stream(StreamRecord {
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
        let pn_off = encode_long_header_into(
            &mut header,
            LongHeader {
                version: QUIC_V1,
                packet_type: LONG_ZERO_RTT,
                dcid: &self.peer_cid,
                scid: &self.local_cid,
                token: None,
                packet_number: pn,
                packet_number_len: PN_LEN,
            },
            body_len_after_pn,
        )
        .ok()?;
        let n = self
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
    ) -> Option<(usize, PacketCommit)> {
        if !self.can_track_packet() {
            return None;
        }
        let target_size = target_size.min(u64::try_from(max_packet_bytes).unwrap_or(u64::MAX));
        let pn = self.spaces[Epoch::Application as usize].next_pn;

        let mut frames = take(&mut self.scratch_frames);
        frames.clear();
        frames.push(TYPE_PING);
        let header_overhead = 1 + self.peer_cid.len() + PN_LEN as usize;
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
        let pn_off = encode_short_header_into(&mut header, &self.peer_cid, pn, PN_LEN).ok()?;
        let n = self
            .app_w
            .as_ref()?
            .encrypt_short_into(dst, &header, &frames, pn, pn_off, PN_LEN as usize)
            .ok()?;

        header.clear();
        self.scratch_header = header;
        frames.clear();
        self.scratch_frames = frames;
        let mut commit = PacketCommit::new(Epoch::Application, pn);
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
    ) -> Option<(usize, PacketCommit)> {
        let close = self.pending_close.as_ref()?;
        let payload_limit = self.short_payload_limit(max_packet_bytes);
        let pn = self.spaces[Epoch::Application as usize].next_pn;

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
        let encoded = VarInt::encode(close.error_code, &mut frames).is_ok()
            && (close.is_application || VarInt::encode(close.frame_type, &mut frames).is_ok())
            && u64::try_from(reason_len).is_ok_and(|len| VarInt::encode(len, &mut frames).is_ok());
        if !encoded {
            frames.clear();
            self.scratch_frames = frames;
            return None;
        }
        frames.extend_from_slice(&close.reason[..reason_len]);

        let mut header = take(&mut self.scratch_header);
        header.clear();
        let pn_off = encode_short_header_into(&mut header, &self.peer_cid, pn, PN_LEN).ok()?;
        let n = self
            .app_w
            .as_ref()?
            .encrypt_short_into(dst, &header, &frames, pn, pn_off, PN_LEN as usize)
            .ok()?;

        header.clear();
        self.scratch_header = header;
        frames.clear();
        self.scratch_frames = frames;
        let mut commit = PacketCommit::new(Epoch::Application, pn);
        commit.bytes = n;
        commit.close = true;
        Some((n, commit))
    }

    fn allows_emit_for(&self, cargo: PacketCargo, now: Instant) -> bool {
        if !self.anti_amp_allows() {
            return false;
        }
        match cargo {
            PacketCargo::CryptoOrAck => self.cc.allows_send() && self.pacer.allows_send(now),
            PacketCargo::DatagramOnly => match self.datagram_congestion_control {
                DatagramCongestionControl::Standard => {
                    self.cc.allows_send() && self.pacer.allows_send(now)
                }
                DatagramCongestionControl::Uncongested => true,
            },
        }
    }

    pub fn next_send_time(&self) -> Instant {
        self.pacer.next_release_time()
    }

    pub(crate) fn has_pending_output(&self) -> bool {
        if self.state == State::Closed {
            return false;
        }
        if self.pto_probe_allowance != 0 {
            return true;
        }
        if self.initial_w.is_some()
            && (self.has_initial_crypto() || self.spaces[Epoch::Initial as usize].ack_pending)
        {
            return true;
        }
        if self.zero_rtt_w.is_some()
            && self.app_w.is_none()
            && self
                .streams_send
                .values()
                .any(|stream| stream.has_pending())
        {
            return true;
        }
        if self.handshake_w.is_some()
            && (self.has_handshake_crypto() || self.spaces[Epoch::Handshake as usize].ack_pending)
        {
            return true;
        }
        self.app_w.is_some()
            && (self.pending_close.is_some()
                || self.handshake_done_pending
                || self.spaces[Epoch::Application as usize].ack_pending
                || !self.pending_datagrams.is_empty()
                || !self.new_cid_pending.is_empty()
                || !self.retire_pending.is_empty()
                || !self.pending_path_responses.is_empty()
                || !self.pending_path_challenges.is_empty()
                || self.local_max_data_pending
                || !self.local_max_stream_data_pending.is_empty()
                || self.max_streams_bidi_pending
                || !self.pending_resets.is_empty()
                || !self.pending_stop_sending.is_empty()
                || !self.pending_crypto_app.is_empty()
                || !self.spaces[Epoch::Application as usize]
                    .crypto_retransmit
                    .is_empty()
                || !self.spaces[Epoch::Application as usize]
                    .stream_retransmit
                    .is_empty()
                || self
                    .streams_send
                    .values()
                    .any(|stream| stream.has_pending())
                || self.pmtud.next_probe().is_some())
    }

    fn has_sendable_control(&self) -> bool {
        (self.handshake_done_pending && !self.control_inflight(ControlRecord::HandshakeDone))
            || self.new_cid_pending.iter().any(|(sequence, _, _)| {
                !self.control_inflight(ControlRecord::NewConnectionId(*sequence))
            })
            || self.retire_pending.iter().any(|sequence| {
                !self.control_inflight(ControlRecord::RetireConnectionId(*sequence))
            })
            || self.pending_stop_sending.iter().any(|(stream_id, error)| {
                !self.control_inflight(ControlRecord::StopSending(*stream_id, *error))
            })
            || self
                .pending_resets
                .iter()
                .any(|(stream_id, (error, final_size))| {
                    !self.control_inflight(ControlRecord::ResetStream(
                        *stream_id,
                        *error,
                        *final_size,
                    ))
                })
            || (self.local_max_data_pending
                && !self.control_inflight(ControlRecord::MaxData(self.local_max_data)))
            || self.local_max_stream_data_pending.keys().any(|stream_id| {
                let maximum = self
                    .local_max_stream_data
                    .get(stream_id)
                    .copied()
                    .unwrap_or(0);
                !self.control_inflight(ControlRecord::MaxStreamData(*stream_id, maximum))
            })
            || (self.max_streams_bidi_pending
                && !self
                    .control_inflight(ControlRecord::MaxStreamsBidi(self.local_max_streams_bidi)))
            || self
                .pending_path_responses
                .iter()
                .any(|data| !self.control_inflight(ControlRecord::PathResponse(*data)))
            || self
                .pending_path_challenges
                .iter()
                .any(|data| !self.control_inflight(ControlRecord::PathChallenge(*data)))
    }

    fn has_sendable_stream(&self) -> bool {
        if !self.spaces[Epoch::Application as usize]
            .stream_retransmit
            .is_empty()
        {
            return true;
        }
        let conn_budget = self.peer_max_data.saturating_sub(self.peer_total_sent);
        self.streams_send.iter().any(|(stream_id, stream)| {
            if !stream.has_pending() || stream.blocked() {
                return false;
            }
            let stream_limit = self
                .peer_max_stream_data
                .get(stream_id)
                .map(|state| state.limit)
                .unwrap_or(u64::MAX);
            let stream_budget = stream_limit.saturating_sub(stream.next_offset());
            (conn_budget != 0 && stream_budget != 0)
                || (conn_budget == 0
                    && !self.blocked_data_emitted
                    && !self.control_inflight(ControlRecord::DataBlocked(self.peer_max_data)))
                || (stream_budget == 0
                    && !self.blocked_stream_emitted.contains_key(stream_id)
                    && !self.control_inflight(ControlRecord::StreamDataBlocked(
                        *stream_id,
                        stream_limit,
                    )))
        })
    }

    fn has_sendable_output(&self) -> bool {
        self.pto_probe_allowance != 0
            || (self.initial_w.is_some()
                && (self.has_initial_crypto() || self.spaces[Epoch::Initial as usize].ack_pending))
            || (self.zero_rtt_w.is_some() && self.app_w.is_none() && self.has_sendable_stream())
            || (self.handshake_w.is_some()
                && (self.has_handshake_crypto()
                    || self.spaces[Epoch::Handshake as usize].ack_pending))
            || (self.app_w.is_some()
                && (self.pending_close.is_some()
                    || self.spaces[Epoch::Application as usize].ack_pending
                    || !self.pending_datagrams.is_empty()
                    || self.has_sendable_control()
                    || !self.pending_crypto_app.is_empty()
                    || !self.spaces[Epoch::Application as usize]
                        .crypto_retransmit
                        .is_empty()
                    || self.has_sendable_stream()
                    || self.pmtud.next_probe().is_some()))
    }

    pub(crate) fn send_deadline(&self, now: Instant) -> Option<Instant> {
        if !self.has_pending_output() {
            return None;
        }
        if self.pto_probe_allowance != 0 {
            return self.anti_amp_allows().then_some(now);
        }
        if !self.has_sendable_output() {
            return self.next_timer();
        }
        if !self.pending_datagrams.is_empty()
            && self.datagram_congestion_control == DatagramCongestionControl::Uncongested
        {
            return Some(now);
        }
        if !self.anti_amp_allows() || !self.cc.allows_send() {
            return self.next_timer();
        }
        Some(self.next_send_time().max(now))
    }

    fn wire_sent(&mut self, bytes: u64, ack_eliciting: bool, now: Instant) {
        self.cc.packet_sent(bytes, ack_eliciting);
        let srtt = self.rtt.smoothed_rtt.unwrap_or(INITIAL_RTT);
        self.pacer.packet_sent(bytes, now, self.cc.cwnd, srtt);
    }

    pub fn try_send_datagram(&mut self, data: Vec<u8>) -> Result<(), TrySendError<Vec<u8>>> {
        if self.state == State::Closed {
            return Err(TrySendError::Closed(data));
        }
        let Some(max) = self.max_datagram_payload() else {
            return Err(TrySendError::Unsupported(data));
        };
        if data.len() > max {
            return Err(TrySendError::TooLarge(data));
        }
        if self.pending_datagrams.len() >= self.pending_datagrams_capacity {
            return Err(TrySendError::Full(data));
        }
        self.pending_datagrams.push_back(data);
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
        let overhead = 1 + self.peer_cid.len() + PN_LEN as usize + 16;
        let by_pmtu = (MAX_DATAGRAM_SIZE as usize).saturating_sub(overhead);
        let by_pmtu_payload = by_pmtu.saturating_sub(1);
        Some(by_peer.min(by_pmtu_payload))
    }

    pub fn recv_datagram(&mut self) -> Option<Vec<u8>> {
        self.incoming_datagrams.pop_front()
    }

    pub fn is_handshaking(&self) -> bool {
        self.state == State::Handshaking
    }

    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }

    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    pub fn peer_transport_params(&self) -> Option<&transport_params::Params> {
        self.peer_transport_params.as_ref()
    }

    pub fn handshake_confirmed(&self) -> bool {
        self.handshake_confirmed
    }

    pub fn peer_address_validated(&self) -> bool {
        self.peer_address_validated
    }

    fn anti_amp_allows(&self) -> bool {
        self.peer_address_validated || self.anti_amp_remaining() != 0
    }

    fn anti_amp_remaining(&self) -> u64 {
        if self.peer_address_validated {
            return u64::MAX;
        }
        self.amplification_received
            .saturating_mul(3)
            .saturating_sub(self.amplification_sent)
    }

    fn emission_ceiling(&self, requested: usize) -> Option<usize> {
        let remaining = usize::try_from(self.anti_amp_remaining()).unwrap_or(usize::MAX);
        let ceiling = requested.min(remaining);
        (ceiling != 0).then_some(ceiling)
    }

    pub fn amplification_received(&self) -> u64 {
        self.amplification_received
    }

    pub fn cwnd(&self) -> u64 {
        self.cc.cwnd
    }
    pub fn bytes_in_flight(&self) -> u64 {
        self.cc.bytes_in_flight
    }
    pub fn ssthresh(&self) -> u64 {
        self.cc.ssthresh
    }

    pub fn close(&mut self, error_code: u64, reason: Vec<u8>) {
        if self.state != State::Closed && self.pending_close.is_none() {
            self.pending_close = Some(PendingClose {
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
        Some(Duration::from_millis(effective))
    }

    fn idle_deadline(&self) -> Option<Instant> {
        self.effective_idle_timeout()
            .map(|d| self.last_activity + d)
    }

    pub fn unacked_count(&self, epoch_ix: usize) -> usize {
        if epoch_ix == Epoch::Application as usize {
            self.packet_journals.count_epoch(Epoch::Application)
        } else {
            self.spaces[epoch_ix].sent.len()
        }
    }

    pub fn smoothed_rtt(&self) -> Option<Duration> {
        self.rtt.smoothed_rtt
    }
}
