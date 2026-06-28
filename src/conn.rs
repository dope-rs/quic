use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use shin::Event;
use shin::sig::SigningKey;
use subtle::ConstantTimeEq;

use crate::frame::Frame;
use crate::new_reno::{K_MAX_DATAGRAM_SIZE, NewReno};
use crate::packet::{HandshakeHeader, InitialHeader, QUIC_V1, ShortHeader};
use crate::packet_protection::PacketProtection;
use crate::pn_space::{AckedFrames, PnSpace, SentPacket};
use crate::qkdf::{InitialSecrets, PacketKeys};
use crate::rtt::RttTracker;
use crate::transport_params;
use crate::transport_params::TpError;

const MIN_INITIAL_LEN: usize = 1200;
const TAG_LEN: usize = 16;
const PN_LEN: u8 = 4;
const STREAM_FRAME_OVERHEAD: usize = 25;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnHandle(pub u32);

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
    Tls,
    UnexpectedEpoch,
    TransportParameterMismatch,
    TransportParameterDecode,
    PeerClosed,
    IdleTimeout,
    FlowControl,
    CryptoBufferExceeded,
}

impl From<TpError> for ConnError {
    fn from(_: TpError) -> Self {
        Self::TransportParameterDecode
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Epoch {
    Initial = 0,
    Handshake = 1,
    Application = 2,
}

/// A nameable [`shin::Clock`] for [`SideKind`] (a closure has no nameable type).
type TlsClock = fn() -> u64;

enum SideKind {
    Client(shin::client::Client<TlsClock>),
    Server(shin::server::Server<TlsClock, crate::early_data::ReplayGuard>),
}

const MAX_CRYPTO_BUFFERED: usize = 64 * 1024;

#[derive(Default)]
struct CryptoReasm {
    next: u64,
    buf: BTreeMap<u64, Vec<u8>>,
    pending: Vec<u8>,
}

impl CryptoReasm {
    fn buffered_bytes(&self) -> usize {
        self.pending
            .len()
            .saturating_add(self.buf.values().map(Vec::len).sum())
    }

    fn accept(&mut self, offset: u64, data: Vec<u8>) -> Result<Vec<Vec<u8>>, ConnError> {
        if !data.is_empty() && offset.saturating_add(data.len() as u64) > self.next {
            if self.buffered_bytes().saturating_add(data.len()) > MAX_CRYPTO_BUFFERED {
                return Err(ConnError::CryptoBufferExceeded);
            }
            self.buf.insert(offset, data);
        }
        while let Some(off) = self.buf.range(..=self.next).next_back().map(|(k, _)| *k) {
            let chunk = self.buf.remove(&off).expect("range key present");
            let end = off + chunk.len() as u64;
            if end <= self.next {
                continue;
            }
            let start = (self.next - off) as usize;
            self.pending.extend_from_slice(&chunk[start..]);
            self.next = end;
        }
        let mut out = Vec::new();
        loop {
            if self.pending.len() < 4 {
                break;
            }
            let len =
                u32::from_be_bytes([0, self.pending[1], self.pending[2], self.pending[3]]) as usize;
            let total = 4 + len;
            if total > MAX_CRYPTO_BUFFERED {
                return Err(ConnError::CryptoBufferExceeded);
            }
            if self.pending.len() < total {
                break;
            }
            out.push(self.pending.drain(..total).collect());
        }
        if self.pending.len() > MAX_CRYPTO_BUFFERED {
            return Err(ConnError::CryptoBufferExceeded);
        }
        Ok(out)
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
    /// Server-only: 0-RTT was accepted, so shin's transcript expects an
    /// `EndOfEarlyData` that QUIC never sends on the wire (RFC 9001 §8.3). When
    /// set, we synthesize one before the client's Handshake flight.
    pending_synth_eod: bool,

    spaces: [PnSpace; 3],
    rtt: RttTracker,
    pto_count: u32,
    loss_timer: Option<Instant>,

    scratch_frames: Vec<u8>,
    scratch_pending: Vec<u64>,

    pending_crypto_initial: Vec<u8>,
    pending_crypto_handshake: Vec<u8>,
    pending_datagrams: VecDeque<Vec<u8>>,
    incoming_datagrams: VecDeque<Vec<u8>>,
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
    pacer: crate::pacer::Pacer,
    pmtud: crate::pmtud::Pmtud,
    pmtud_probe_pn: Option<u64>,
    datagram_cc_mode: DatagramCcMode,
    pending_datagrams_cap: usize,
    cid_prefix: Option<u8>,
    stateless_reset_secret: Option<[u8; 32]>,
    stateless_reset_received: bool,
    pending_path_responses: Vec<[u8; 8]>,
    pending_path_challenges: Vec<[u8; 8]>,
    outstanding_path_challenges: Vec<[u8; 8]>,
    validated_path_tokens: Vec<[u8; 8]>,

    local_cids: BTreeMap<u64, Vec<u8>>,
    peer_cids: BTreeMap<u64, (Vec<u8>, [u8; 16])>,
    next_local_cid_seq: u64,
    new_cid_pending: Vec<(u64, Vec<u8>, [u8; 16])>,
    retire_pending: Vec<u64>,
    cids_to_register: Vec<Vec<u8>>,
    auto_issued: bool,

    retry_token: Vec<u8>,
    retry_processed: bool,

    streams_recv: BTreeMap<u64, crate::stream::RecvStream>,
    streams_send: BTreeMap<u64, crate::stream::SendStream>,
    stream_events: VecDeque<StreamEvent>,
    next_local_bidi_stream: u64,
    local_max_streams_bidi: u64,
    initial_max_streams_bidi: u64,
    peer_bidi_closed: u64,
    max_streams_bidi_pending: bool,
    next_local_uni_stream: u64,
    opened_local_bidi_streams: u64,
    opened_local_uni_streams: u64,

    peer_max_data: u64,
    peer_total_sent: u64,
    peer_max_stream_data: BTreeMap<u64, u64>,
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
    received_tickets: Vec<SessionTicket>,
    pending_resumption_psk: Option<[u8; 32]>,
    recv_crypto: [CryptoReasm; 3],
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
pub enum DatagramError {
    TooLarge,
    PeerDoesNotSupport,
    Closed,
    QueueFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamError {
    NotEstablished,
    PeerLimit,
    IdOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    Data { stream_id: u64 },
    Finished { stream_id: u64 },
    Reset { stream_id: u64, error_code: u64 },
    Stopped { stream_id: u64, error_code: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DatagramCcMode {
    #[default]
    Standard,
    Uncongested,
}

#[derive(Debug, Clone)]
pub struct ConnConfig {
    pub transport_params: transport_params::Params,
    pub datagram_cc_mode: DatagramCcMode,
    pub pending_datagrams_cap: usize,
    pub cid_prefix: Option<u8>,
    pub stateless_reset_secret: Option<[u8; 32]>,
    pub require_address_validation: bool,
    pub retry_token_secret: Option<[u8; 32]>,
    pub ticket_secret: Option<[u8; 32]>,
    pub resumption: Option<shin::client::Resumption>,
    pub enable_early_data: bool,
    pub accept_early_data: bool,
    pub resumption_peer_tp: Option<transport_params::Params>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub server_cert_chain: Option<Vec<Vec<u8>>>,
    pub early_data_store: Option<crate::early_data::SharedReplayStore>,
}

impl Default for ConnConfig {
    fn default() -> Self {
        Self {
            transport_params: transport_params::Params::default(),
            datagram_cc_mode: DatagramCcMode::Standard,
            pending_datagrams_cap: 1024,
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
            early_data_store: None,
        }
    }
}

impl From<transport_params::Params> for ConnConfig {
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
    ) -> Vec<u8> {
        let mut tp = user_tp;
        tp.initial_source_connection_id = Some(local_cid.to_vec());
        if !is_client {
            tp.original_destination_connection_id = Some(original_dcid.to_vec());
            if let Some(rscid) = retry_scid {
                tp.retry_source_connection_id = Some(rscid.to_vec());
            }
        }
        let mut buf = Vec::new();
        tp.encode(&mut buf);
        buf
    }

    pub fn new_client(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        server_pubkey: [u8; 32],
        config: ConnConfig,
    ) -> Self {
        let tp_original_dcid = initial_dcid.clone();
        let mut conn = Self::new_with(
            initial_dcid,
            local_cid,
            tp_original_dcid,
            None,
            config,
            SideSetup::Client { server_pubkey },
        );
        conn.start_client_handshake();
        conn
    }

    pub fn new_server(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        peer_cid: Vec<u8>,
        signing_key: SigningKey,
        config: ConnConfig,
    ) -> Self {
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
        config: ConnConfig,
    ) -> Self {
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
        config: ConnConfig,
        side_setup: SideSetup,
    ) -> Self {
        let ConnConfig {
            transport_params: mut user_tp,
            datagram_cc_mode,
            pending_datagrams_cap,
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
            early_data_store,
        } = config;
        let secrets = InitialSecrets::from_dcid(&initial_dcid);
        let local_idle = Duration::from_millis(user_tp.max_idle_timeout_ms);
        let local_max_data = user_tp.initial_max_data;
        let local_initial_max_stream_data_bidi_local = user_tp.initial_max_stream_data_bidi_local;
        let local_initial_max_stream_data_bidi_remote = user_tp.initial_max_stream_data_bidi_remote;
        let local_initial_max_stream_data_uni = user_tp.initial_max_stream_data_uni;
        let local_initial_max_streams_bidi = user_tp.initial_max_streams_bidi;

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
                );
                let cfg = shin::client::Config {
                    verifier: shin::client::Verifier::RawPublicKey {
                        expected_pubkey: server_pubkey,
                    },
                    transport_params: tp_bytes,
                    alpn_protocols,
                    resumption,
                    enable_early_data,
                };
                (
                    SideKind::Client(shin::client::Client::new(
                        cfg,
                        crate::time::now_ms as TlsClock,
                    )),
                    true,
                    initial_dcid.clone(),
                    None,
                    true,
                    PacketProtection::aes_128(&PacketKeys::aes_128(&secrets.client)),
                    PacketProtection::aes_128(&PacketKeys::aes_128(&secrets.server)),
                )
            }
            SideSetup::Server {
                peer_cid,
                signing_key,
            } => {
                user_tp.stateless_reset_token = stateless_reset_secret
                    .map(|s| crate::secrets::StatelessResetSecret(s).token_for(&local_cid));
                let tp_bytes = Self::local_tp_bytes(
                    false,
                    &local_cid,
                    &tp_original_dcid,
                    retry_scid.as_deref(),
                    user_tp,
                );
                let cfg = shin::server::Config {
                    source: match server_cert_chain {
                        Some(chain_der) => shin::server::CertSource::X509 {
                            chain_der,
                            signing_key: *signing_key,
                        },
                        None => shin::server::CertSource::RawPublicKey {
                            signing_key: *signing_key,
                        },
                    },
                    transport_params: tp_bytes,
                    alpn_protocols,
                    ticket_keys: ticket_secret.map(shin::ticket::TicketKeys::single),
                    accept_early_data,
                };
                // Attached unconditionally to keep `Server`'s type uniform; it is
                // only consulted once `accept_early_data` is set.
                let store = early_data_store.unwrap_or_else(crate::early_data::shared_replay_store);
                let server = shin::server::Server::with_early_data_guard(
                    cfg,
                    crate::time::now_ms as TlsClock,
                    crate::early_data::ReplayGuard::new(store),
                );
                (
                    SideKind::Server(server),
                    false,
                    peer_cid.clone(),
                    Some(peer_cid),
                    false,
                    PacketProtection::aes_128(&PacketKeys::aes_128(&secrets.server)),
                    PacketProtection::aes_128(&PacketKeys::aes_128(&secrets.client)),
                )
            }
        };

        let mut local_cids = BTreeMap::new();
        local_cids.insert(0, local_cid.clone());
        let mut peer_cids = BTreeMap::new();
        peer_cids.insert(0, (peer_cid.clone(), [0u8; 16]));

        let mut conn = Self {
            side,
            is_client,
            scratch_frames: Vec::with_capacity(K_MAX_DATAGRAM_SIZE as usize),
            scratch_pending: Vec::new(),
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
            spaces: Default::default(),
            rtt: RttTracker::default(),
            pto_count: 0,
            loss_timer: None,
            pending_crypto_initial: Vec::new(),
            pending_crypto_handshake: Vec::new(),
            pending_datagrams: VecDeque::new(),
            incoming_datagrams: VecDeque::new(),
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
            pacer: crate::pacer::Pacer::new(Instant::now()),
            pmtud: crate::pmtud::Pmtud::default(),
            pmtud_probe_pn: None,
            datagram_cc_mode,
            pending_datagrams_cap,
            cid_prefix,
            stateless_reset_secret,
            stateless_reset_received: false,
            pending_path_responses: Vec::new(),
            pending_path_challenges: Vec::new(),
            outstanding_path_challenges: Vec::new(),
            validated_path_tokens: Vec::new(),
            local_cids,
            peer_cids,
            next_local_cid_seq: 1,
            new_cid_pending: Vec::new(),
            retire_pending: Vec::new(),
            cids_to_register: Vec::new(),
            auto_issued: false,
            retry_token: Vec::new(),
            retry_processed: false,
            streams_recv: BTreeMap::new(),
            streams_send: BTreeMap::new(),
            stream_events: VecDeque::new(),
            next_local_bidi_stream: if is_client { 0 } else { 1 },
            local_max_streams_bidi: local_initial_max_streams_bidi,
            initial_max_streams_bidi: local_initial_max_streams_bidi,
            peer_bidi_closed: 0,
            max_streams_bidi_pending: false,
            next_local_uni_stream: if is_client { 2 } else { 3 },
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
            received_tickets: Vec::new(),
            pending_resumption_psk: None,
            recv_crypto: core::array::from_fn(|_| CryptoReasm::default()),
        };
        if let Some(tp) = resumption_peer_tp {
            conn.peer_max_data = tp.initial_max_data;
            conn.peer_transport_params = Some(tp);
        }
        conn
    }

    fn start_client_handshake(&mut self) {
        if let SideKind::Client(c) = &mut self.side {
            let evs = c.start().expect("shin client start");
            self.absorb_shin_events(evs);
        }
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
                    let p = crate::packet::ZeroRttHeader::decode_pre_hp(rest)
                        .map_err(|_| ConnError::HeaderDecode)?;
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
        let prefix = crate::packet::ZeroRttHeader::decode_pre_hp(wire)
            .map_err(|_| ConnError::HeaderDecode)?;
        let mut buf = wire.to_vec();
        let body = zr
            .decrypt_long(&mut buf, prefix.pn_offset)
            .map_err(|_| ConnError::PacketDecrypt)?;
        let pn = Self::decode_pn(&buf, prefix.pn_offset);
        self.process_packet_body(Epoch::Application, pn, &body, now)
    }

    fn recv_retry(&mut self, wire: &[u8]) -> Result<(), ConnError> {
        if !self.is_client || self.retry_processed {
            return Ok(());
        }
        if self.handshake_r.is_some() || self.peer_first_scid.is_some() {
            return Ok(());
        }
        let pkt = crate::packet::RetryPacket::decode(wire).map_err(|_| ConnError::HeaderDecode)?;
        if !pkt.verify_integrity(&self.original_dcid) {
            return Ok(());
        }
        let ch_bytes: Vec<u8> = {
            let space = &self.spaces[Epoch::Initial as usize];
            let mut acc = Vec::new();
            for (_off, (data, _pn)) in space.crypto_inflight.iter() {
                acc.extend_from_slice(data);
            }
            acc
        };
        let new_secrets = InitialSecrets::from_dcid(&pkt.scid);
        self.discard_initial_keys();
        self.initial_w = Some(PacketProtection::aes_128(&PacketKeys::aes_128(
            &new_secrets.client,
        )));
        self.initial_r = Some(PacketProtection::aes_128(&PacketKeys::aes_128(
            &new_secrets.server,
        )));
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
        for (_seq, (_cid, token)) in self.peer_cids.iter() {
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
        if self.state == State::Established {
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

    pub fn stream_send(&mut self, stream_id: u64, data: &[u8]) {
        self.streams_send.entry(stream_id).or_default().write(data);
    }

    pub fn stream_send_fin(&mut self, stream_id: u64) {
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
    }

    pub fn stream_reset(&mut self, stream_id: u64, error_code: u64) {
        let s = self.streams_send.entry(stream_id).or_default();
        let final_size = s.next_offset();
        s.mark_reset_sent();
        self.pending_resets
            .insert(stream_id, (error_code, final_size));
    }

    pub fn stream_stop_sending(&mut self, stream_id: u64, error_code: u64) {
        self.pending_stop_sending.insert(stream_id, error_code);
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
        self.stream_events.pop_front()
    }

    pub fn has_stream_events(&self) -> bool {
        !self.stream_events.is_empty()
    }

    fn open_local_stream(&mut self, uni: bool) -> Result<u64, StreamError> {
        if self.state != State::Established {
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
        let mut buf = wire.to_vec();
        let body = initial_r
            .decrypt_long(&mut buf, prefix.pn_offset)
            .map_err(|_| ConnError::PacketDecrypt)?;
        let pn = Self::decode_pn(&buf, prefix.pn_offset);
        self.process_packet_body(Epoch::Initial, pn, &body, now)
    }

    fn recv_handshake(&mut self, wire: &[u8], now: Instant) -> Result<(), ConnError> {
        let Some(hr) = self.handshake_r.as_ref() else {
            return Ok(());
        };
        let prefix = HandshakeHeader::decode_pre_hp(wire).map_err(|_| ConnError::HeaderDecode)?;
        let mut buf = wire.to_vec();
        let body = hr
            .decrypt_long(&mut buf, prefix.pn_offset)
            .map_err(|_| ConnError::PacketDecrypt)?;
        self.peer_address_validated = true;
        let pn = Self::decode_pn(&buf, prefix.pn_offset);
        self.process_packet_body(Epoch::Handshake, pn, &body, now)
    }

    fn recv_one_rtt(&mut self, wire: &[u8], now: Instant) -> Result<(), ConnError> {
        let Some(ar) = self.app_r.as_ref() else {
            return Ok(());
        };
        let pn_offset = ShortHeader::pn_offset_for(self.local_cid.len());
        let mut buf = wire.to_vec();
        let body = ar
            .decrypt_short(&mut buf, pn_offset)
            .map_err(|_| ConnError::PacketDecrypt)?;
        let pn = Self::decode_pn(&buf, pn_offset);
        self.process_packet_body(Epoch::Application, pn, &body, now)
    }

    fn process_packet_body(
        &mut self,
        epoch: Epoch,
        pn: u64,
        body: &[u8],
        now: Instant,
    ) -> Result<(), ConnError> {
        let frames = Frame::decode_all(body).map_err(|_| ConnError::FrameDecode)?;
        let mut ack_eliciting = false;
        for f in &frames {
            if !matches!(
                f,
                Frame::Ack { .. } | Frame::Padding | Frame::ConnectionClose { .. }
            ) {
                ack_eliciting = true;
                break;
            }
        }
        self.spaces[epoch as usize].record_received(pn, ack_eliciting, now);
        self.last_activity = now;

        let shin_epoch = match epoch {
            Epoch::Initial => shin::Epoch::Plaintext,
            Epoch::Handshake => shin::Epoch::Handshake,
            Epoch::Application => shin::Epoch::Application,
        };
        for f in frames {
            match f {
                Frame::Crypto { offset, data } => {
                    let msgs = self.recv_crypto[epoch as usize].accept(offset, data)?;
                    for msg in msgs {
                        if self.pending_synth_eod && epoch == Epoch::Handshake {
                            self.pending_synth_eod = false;
                            // EndOfEarlyData: handshake type 5, empty body.
                            let evs =
                                self.feed_shin(shin::Epoch::EarlyData, &[0x05, 0x00, 0x00, 0x00])?;
                            self.absorb_shin_events(evs);
                        }
                        let evs = self.feed_shin(shin_epoch, &msg)?;
                        self.absorb_shin_events(evs);
                    }
                }
                Frame::Ack {
                    largest,
                    delay,
                    first_range,
                    additional_ranges,
                } => {
                    let acked = self.spaces[epoch as usize].process_ack(
                        largest,
                        first_range,
                        &additional_ranges,
                    );
                    self.on_acked(epoch, largest, delay, acked, now);
                }
                Frame::Datagram { data, .. } if epoch == Epoch::Application => {
                    self.incoming_datagrams.push_back(data);
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
                    self.peer_cids
                        .insert(sequence_number, (connection_id, stateless_reset_token));
                    let to_retire: Vec<u64> = self
                        .peer_cids
                        .keys()
                        .copied()
                        .filter(|&s| s < retire_prior_to)
                        .collect();
                    for s in to_retire {
                        self.peer_cids.remove(&s);
                        self.retire_pending.push(s);
                    }
                }
                Frame::RetireConnectionId { sequence_number } if epoch == Epoch::Application => {
                    self.local_cids.remove(&sequence_number);
                }
                Frame::PathChallenge { data } if epoch == Epoch::Application => {
                    self.pending_path_responses.push(data);
                }
                Frame::Stream {
                    stream_id,
                    offset,
                    fin,
                    data,
                    ..
                } if epoch == Epoch::Application => {
                    let new_end = offset.saturating_add(data.len() as u64);
                    let stream_limit = self.local_stream_recv_limit(stream_id);
                    if new_end > stream_limit {
                        return Err(ConnError::FlowControl);
                    }
                    let rs = self.streams_recv.entry(stream_id).or_default();
                    let prev_high = rs.highest_offset();
                    if new_end > prev_high {
                        let delta = new_end - prev_high;
                        let projected = self.conn_recv_total.saturating_add(delta);
                        if projected > self.local_max_data {
                            return Err(ConnError::FlowControl);
                        }
                        self.conn_recv_total = projected;
                    }
                    let rs = self.streams_recv.entry(stream_id).or_default();
                    rs.on_chunk(offset, &data, fin);
                    if !data.is_empty() {
                        self.stream_events
                            .push_back(StreamEvent::Data { stream_id });
                    }
                    if fin {
                        self.stream_events
                            .push_back(StreamEvent::Finished { stream_id });
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
                    let entry = self.peer_max_stream_data.entry(stream_id).or_insert(0);
                    if maximum_stream_data > *entry {
                        *entry = maximum_stream_data;
                        self.blocked_stream_emitted.remove(&stream_id);
                    }
                }
                Frame::DataBlocked { .. } | Frame::StreamDataBlocked { .. }
                    if epoch == Epoch::Application => {}
                Frame::ResetStream {
                    stream_id,
                    error_code,
                    final_size,
                } if epoch == Epoch::Application => {
                    if final_size > self.local_stream_recv_limit(stream_id) {
                        return Err(ConnError::FlowControl);
                    }
                    let rs = self.streams_recv.entry(stream_id).or_default();
                    let prev_high = rs.highest_offset();
                    if final_size > prev_high {
                        let delta = final_size - prev_high;
                        let projected = self.conn_recv_total.saturating_add(delta);
                        if projected > self.local_max_data {
                            return Err(ConnError::FlowControl);
                        }
                        self.conn_recv_total = projected;
                    }
                    let rs = self.streams_recv.entry(stream_id).or_default();
                    rs.on_reset(error_code, final_size);
                    self.stream_events.push_back(StreamEvent::Reset {
                        stream_id,
                        error_code,
                    });
                }
                Frame::StopSending {
                    stream_id,
                    error_code,
                } if epoch == Epoch::Application => {
                    let s = self.streams_send.entry(stream_id).or_default();
                    s.on_stop_sending(error_code);
                    self.stream_events.push_back(StreamEvent::Stopped {
                        stream_id,
                        error_code,
                    });
                    let final_size = s.next_offset();
                    if !s.reset_sent() {
                        s.mark_reset_sent();
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
                        self.validated_path_tokens.push(data);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn discard_initial_keys(&mut self) {
        let leaked = self.spaces[Epoch::Initial as usize].in_flight_bytes();
        self.cc.discard(leaked);
        self.initial_w = None;
        self.initial_r = None;
        self.spaces[Epoch::Initial as usize] = PnSpace::default();
        self.pending_crypto_initial.clear();
    }

    fn discard_handshake_keys(&mut self) {
        let leaked = self.spaces[Epoch::Handshake as usize].in_flight_bytes();
        self.cc.discard(leaked);
        self.handshake_w = None;
        self.handshake_r = None;
        self.spaces[Epoch::Handshake as usize] = PnSpace::default();
        self.pending_crypto_handshake.clear();
    }

    fn on_acked(
        &mut self,
        epoch: Epoch,
        largest_in_ack: u64,
        ack_delay_microseconds: u64,
        acked: Vec<SentPacket>,
        now: Instant,
    ) {
        if let Some(p) = acked.iter().find(|p| p.pn == largest_in_ack) {
            let sample = now.saturating_duration_since(p.sent_time);
            let ack_delay = if matches!(epoch, Epoch::Application) {
                Duration::from_micros(ack_delay_microseconds)
            } else {
                Duration::ZERO
            };
            self.rtt.update(sample, ack_delay);
            self.pto_count = 0;
        }
        for p in &acked {
            self.cc.on_packet_acked(p.bytes_sent as u64, p.in_flight);
            if matches!(epoch, Epoch::Application) && Some(p.pn) == self.pmtud_probe_pn {
                self.pmtud.on_probe_acked();
                self.pmtud_probe_pn = None;
            }
            for sf in &p.frames.stream {
                if let Some(s) = self.streams_send.get_mut(&sf.stream_id) {
                    s.ack(sf.offset, sf.len);
                    if sf.fin {
                        s.mark_fin_acked();
                    }
                }
            }
        }
        let app = Epoch::Application as usize;
        let sids: Vec<u64> = self.streams_send.keys().copied().collect();
        for sid in sids {
            if !self
                .streams_send
                .get(&sid)
                .is_some_and(|s| s.is_fully_acked())
            {
                continue;
            }
            let no_inflight = !self.spaces[app]
                .stream_inflight
                .keys()
                .any(|(s, _)| *s == sid);
            let no_retx = !self.spaces[app]
                .stream_retransmit
                .iter()
                .any(|(s, _, _, _)| *s == sid);
            if no_inflight && no_retx {
                self.streams_send.remove(&sid);
                if self.streams_recv.get(&sid).is_none_or(|r| r.is_eof()) {
                    self.streams_recv.remove(&sid);
                }
            }
        }
        self.run_rack(now);
        self.update_loss_timer();
    }

    fn run_rack(&mut self, now: Instant) {
        let loss_delay = self.rtt.loss_delay();
        for (idx, space) in self.spaces.iter_mut().enumerate() {
            let (lost, _) = space.detect_lost(loss_delay, now);
            if lost.is_empty() {
                continue;
            }
            let lost_bytes: u64 = lost.iter().map(|p| p.bytes_sent as u64).sum();
            let latest = lost.iter().map(|p| p.sent_time).max().expect("non-empty");
            self.cc.on_packets_lost(lost_bytes, latest);
            if idx == Epoch::Application as usize
                && let Some(probe_pn) = self.pmtud_probe_pn
                && lost.iter().any(|p| p.pn == probe_pn)
            {
                self.pmtud.on_probe_lost();
                self.pmtud_probe_pn = None;
            }
        }
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
            let lo = largest_acked.saturating_sub(crate::rtt::K_PACKET_THRESHOLD - 1);
            for (&_pn, p) in space.sent.range(lo..=largest_acked) {
                let when = p.sent_time + loss_delay;
                rack_candidate = Some(match rack_candidate {
                    Some(prev) if prev < when => prev,
                    _ => when,
                });
            }
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
        for space in &mut self.spaces {
            let (lost, _) = space.detect_lost(loss_delay, now);
            if !lost.is_empty() {
                let lost_bytes: u64 = lost.iter().map(|p| p.bytes_sent as u64).sum();
                let latest = lost.iter().map(|p| p.sent_time).max().expect("non-empty");
                self.cc.on_packets_lost(lost_bytes, latest);
                total_lost += lost.len();
            }
        }

        if total_lost == 0 {
            for space in &mut self.spaces {
                if space.ack_eliciting_in_flight > 0 {
                    space.requeue_inflight_crypto();
                    space.requeue_inflight_stream();
                    for p in space.sent.values_mut() {
                        p.in_flight = false;
                    }
                    space.ack_eliciting_in_flight = 0;
                    break;
                }
            }
            self.pto_count = self.pto_count.saturating_add(1);
        }
        self.update_loss_timer();
    }

    fn feed_shin(&mut self, epoch: shin::Epoch, data: &[u8]) -> Result<Vec<Event>, ConnError> {
        match &mut self.side {
            SideKind::Client(c) => c.read(epoch, data).map_err(|_| ConnError::Tls),
            SideKind::Server(s) => s.read(epoch, data).map_err(|_| ConnError::Tls),
        }
    }

    fn absorb_shin_events(&mut self, events: Vec<Event>) {
        for e in events {
            match e {
                Event::Send { epoch, data } => match epoch {
                    shin::Epoch::Plaintext => self.pending_crypto_initial.extend_from_slice(&data),
                    shin::Epoch::Handshake => {
                        self.pending_crypto_handshake.extend_from_slice(&data)
                    }
                    shin::Epoch::Application => self.pending_crypto_app.extend_from_slice(&data),
                    // QUIC carries no CRYPTO at the 0-RTT epoch.
                    shin::Epoch::EarlyData => {}
                },
                Event::KeysReady {
                    epoch,
                    read_secret,
                    write_secret,
                } => {
                    let r = PacketProtection::aes_128(&PacketKeys::aes_128(read_secret.as_slice()));
                    let w =
                        PacketProtection::aes_128(&PacketKeys::aes_128(write_secret.as_slice()));
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
                        // 0-RTT keys arrive via `ZeroRttKeysReady`, never here.
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
                    let keys = PacketProtection::aes_128(&PacketKeys::aes_128(secret.as_slice()));
                    if self.is_client {
                        self.zero_rtt_w = Some(keys);
                    } else {
                        self.zero_rtt_r = Some(keys);
                        self.pending_synth_eod = true;
                    }
                }
                Event::EarlyDataAccepted => {}
                // Rejected: drop write keys; the data is resent at 1-RTT.
                Event::EarlyDataRejected => {
                    self.zero_rtt_w = None;
                }
                Event::NewSessionTicket {
                    ticket_lifetime,
                    ticket_age_add,
                    ticket_nonce,
                    ticket,
                    // Per-ticket 0-RTT cap not yet enforced.
                    max_early_data: _,
                } => {
                    let psk = self.pending_resumption_psk.take().unwrap_or([0u8; 32]);
                    self.received_tickets.push(SessionTicket {
                        ticket_lifetime,
                        ticket_age_add,
                        ticket_nonce,
                        ticket,
                        psk,
                    });
                }
                Event::ResumptionSecret { psk } => {
                    self.pending_resumption_psk = Some(psk);
                }
            }
        }
    }

    pub fn take_session_tickets(&mut self) -> Vec<SessionTicket> {
        std::mem::take(&mut self.received_tickets)
    }

    fn finalize_peer_tp(&mut self) -> Result<(), ConnError> {
        let raw = self
            .peer_transport_params_raw
            .as_ref()
            .ok_or(ConnError::TransportParameterMismatch)?;
        let peer_tp = transport_params::Params::decode(raw)?;

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
        self.peer_max_stream_data.insert(id, limit);
    }

    pub fn send_packets(&mut self, now: Instant) -> Vec<Vec<u8>> {
        if self.state == State::Closed {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut sent_handshake_packet = false;
        let mut sent_handshake_done = false;

        if self.initial_w.is_some() {
            loop {
                if !self.allows_emit_for(PacketCargo::CryptoOrAck, now) {
                    break;
                }
                let crypto = self.pop_initial_crypto();
                let has_ack = self.spaces[Epoch::Initial as usize].ack_pending;
                if crypto.is_none() && !has_ack {
                    break;
                }
                let wire = self.build_initial(crypto, now);
                self.amplification_sent = self.amplification_sent.saturating_add(wire.len() as u64);
                out.push(wire);
                self.sent_initial = true;
            }
        }

        if self.zero_rtt_w.is_some()
            && self.app_w.is_none()
            && let Some(wire) = self.build_zero_rtt(now)
        {
            self.amplification_sent = self.amplification_sent.saturating_add(wire.len() as u64);
            out.push(wire);
        }

        if self.handshake_w.is_some() {
            loop {
                if !self.allows_emit_for(PacketCargo::CryptoOrAck, now) {
                    break;
                }
                let crypto = self.pop_handshake_crypto();
                let has_ack = self.spaces[Epoch::Handshake as usize].ack_pending;
                if crypto.is_none() && !has_ack {
                    break;
                }
                let wire = self.build_handshake(crypto, now);
                self.amplification_sent = self.amplification_sent.saturating_add(wire.len() as u64);
                out.push(wire);
                sent_handshake_packet = true;
            }
        }

        if self.app_w.is_some() {
            if let Some(close) = self.pending_close.take() {
                let wire = self.build_one_rtt_close(close, now);
                self.amplification_sent = self.amplification_sent.saturating_add(wire.len() as u64);
                out.push(wire);
                self.state = State::Closed;
                self.last_activity = now;
                return out;
            }

            // Snapshot sendable streams once; build_one_rtt drains it per packet,
            // avoiding an O(streams) rescan for every packet built.
            {
                let mut pend = std::mem::take(&mut self.scratch_pending);
                pend.clear();
                for (&id, s) in &self.streams_send {
                    if s.has_pending() {
                        pend.push(id);
                    }
                }
                self.scratch_pending = pend;
            }

            for _ in 0..4096u32 {
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
                    || !self.pending_crypto_app.is_empty();

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
                let wire = self.build_one_rtt(None, want_handshake_done, now);
                self.amplification_sent = self.amplification_sent.saturating_add(wire.len() as u64);
                out.push(wire);
                if want_handshake_done {
                    self.handshake_done_pending = false;
                    sent_handshake_done = true;
                }
                if !one_shot && self.cc.bytes_in_flight == before {
                    break;
                }
            }
            while let Some(dg) = self.pending_datagrams.pop_front() {
                if !self.allows_emit_for(PacketCargo::DatagramOnly, now) {
                    self.pending_datagrams.push_front(dg);
                    break;
                }
                let wire = self.build_one_rtt(Some(dg), false, now);
                self.amplification_sent = self.amplification_sent.saturating_add(wire.len() as u64);
                out.push(wire);
            }
            if let Some(probe_size) = self.pmtud.next_probe()
                && self.allows_emit_for(PacketCargo::CryptoOrAck, now)
            {
                let wire = self.build_one_rtt_probe(probe_size, now);
                self.amplification_sent = self.amplification_sent.saturating_add(wire.len() as u64);
                out.push(wire);
            }
        }

        if sent_handshake_packet && self.initial_w.is_some() {
            self.discard_initial_keys();
        }
        if sent_handshake_done && !self.is_client {
            self.discard_handshake_keys();
        }

        if !out.is_empty() {
            self.last_activity = now;
            self.update_loss_timer();
        }
        out
    }

    /// Resets application send state (lifts cc/flow limits, clears bookkeeping)
    /// so `send_packets` can be driven in a tight loop with no acking peer.
    #[cfg(feature = "bench")]
    pub fn bench_prepare_blast(&mut self) {
        self.cc.cwnd = u64::MAX / 4;
        self.cc.bytes_in_flight = 0;
        self.peer_max_data = u64::MAX / 4;
        self.peer_total_sent = 0;
        self.pacer = crate::pacer::Pacer::new(Instant::now());
        let sp = &mut self.spaces[Epoch::Application as usize];
        sp.sent.clear();
        sp.stream_inflight.clear();
        sp.stream_retransmit.clear();
        sp.ack_pending = false;
        self.streams_send.clear();
    }

    fn pop_initial_crypto(&mut self) -> Option<(u64, Vec<u8>)> {
        let space = &mut self.spaces[Epoch::Initial as usize];
        if let Some(rt) = space.crypto_retransmit.pop() {
            return Some(rt);
        }
        if self.pending_crypto_initial.is_empty() {
            return None;
        }
        let data = std::mem::take(&mut self.pending_crypto_initial);
        let offset = space.crypto_next_offset;
        space.crypto_next_offset += data.len() as u64;
        Some((offset, data))
    }

    fn pop_handshake_crypto(&mut self) -> Option<(u64, Vec<u8>)> {
        let space = &mut self.spaces[Epoch::Handshake as usize];
        if let Some(rt) = space.crypto_retransmit.pop() {
            return Some(rt);
        }
        if self.pending_crypto_handshake.is_empty() {
            return None;
        }
        let data = std::mem::take(&mut self.pending_crypto_handshake);
        let offset = space.crypto_next_offset;
        space.crypto_next_offset += data.len() as u64;
        Some((offset, data))
    }

    fn drain_ack_frame(&mut self, epoch: Epoch) -> Option<Frame> {
        let space = &mut self.spaces[epoch as usize];
        if !space.ack_pending {
            return None;
        }
        let (largest, first_range, additional_ranges) = space.build_ack_ranges()?;
        space.ack_pending = false;
        Some(Frame::Ack {
            largest,
            delay: 0,
            first_range,
            additional_ranges,
        })
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
            .unwrap_or(crate::transport_params::DEFAULT_ACTIVE_CONNECTION_ID_LIMIT);
        let to_issue = limit.saturating_sub(self.local_cids.len() as u64) as usize;
        for _ in 0..to_issue.min(8) {
            let seq = self.next_local_cid_seq;
            self.next_local_cid_seq += 1;
            let cid = self.derive_cid_for_seq(seq);
            let srt = self
                .stateless_reset_secret
                .map(|s| crate::secrets::StatelessResetSecret(s).token_for(&cid))
                .unwrap_or([0u8; 16]);
            self.local_cids.insert(seq, cid.clone());
            self.cids_to_register.push(cid.clone());
            self.new_cid_pending.push((seq, cid, srt));
        }
    }

    pub fn take_cids_to_register(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.cids_to_register)
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

    fn build_initial(&mut self, crypto: Option<(u64, Vec<u8>)>, now: Instant) -> Vec<u8> {
        let pn = self.spaces[Epoch::Initial as usize].next_pn;
        self.spaces[Epoch::Initial as usize].next_pn += 1;

        let mut frames = Vec::with_capacity(crypto.as_ref().map_or(0, |(_, d)| d.len()) + 16);
        if let Some(ack) = self.drain_ack_frame(Epoch::Initial) {
            ack.encode(&mut frames);
        }
        let mut crypto_record = None;
        if let Some((offset, data)) = crypto {
            crypto_record = Some((offset, data.len()));
            self.spaces[Epoch::Initial as usize]
                .crypto_inflight
                .insert(offset, (data.clone(), pn));
            Frame::Crypto { offset, data }.encode(&mut frames);
        }

        let mut payload = frames;
        if self.is_client && !self.sent_initial {
            let token_len = self.retry_token.len();
            let token_varint_len = if token_len < 64 { 1 } else { 2 };
            let header_estimate = 1
                + 4
                + 1
                + self.peer_cid.len()
                + 1
                + self.local_cid.len()
                + token_varint_len
                + token_len
                + 2;
            let needed =
                MIN_INITIAL_LEN.saturating_sub(header_estimate + PN_LEN as usize + TAG_LEN);
            if payload.len() < needed {
                payload.resize(needed, 0);
            }
        }
        let body_len_after_pn = payload.len() + TAG_LEN;
        let h = InitialHeader {
            version: QUIC_V1,
            dcid: self.peer_cid.clone(),
            scid: self.local_cid.clone(),
            token: self.retry_token.clone(),
            packet_number: pn,
            pn_len: PN_LEN,
        };
        let (hdr, pn_off) = h.encode_with_pn(body_len_after_pn);
        let wire = self
            .initial_w
            .as_ref()
            .expect("Initial keys present at build_initial")
            .encrypt_long(&hdr, &payload, pn, pn_off, PN_LEN as usize);

        let ack_eliciting = crypto_record.is_some();
        self.on_wire_sent(wire.len() as u64, ack_eliciting, now);
        self.spaces[Epoch::Initial as usize].record_sent(SentPacket {
            pn,
            sent_time: now,
            ack_eliciting,
            in_flight: true,
            frames: AckedFrames {
                crypto: crypto_record,
                stream: Vec::new(),
            },
            bytes_sent: wire.len(),
        });
        wire
    }

    fn build_handshake(&mut self, crypto: Option<(u64, Vec<u8>)>, now: Instant) -> Vec<u8> {
        let pn = self.spaces[Epoch::Handshake as usize].next_pn;
        self.spaces[Epoch::Handshake as usize].next_pn += 1;

        let mut frames = Vec::with_capacity(crypto.as_ref().map_or(0, |(_, d)| d.len()) + 16);
        if let Some(ack) = self.drain_ack_frame(Epoch::Handshake) {
            ack.encode(&mut frames);
        }
        let mut crypto_record = None;
        if let Some((offset, data)) = crypto {
            crypto_record = Some((offset, data.len()));
            self.spaces[Epoch::Handshake as usize]
                .crypto_inflight
                .insert(offset, (data.clone(), pn));
            Frame::Crypto { offset, data }.encode(&mut frames);
        }

        let body_len_after_pn = frames.len() + TAG_LEN;
        let h = HandshakeHeader {
            version: QUIC_V1,
            dcid: self.peer_cid.clone(),
            scid: self.local_cid.clone(),
            packet_number: pn,
            pn_len: PN_LEN,
        };
        let (hdr, pn_off) = h.encode_with_pn(body_len_after_pn);
        let wire = self
            .handshake_w
            .as_ref()
            .expect("handshake keys present")
            .encrypt_long(&hdr, &frames, pn, pn_off, PN_LEN as usize);

        let ack_eliciting = crypto_record.is_some();
        self.on_wire_sent(wire.len() as u64, ack_eliciting, now);
        self.spaces[Epoch::Handshake as usize].record_sent(SentPacket {
            pn,
            sent_time: now,
            ack_eliciting,
            in_flight: true,
            frames: AckedFrames {
                crypto: crypto_record,
                stream: Vec::new(),
            },
            bytes_sent: wire.len(),
        });
        wire
    }

    fn build_one_rtt(
        &mut self,
        dgram: Option<Vec<u8>>,
        emit_handshake_done: bool,
        now: Instant,
    ) -> Vec<u8> {
        let pn = self.spaces[Epoch::Application as usize].next_pn;
        self.spaces[Epoch::Application as usize].next_pn += 1;

        let mut frames = std::mem::take(&mut self.scratch_frames);
        frames.clear();
        if let Some(ack) = self.drain_ack_frame(Epoch::Application) {
            ack.encode(&mut frames);
        }
        let mut ack_eliciting = false;
        if emit_handshake_done {
            Frame::HandshakeDone.encode(&mut frames);
            ack_eliciting = true;
        }
        for (seq, cid, token) in std::mem::take(&mut self.new_cid_pending) {
            Frame::NewConnectionId {
                sequence_number: seq,
                retire_prior_to: 0,
                connection_id: cid,
                stateless_reset_token: token,
            }
            .encode(&mut frames);
            ack_eliciting = true;
        }
        for seq in std::mem::take(&mut self.retire_pending) {
            Frame::RetireConnectionId {
                sequence_number: seq,
            }
            .encode(&mut frames);
            ack_eliciting = true;
        }
        if !self.pending_crypto_app.is_empty() {
            let data = std::mem::take(&mut self.pending_crypto_app);
            let space = &mut self.spaces[Epoch::Application as usize];
            let offset = space.crypto_next_offset;
            space.crypto_next_offset += data.len() as u64;
            Frame::Crypto { offset, data }.encode(&mut frames);
            ack_eliciting = true;
        }
        for (id, error_code) in std::mem::take(&mut self.pending_stop_sending) {
            Frame::StopSending {
                stream_id: id,
                error_code,
            }
            .encode(&mut frames);
            ack_eliciting = true;
        }
        for (id, (error_code, final_size)) in std::mem::take(&mut self.pending_resets) {
            Frame::ResetStream {
                stream_id: id,
                error_code,
                final_size,
            }
            .encode(&mut frames);
            ack_eliciting = true;
        }
        if self.local_max_data_pending {
            Frame::MaxData {
                maximum_data: self.local_max_data,
            }
            .encode(&mut frames);
            ack_eliciting = true;
            self.local_max_data_pending = false;
        }
        for id in std::mem::take(&mut self.local_max_stream_data_pending)
            .into_keys()
            .collect::<Vec<_>>()
        {
            let limit = *self.local_max_stream_data.get(&id).unwrap_or(&0);
            Frame::MaxStreamData {
                stream_id: id,
                maximum_stream_data: limit,
            }
            .encode(&mut frames);
            ack_eliciting = true;
        }
        if self.max_streams_bidi_pending {
            Frame::MaxStreams {
                is_uni: false,
                max_streams: self.local_max_streams_bidi,
            }
            .encode(&mut frames);
            ack_eliciting = true;
            self.max_streams_bidi_pending = false;
        }
        for data in std::mem::take(&mut self.pending_path_responses) {
            Frame::PathResponse { data }.encode(&mut frames);
            ack_eliciting = true;
        }
        for data in std::mem::take(&mut self.pending_path_challenges) {
            Frame::PathChallenge { data }.encode(&mut frames);
            self.outstanding_path_challenges.push(data);
            ack_eliciting = true;
        }
        let mut stream_frames: Vec<crate::pn_space::StreamFrameInfo> = Vec::new();
        loop {
            let header_overhead = 1 + self.peer_cid.len() + PN_LEN as usize;
            let room = (K_MAX_DATAGRAM_SIZE as usize)
                .saturating_sub(header_overhead + TAG_LEN + frames.len() + STREAM_FRAME_OVERHEAD);
            let pos = self.spaces[Epoch::Application as usize]
                .stream_retransmit
                .iter()
                .position(|(_, _, len, _)| (*len as usize) <= room);
            let Some(pos) = pos else {
                break;
            };
            let (sid, off, len, fin) = self.spaces[Epoch::Application as usize]
                .stream_retransmit
                .remove(pos);
            let Some(chunk) = self
                .streams_send
                .get(&sid)
                .and_then(|s| s.chunk_at(off, len))
            else {
                continue;
            };
            Frame::encode_stream(&mut frames, sid, off, fin, true, chunk);
            self.spaces[Epoch::Application as usize]
                .stream_inflight
                .insert((sid, off), (len, fin, pn));
            stream_frames.push(crate::pn_space::StreamFrameInfo {
                stream_id: sid,
                offset: off,
                len,
                fin,
            });
            ack_eliciting = true;
        }
        // Drain the snapshot: drained streams are removed, a full packet breaks.
        let mut pending = std::mem::take(&mut self.scratch_pending);
        let header_overhead = 1 + self.peer_cid.len() + PN_LEN as usize;
        let mut idx = 0;
        while idx < pending.len() {
            let id = pending[idx];
            self.ensure_peer_stream_credit(id);
            let stream_limit = *self.peer_max_stream_data.get(&id).unwrap_or(&0);
            let Some(s) = self.streams_send.get_mut(&id) else {
                pending.swap_remove(idx);
                continue;
            };
            let stream_budget = stream_limit.saturating_sub(s.next_offset());
            let conn_budget = self.peer_max_data.saturating_sub(self.peer_total_sent);
            let flow_take = stream_budget.min(conn_budget);
            if flow_take == 0 {
                let has_pending = s.has_pending();
                if conn_budget == 0 && !self.blocked_data_emitted {
                    Frame::DataBlocked {
                        maximum_data: self.peer_max_data,
                    }
                    .encode(&mut frames);
                    ack_eliciting = true;
                    self.blocked_data_emitted = true;
                }
                if stream_budget == 0
                    && !self.blocked_stream_emitted.contains_key(&id)
                    && has_pending
                {
                    Frame::StreamDataBlocked {
                        stream_id: id,
                        maximum_stream_data: stream_limit,
                    }
                    .encode(&mut frames);
                    ack_eliciting = true;
                    self.blocked_stream_emitted.insert(id, ());
                }
                idx += 1;
                continue;
            }
            let packet_room = (K_MAX_DATAGRAM_SIZE as usize)
                .saturating_sub(header_overhead + TAG_LEN + frames.len() + STREAM_FRAME_OVERHEAD);
            let take = flow_take.min(packet_room as u64) as usize;
            if take == 0 {
                break;
            }
            if s.blocked() {
                pending.swap_remove(idx);
                continue;
            }
            let (offset, slice) = s.unsent();
            let n = take.min(slice.len());
            if n == 0 && !s.would_fin(0) {
                pending.swap_remove(idx);
                continue;
            }
            let fin_now = s.would_fin(n);
            Frame::encode_stream(&mut frames, id, offset, fin_now, true, &slice[..n]);
            s.advance_sent(n, fin_now);
            let drained = !s.has_pending();
            self.spaces[Epoch::Application as usize]
                .stream_inflight
                .insert((id, offset), (n as u64, fin_now, pn));
            stream_frames.push(crate::pn_space::StreamFrameInfo {
                stream_id: id,
                offset,
                len: n as u64,
                fin: fin_now,
            });
            ack_eliciting = true;
            self.peer_total_sent = self.peer_total_sent.saturating_add(n as u64);
            if drained {
                pending.swap_remove(idx);
            }
            // else: kept at idx; next iteration sees take==0 and breaks.
        }
        self.scratch_pending = pending;
        if let Some(d) = dgram {
            Frame::Datagram {
                length_prefixed: false,
                data: d,
            }
            .encode(&mut frames);
            ack_eliciting = true;
        }

        let h = ShortHeader {
            dcid: self.peer_cid.clone(),
            packet_number: pn,
            pn_len: PN_LEN,
        };
        let (hdr, pn_off) = h.encode_with_pn();
        let wire = self
            .app_w
            .as_ref()
            .expect("app keys present")
            .encrypt_short(&hdr, &frames, pn, pn_off, PN_LEN as usize);

        frames.clear();
        self.scratch_frames = frames;
        self.on_wire_sent(wire.len() as u64, ack_eliciting, now);
        self.spaces[Epoch::Application as usize].record_sent(SentPacket {
            pn,
            sent_time: now,
            ack_eliciting,
            in_flight: true,
            frames: AckedFrames {
                crypto: None,
                stream: stream_frames,
            },
            bytes_sent: wire.len(),
        });
        wire
    }

    fn build_zero_rtt(&mut self, now: Instant) -> Option<Vec<u8>> {
        self.zero_rtt_w.as_ref()?;
        let stream_ids: Vec<u64> = self
            .streams_send
            .iter()
            .filter(|(_, s)| s.has_pending())
            .map(|(id, _)| *id)
            .collect();
        if stream_ids.is_empty() {
            return None;
        }
        let mut frames = Vec::new();
        let mut ack_eliciting = false;
        for id in stream_ids {
            self.ensure_peer_stream_credit(id);
            let stream_limit = *self.peer_max_stream_data.get(&id).unwrap_or(&u64::MAX);
            let s = self.streams_send.get_mut(&id).expect("just iterated");
            let stream_budget = stream_limit.saturating_sub(s.next_offset());
            let take = stream_budget as usize;
            if take == 0 {
                continue;
            }
            if s.blocked() {
                continue;
            }
            let (offset, slice) = s.unsent();
            let n = take.min(slice.len());
            if n == 0 && !s.would_fin(0) {
                continue;
            }
            let fin_now = s.would_fin(n);
            Frame::encode_stream(&mut frames, id, offset, fin_now, true, &slice[..n]);
            s.advance_sent(n, fin_now);
            ack_eliciting = true;
            self.peer_total_sent = self.peer_total_sent.saturating_add(n as u64);
        }
        if frames.is_empty() {
            return None;
        }
        let pn = self.spaces[Epoch::Application as usize].next_pn;
        self.spaces[Epoch::Application as usize].next_pn += 1;
        let body_len_after_pn = frames.len() + TAG_LEN;
        let h = crate::packet::ZeroRttHeader {
            version: QUIC_V1,
            dcid: self.peer_cid.clone(),
            scid: self.local_cid.clone(),
            packet_number: pn,
            pn_len: PN_LEN,
        };
        let (hdr, pn_off) = h.encode_with_pn(body_len_after_pn);
        let wire = self
            .zero_rtt_w
            .as_ref()
            .expect("checked above")
            .encrypt_long(&hdr, &frames, pn, pn_off, PN_LEN as usize);
        self.on_wire_sent(wire.len() as u64, ack_eliciting, now);
        self.spaces[Epoch::Application as usize].record_sent(SentPacket {
            pn,
            sent_time: now,
            ack_eliciting,
            in_flight: true,
            frames: AckedFrames {
                crypto: None,
                stream: Vec::new(),
            },
            bytes_sent: wire.len(),
        });
        Some(wire)
    }

    fn build_one_rtt_probe(&mut self, target_size: u64, now: Instant) -> Vec<u8> {
        let pn = self.spaces[Epoch::Application as usize].next_pn;
        self.spaces[Epoch::Application as usize].next_pn += 1;

        let mut frames = Vec::new();
        Frame::Ping.encode(&mut frames);
        let header_overhead = 1 + self.peer_cid.len() + PN_LEN as usize;
        let payload_target = (target_size as usize).saturating_sub(header_overhead + TAG_LEN);
        while frames.len() < payload_target {
            Frame::Padding.encode(&mut frames);
        }

        let h = ShortHeader {
            dcid: self.peer_cid.clone(),
            packet_number: pn,
            pn_len: PN_LEN,
        };
        let (hdr, pn_off) = h.encode_with_pn();
        let wire = self
            .app_w
            .as_ref()
            .expect("app keys present")
            .encrypt_short(&hdr, &frames, pn, pn_off, PN_LEN as usize);

        self.on_wire_sent(wire.len() as u64, true, now);
        self.spaces[Epoch::Application as usize].record_sent(SentPacket {
            pn,
            sent_time: now,
            ack_eliciting: true,
            in_flight: true,
            frames: AckedFrames {
                crypto: None,
                stream: Vec::new(),
            },
            bytes_sent: wire.len(),
        });
        self.pmtud.arm_probe(target_size);
        self.pmtud_probe_pn = Some(pn);
        wire
    }

    fn build_one_rtt_close(&mut self, close: PendingClose, now: Instant) -> Vec<u8> {
        let pn = self.spaces[Epoch::Application as usize].next_pn;
        self.spaces[Epoch::Application as usize].next_pn += 1;

        let mut frames = Vec::with_capacity(close.reason.len() + 16);
        Frame::ConnectionClose {
            is_application: close.is_application,
            error_code: close.error_code,
            frame_type: close.frame_type,
            reason: close.reason,
        }
        .encode(&mut frames);

        let h = ShortHeader {
            dcid: self.peer_cid.clone(),
            packet_number: pn,
            pn_len: PN_LEN,
        };
        let (hdr, pn_off) = h.encode_with_pn();
        let wire = self
            .app_w
            .as_ref()
            .expect("app keys present")
            .encrypt_short(&hdr, &frames, pn, pn_off, PN_LEN as usize);

        self.spaces[Epoch::Application as usize].record_sent(SentPacket {
            pn,
            sent_time: now,
            ack_eliciting: false,
            in_flight: false,
            frames: AckedFrames {
                crypto: None,
                stream: Vec::new(),
            },
            bytes_sent: wire.len(),
        });
        wire
    }

    #[doc(hidden)]
    pub fn cc_mut(&mut self) -> &mut NewReno {
        &mut self.cc
    }

    #[doc(hidden)]
    pub fn peer_cids_for_test(&self) -> &BTreeMap<u64, (Vec<u8>, [u8; 16])> {
        &self.peer_cids
    }

    #[doc(hidden)]
    pub fn flush_test_one_rtt(&mut self, frame: Frame, now: Instant) -> Vec<u8> {
        let pn = self.spaces[Epoch::Application as usize].next_pn;
        self.spaces[Epoch::Application as usize].next_pn += 1;
        let mut frames = Vec::new();
        frame.encode(&mut frames);
        let h = ShortHeader {
            dcid: self.peer_cid.clone(),
            packet_number: pn,
            pn_len: PN_LEN,
        };
        let (hdr, pn_off) = h.encode_with_pn();
        let wire = self
            .app_w
            .as_ref()
            .expect("app keys present")
            .encrypt_short(&hdr, &frames, pn, pn_off, PN_LEN as usize);
        self.on_wire_sent(wire.len() as u64, true, now);
        self.spaces[Epoch::Application as usize].record_sent(SentPacket {
            pn,
            sent_time: now,
            ack_eliciting: true,
            in_flight: true,
            frames: AckedFrames {
                crypto: None,
                stream: Vec::new(),
            },
            bytes_sent: wire.len(),
        });
        wire
    }

    fn allows_emit_for(&self, cargo: PacketCargo, now: Instant) -> bool {
        if !self.anti_amp_allows() {
            return false;
        }
        match cargo {
            PacketCargo::CryptoOrAck => self.cc.allows_send() && self.pacer.allows_send(now),
            PacketCargo::DatagramOnly => match self.datagram_cc_mode {
                DatagramCcMode::Standard => self.cc.allows_send() && self.pacer.allows_send(now),
                DatagramCcMode::Uncongested => true,
            },
        }
    }

    pub fn next_send_time(&self) -> Instant {
        self.pacer.next_release_time()
    }

    fn on_wire_sent(&mut self, bytes: u64, ack_eliciting: bool, now: Instant) {
        self.cc.on_packet_sent(bytes, ack_eliciting);
        let srtt = self.rtt.smoothed_rtt.unwrap_or(crate::rtt::K_INITIAL_RTT);
        self.pacer.on_packet_sent(bytes, now, self.cc.cwnd, srtt);
    }

    pub fn send_datagram(&mut self, data: Vec<u8>) -> Result<(), DatagramError> {
        if self.state == State::Closed {
            return Err(DatagramError::Closed);
        }
        let max = self
            .max_datagram_payload()
            .ok_or(DatagramError::PeerDoesNotSupport)?;
        if data.len() > max {
            return Err(DatagramError::TooLarge);
        }
        if self.pending_datagrams.len() >= self.pending_datagrams_cap {
            return Err(DatagramError::QueueFull);
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
        let by_pmtu = (K_MAX_DATAGRAM_SIZE as usize).saturating_sub(overhead);
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
        if self.peer_address_validated {
            return true;
        }
        self.amplification_sent < self.amplification_received.saturating_mul(3)
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
        self.spaces[epoch_ix].sent.len()
    }

    pub fn smoothed_rtt(&self) -> Option<std::time::Duration> {
        self.rtt.smoothed_rtt
    }

    fn decode_pn(buf: &[u8], pn_offset: usize) -> u64 {
        let pn_len = ((buf[0] & 0x03) + 1) as usize;
        let mut pn = 0u64;
        for i in 0..pn_len {
            pn = (pn << 8) | (buf[pn_offset + i] as u64);
        }
        pn
    }
}
