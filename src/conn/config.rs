use std::{fmt, mem, ops};

use shin::{client, crypto, server};

use crate::{conn, errors, transport_params};

pub struct Options {
    pub transport_params: transport_params::Params,
    pub datagram_congestion_control: conn::datagram::CongestionControl,
    pub pending_datagrams_capacity: usize,
    pub incoming_datagrams_capacity: usize,
    pub stream_events_capacity: usize,
    /// Connection-wide receive segment nodes shared by gap and ready lanes.
    pub receive_segment_capacity: usize,
    pub packet_journal_capacity: usize,
    pub crypto_journal_capacity: usize,
    pub control_journal_capacity: usize,
    pub stream_journal_capacity: usize,
    /// Maximum simultaneously-live locally initiated bidirectional streams.
    pub local_bidi_stream_capacity: usize,
    /// Maximum simultaneously-live locally initiated unidirectional streams.
    pub local_uni_stream_capacity: usize,
    pub cid_prefix: Option<u8>,
    pub stateless_reset_secret: Option<[u8; 32]>,
    pub require_address_validation: bool,
    pub retry_token_secret: Option<[u8; 32]>,
    pub ticket_secret: Option<[u8; 32]>,
    pub resumption: Option<conn::session::Ticket>,
    pub enable_early_data: bool,
    pub resumption_peer_tp: Option<transport_params::Params>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub server_cert_chain: Option<Vec<Vec<u8>>>,
    pub identity: Option<client::config::Identity>,
    pub max_pmtu: u64,
}

impl fmt::Debug for Options {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Options")
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
            .field("receive_segment_capacity", &self.receive_segment_capacity)
            .field("packet_journal_capacity", &self.packet_journal_capacity)
            .field("crypto_journal_capacity", &self.crypto_journal_capacity)
            .field("control_journal_capacity", &self.control_journal_capacity)
            .field("stream_journal_capacity", &self.stream_journal_capacity)
            .field(
                "local_bidi_stream_capacity",
                &self.local_bidi_stream_capacity,
            )
            .field("local_uni_stream_capacity", &self.local_uni_stream_capacity)
            .field("cid_prefix", &self.cid_prefix)
            .field(
                "require_address_validation",
                &self.require_address_validation,
            )
            .field("enable_early_data", &self.enable_early_data)
            .field("resumption_peer_tp", &self.resumption_peer_tp)
            .field("alpn_protocols", &self.alpn_protocols)
            .field("server_cert_chain", &self.server_cert_chain.is_some())
            .field("identity", &self.identity.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            transport_params: transport_params::Params::default(),
            datagram_congestion_control: conn::datagram::CongestionControl::Standard,
            pending_datagrams_capacity: 1024,
            incoming_datagrams_capacity: 1024,
            stream_events_capacity: 1024,
            receive_segment_capacity: crate::range_buffer::MAX_RANGES,
            packet_journal_capacity: conn::PACKET_JOURNAL_CAPACITY,
            crypto_journal_capacity: conn::CRYPTO_JOURNAL_CAPACITY,
            control_journal_capacity: conn::CONTROL_JOURNAL_CAPACITY,
            stream_journal_capacity: conn::STREAM_JOURNAL_CAPACITY,
            local_bidi_stream_capacity: 1024,
            local_uni_stream_capacity: 1024,
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
            identity: None,
            max_pmtu: crate::pmtud::DEFAULT_MAX_PMTU,
        }
    }
}

impl Options {
    pub(crate) fn max_packet_bytes(&self) -> usize {
        self.max_pmtu as usize
    }

    pub(crate) fn connection_ceiling(&self, outgoing_capacity: usize) -> usize {
        self.max_packet_bytes().min(outgoing_capacity)
    }

    pub fn validate(&self) -> Result<(), errors::ConnectFailure> {
        let indexed = [
            self.packet_journal_capacity,
            self.crypto_journal_capacity,
            self.control_journal_capacity,
            self.stream_journal_capacity,
        ];
        if self.max_pmtu < conn::MIN_INITIAL_LEN as u64
            || self.max_pmtu > crate::pmtud::MAX_PMTU
            || usize::try_from(self.max_pmtu).is_err()
            || self.pending_datagrams_capacity > conn::MAX_QUEUE_CAPACITY
            || self.incoming_datagrams_capacity > conn::MAX_QUEUE_CAPACITY
            || self.stream_events_capacity == 0
            || self.stream_events_capacity > conn::MAX_QUEUE_CAPACITY
            || self.receive_segment_capacity == 0
            || self.receive_segment_capacity > conn::MAX_QUEUE_CAPACITY
            || self.packet_journal_capacity < 2
            || self.crypto_journal_capacity < 2
            || self.control_journal_capacity < conn::PACKET_CONTROL_CAPACITY * 2
            || self.stream_journal_capacity < conn::PACKET_STREAM_CAPACITY * 2
            || self.local_bidi_stream_capacity > conn::MAX_STREAMS as usize
            || self.local_uni_stream_capacity > conn::MAX_STREAMS as usize
            || indexed
                .into_iter()
                .any(|capacity| capacity > u16::MAX as usize)
            || self.transport_params.initial_max_data > conn::MAX_FLOW_CONTROL_CREDIT
            || self.transport_params.initial_max_stream_data_bidi_local
                > conn::MAX_FLOW_CONTROL_CREDIT
            || self.transport_params.initial_max_stream_data_bidi_remote
                > conn::MAX_FLOW_CONTROL_CREDIT
            || self.transport_params.initial_max_stream_data_uni > conn::MAX_FLOW_CONTROL_CREDIT
            || self.transport_params.initial_max_streams_bidi > conn::MAX_STREAMS
            || self.transport_params.initial_max_streams_uni > conn::MAX_STREAMS
            || self.transport_params.active_connection_id_limit
                > conn::MAX_ACTIVE_CONNECTION_IDS as u64
            || self.transport_params.validate().is_err()
            || self
                .resumption_peer_tp
                .as_ref()
                .is_some_and(|params| params.validate().is_err())
        {
            return Err(errors::ConnectFailure::InvalidConfig);
        }
        Ok(())
    }

    pub(crate) fn validate_pooled_client(&self) -> Result<(), errors::ConnectFailure> {
        self.validate()?;
        if !self.alpn_protocols.is_empty()
            || self.server_cert_chain.is_some()
            || self.ticket_secret.is_some()
            || self.identity.is_some()
            || self.enable_early_data
        {
            return Err(errors::ConnectFailure::InvalidConfig);
        }
        Ok(())
    }

    fn validate_pooled_server(&self) -> Result<(), errors::ConnectFailure> {
        self.validate()?;
        if !self.alpn_protocols.is_empty()
            || self.server_cert_chain.is_some()
            || self.ticket_secret.is_some()
            || self.resumption.is_some()
            || self.identity.is_some()
            || self.enable_early_data
        {
            return Err(errors::ConnectFailure::InvalidConfig);
        }
        Ok(())
    }

    pub(crate) fn duplicate_connection(&self) -> Result<Self, errors::ConnectFailure> {
        if self.resumption.is_some() || self.identity.is_some() {
            return Err(errors::ConnectFailure::InvalidConfig);
        }
        Ok(Self {
            transport_params: self.transport_params.clone(),
            datagram_congestion_control: self.datagram_congestion_control,
            pending_datagrams_capacity: self.pending_datagrams_capacity,
            incoming_datagrams_capacity: self.incoming_datagrams_capacity,
            stream_events_capacity: self.stream_events_capacity,
            receive_segment_capacity: self.receive_segment_capacity,
            packet_journal_capacity: self.packet_journal_capacity,
            crypto_journal_capacity: self.crypto_journal_capacity,
            control_journal_capacity: self.control_journal_capacity,
            stream_journal_capacity: self.stream_journal_capacity,
            local_bidi_stream_capacity: self.local_bidi_stream_capacity,
            local_uni_stream_capacity: self.local_uni_stream_capacity,
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
            identity: None,
            max_pmtu: self.max_pmtu,
        })
    }
}

impl From<transport_params::Params> for Options {
    fn from(params: transport_params::Params) -> Self {
        Self {
            transport_params: params,
            ..Default::default()
        }
    }
}

#[repr(transparent)]
pub(crate) struct Validated(Options);

impl Validated {
    pub(crate) fn new(config: Options) -> Result<Self, errors::ConnectFailure> {
        config.validate()?;
        Ok(Self(config))
    }

    pub(crate) fn new_pooled_server(config: Options) -> Result<Self, errors::ConnectFailure> {
        config.validate_pooled_server()?;
        Ok(Self(config))
    }

    pub(crate) fn cap_max_pmtu(&mut self, ceiling: u64) -> Result<(), errors::ConnectFailure> {
        if ceiling < conn::MIN_INITIAL_LEN as u64 {
            return Err(errors::ConnectFailure::InvalidConfig);
        }
        self.0.max_pmtu = self.0.max_pmtu.min(ceiling);
        Ok(())
    }

    pub(crate) fn duplicate_connection(&self) -> Result<Self, errors::ConnectFailure> {
        self.0.duplicate_connection().map(Self)
    }

    pub(crate) fn take_server_config(
        &mut self,
        signing_key: crypto::sig::SigningKey,
    ) -> Result<server::config::Config, errors::ConnectFailure> {
        let ticket_keys = self
            .0
            .ticket_secret
            .take()
            .map(crypto::ticket::Keys::single)
            .transpose()
            .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
        Ok(shin::server::config::Config {
            source: match self.0.server_cert_chain.take() {
                Some(chain_der) => server::config::CertSource::X509 {
                    chain_der,
                    signing_key,
                },
                None => server::config::CertSource::RawPublicKey { signing_key },
            },
            alpn_protocols: mem::take(&mut self.0.alpn_protocols),
            ticket_keys,
        })
    }

    pub(super) fn into_inner(self) -> Options {
        self.0
    }
}

impl ops::Deref for Validated {
    type Target = Options;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
