use std::{error, fmt};

use crate::packet;
use crate::varint;

trait Sink {
    fn put(&mut self, bytes: &[u8]) -> Result<(), TransportParameterError>;
}

#[derive(Clone, Copy)]
struct ConnectionIds<'a> {
    initial: Option<packet::ConnectionIdRef<'a>>,
    original: Option<packet::ConnectionIdRef<'a>>,
    retry: Option<packet::ConnectionIdRef<'a>>,
}

impl Sink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), TransportParameterError> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

impl Sink for shin::connection::RetainedBytes<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), TransportParameterError> {
        self.try_extend(bytes)
            .map_err(|_| TransportParameterError::OutOfRange)
    }
}

pub const ID_ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
pub const ID_MAX_IDLE_TIMEOUT: u64 = 0x01;
pub const ID_STATELESS_RESET_TOKEN: u64 = 0x02;
pub const ID_MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
pub const ID_INITIAL_MAX_DATA: u64 = 0x04;
pub const ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
pub const ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
pub const ID_INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
pub const ID_INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
pub const ID_INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
pub const ID_ACK_DELAY_EXPONENT: u64 = 0x0a;
pub const ID_MAX_ACK_DELAY: u64 = 0x0b;
pub const ID_DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
pub const ID_ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
pub const ID_INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
pub const ID_RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;
pub const ID_MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;

pub const DEFAULT_MAX_UDP_PAYLOAD_SIZE: u64 = 65527;
pub const DEFAULT_ACK_DELAY_EXPONENT: u64 = 3;
pub const DEFAULT_MAX_ACK_DELAY_MS: u64 = 25;
pub const DEFAULT_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;

/// Maximum number of distinct, non-reserved parameters accepted from one
/// peer. The current profile defines 17 parameters; the remaining slots are
/// an explicit forward-compatibility budget that keeps decoding allocation
/// free and adversarial work bounded.
pub const MAX_PARAMETERS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportParameterError {
    Underflow,
    BadVarInt,
    Duplicate,
    TooMany,
    BadValueLength,
    OutOfRange,
}

impl fmt::Display for TransportParameterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Underflow => "truncated transport parameter",
            Self::BadVarInt => "invalid transport parameter integer",
            Self::Duplicate => "duplicate transport parameter",
            Self::TooMany => "too many transport parameters",
            Self::BadValueLength => "invalid transport parameter length",
            Self::OutOfRange => "transport parameter is out of range",
        })
    }
}

impl error::Error for TransportParameterError {}

impl From<varint::Error> for TransportParameterError {
    fn from(_: varint::Error) -> Self {
        Self::BadVarInt
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    pub max_idle_timeout_ms: u64,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay_ms: u64,
    pub disable_active_migration: bool,
    pub active_connection_id_limit: u64,
    pub initial_source_connection_id: Option<packet::ConnectionId>,
    pub original_destination_connection_id: Option<packet::ConnectionId>,
    pub retry_source_connection_id: Option<packet::ConnectionId>,
    pub max_datagram_frame_size: Option<u64>,
    pub stateless_reset_token: Option<[u8; 16]>,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            max_idle_timeout_ms: 0,
            max_udp_payload_size: DEFAULT_MAX_UDP_PAYLOAD_SIZE,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: DEFAULT_ACK_DELAY_EXPONENT,
            max_ack_delay_ms: DEFAULT_MAX_ACK_DELAY_MS,
            disable_active_migration: false,
            active_connection_id_limit: DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
            initial_source_connection_id: None,
            original_destination_connection_id: None,
            retry_source_connection_id: None,
            max_datagram_frame_size: None,
            stateless_reset_token: None,
        }
    }
}

impl Params {
    /// Conservative exact-all-fields reservation bound. Every valid parameter
    /// set, including maximum-length connection IDs, fits this many bytes.
    pub const MAX_ENCODED_LEN: usize = 193;

    pub fn validate(&self) -> Result<(), TransportParameterError> {
        let varints = [
            self.max_idle_timeout_ms,
            self.max_udp_payload_size,
            self.initial_max_data,
            self.initial_max_stream_data_bidi_local,
            self.initial_max_stream_data_bidi_remote,
            self.initial_max_stream_data_uni,
            self.initial_max_streams_bidi,
            self.initial_max_streams_uni,
            self.ack_delay_exponent,
            self.max_ack_delay_ms,
            self.active_connection_id_limit,
        ];
        if varints.into_iter().any(|value| value > varint::VarInt::MAX)
            || self.max_udp_payload_size < 1200
            || self.initial_max_streams_bidi > (1u64 << 60)
            || self.initial_max_streams_uni > (1u64 << 60)
            || self.ack_delay_exponent > 20
            || self.max_ack_delay_ms >= (1u64 << 14)
            || self.active_connection_id_limit < 2
            || self
                .max_datagram_frame_size
                .is_some_and(|value| value > varint::VarInt::MAX)
        {
            return Err(TransportParameterError::OutOfRange);
        }
        Ok(())
    }

    fn put_encoded(
        out: &mut impl Sink,
        value: varint::VarInt,
    ) -> Result<(), TransportParameterError> {
        let raw = value.get();
        match value.encoded_len() {
            1 => out.put(&[raw as u8]),
            2 => out.put(&((raw as u16) | 0x4000).to_be_bytes()),
            4 => out.put(&((raw as u32) | 0x8000_0000).to_be_bytes()),
            _ => out.put(&(raw | 0xC000_0000_0000_0000).to_be_bytes()),
        }
    }

    fn put_varint(out: &mut impl Sink, id: u64, value: u64) -> Result<(), TransportParameterError> {
        Self::put_encoded(
            out,
            varint::VarInt::new(id).ok_or(TransportParameterError::OutOfRange)?,
        )?;
        let value = varint::VarInt::new(value).ok_or(TransportParameterError::OutOfRange)?;
        Self::put_encoded(
            out,
            varint::VarInt::from_usize(value.encoded_len())
                .ok_or(TransportParameterError::OutOfRange)?,
        )?;
        Self::put_encoded(out, value)?;
        Ok(())
    }

    fn put_bytes(
        out: &mut impl Sink,
        id: u64,
        value: &[u8],
    ) -> Result<(), TransportParameterError> {
        Self::put_encoded(
            out,
            varint::VarInt::new(id).ok_or(TransportParameterError::OutOfRange)?,
        )?;
        Self::put_encoded(
            out,
            varint::VarInt::from_usize(value.len()).ok_or(TransportParameterError::OutOfRange)?,
        )?;
        out.put(value)?;
        Ok(())
    }

    fn put_empty(out: &mut impl Sink, id: u64) -> Result<(), TransportParameterError> {
        Self::put_encoded(
            out,
            varint::VarInt::new(id).ok_or(TransportParameterError::OutOfRange)?,
        )?;
        out.put(&[0])?;
        Ok(())
    }

    fn parse_varint(value: &[u8]) -> Result<u64, TransportParameterError> {
        let (v, n) = varint::VarInt::decode(value)?;
        if n != value.len() {
            return Err(TransportParameterError::BadValueLength);
        }
        Ok(v.get())
    }

    fn is_reserved(id: u64) -> bool {
        id >= 27 && (id - 27).is_multiple_of(31)
    }

    fn encode_to(
        &self,
        out: &mut impl Sink,
        ids: ConnectionIds<'_>,
    ) -> Result<(), TransportParameterError> {
        self.validate()?;
        Self::put_varint(out, ID_MAX_IDLE_TIMEOUT, self.max_idle_timeout_ms)?;
        Self::put_varint(out, ID_MAX_UDP_PAYLOAD_SIZE, self.max_udp_payload_size)?;
        Self::put_varint(out, ID_INITIAL_MAX_DATA, self.initial_max_data)?;
        Self::put_varint(
            out,
            ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            self.initial_max_stream_data_bidi_local,
        )?;
        Self::put_varint(
            out,
            ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            self.initial_max_stream_data_bidi_remote,
        )?;
        Self::put_varint(
            out,
            ID_INITIAL_MAX_STREAM_DATA_UNI,
            self.initial_max_stream_data_uni,
        )?;
        Self::put_varint(
            out,
            ID_INITIAL_MAX_STREAMS_BIDI,
            self.initial_max_streams_bidi,
        )?;
        Self::put_varint(
            out,
            ID_INITIAL_MAX_STREAMS_UNI,
            self.initial_max_streams_uni,
        )?;
        Self::put_varint(out, ID_ACK_DELAY_EXPONENT, self.ack_delay_exponent)?;
        Self::put_varint(out, ID_MAX_ACK_DELAY, self.max_ack_delay_ms)?;
        if self.disable_active_migration {
            Self::put_empty(out, ID_DISABLE_ACTIVE_MIGRATION)?;
        }
        Self::put_varint(
            out,
            ID_ACTIVE_CONNECTION_ID_LIMIT,
            self.active_connection_id_limit,
        )?;
        if let Some(cid) = ids.initial {
            Self::put_bytes(out, ID_INITIAL_SOURCE_CONNECTION_ID, cid.into_slice())?;
        }
        if let Some(cid) = ids.original {
            Self::put_bytes(out, ID_ORIGINAL_DESTINATION_CONNECTION_ID, cid.into_slice())?;
        }
        if let Some(cid) = ids.retry {
            Self::put_bytes(out, ID_RETRY_SOURCE_CONNECTION_ID, cid.into_slice())?;
        }
        if let Some(size) = self.max_datagram_frame_size {
            Self::put_varint(out, ID_MAX_DATAGRAM_FRAME_SIZE, size)?;
        }
        if let Some(token) = &self.stateless_reset_token {
            Self::put_bytes(out, ID_STATELESS_RESET_TOKEN, token)?;
        }
        Ok(())
    }

    fn connection_ids(&self) -> ConnectionIds<'_> {
        ConnectionIds {
            initial: self
                .initial_source_connection_id
                .as_ref()
                .map(packet::ConnectionId::as_ref_id),
            original: self
                .original_destination_connection_id
                .as_ref()
                .map(packet::ConnectionId::as_ref_id),
            retry: self
                .retry_source_connection_id
                .as_ref()
                .map(packet::ConnectionId::as_ref_id),
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), TransportParameterError> {
        self.encode_to(out, self.connection_ids())
    }

    pub fn encode_retained(
        &self,
        out: &mut shin::connection::RetainedBytes<'_>,
    ) -> Result<(), TransportParameterError> {
        self.encode_to(out, self.connection_ids())
    }

    pub(crate) fn encode_connection_retained(
        &self,
        is_client: bool,
        local_cid: &[u8],
        original_dcid: &[u8],
        retry_scid: Option<&[u8]>,
        out: &mut shin::connection::RetainedBytes<'_>,
    ) -> Result<(), TransportParameterError> {
        let initial = packet::ConnectionIdRef::new(local_cid)
            .map_err(|_| TransportParameterError::OutOfRange)?;
        let original = packet::ConnectionIdRef::new(original_dcid)
            .map_err(|_| TransportParameterError::OutOfRange)?;
        let retry = retry_scid
            .map(packet::ConnectionIdRef::new)
            .transpose()
            .map_err(|_| TransportParameterError::OutOfRange)?;
        self.encode_to(
            out,
            ConnectionIds {
                initial: Some(initial),
                original: (!is_client).then_some(original),
                retry: (!is_client).then_some(retry).flatten(),
            },
        )
    }

    /// Decodes directly from the borrowed extension body without allocating.
    pub fn decode(input: &[u8]) -> Result<Self, TransportParameterError> {
        let mut params = Self::default();
        let mut pos = 0;
        let mut seen = o3::collections::fixed::array::CopyInline::<u64, MAX_PARAMETERS>::new();
        while pos < input.len() {
            let (id, n) = varint::VarInt::decode(&input[pos..])?;
            pos += n;
            let (length, n) = varint::VarInt::decode(&input[pos..])?;
            pos += n;
            let id = id.get();
            let length =
                usize::try_from(length.get()).map_err(|_| TransportParameterError::OutOfRange)?;
            let end = pos
                .checked_add(length)
                .filter(|&end| end <= input.len())
                .ok_or(TransportParameterError::Underflow)?;
            let value = &input[pos..end];
            pos = end;

            if Self::is_reserved(id) {
                continue;
            }
            match seen.binary_search(&id) {
                Ok(_) => return Err(TransportParameterError::Duplicate),
                Err(position) => seen
                    .insert(position, id)
                    .map_err(|_| TransportParameterError::TooMany)?,
            }

            match id {
                ID_ORIGINAL_DESTINATION_CONNECTION_ID => {
                    params.original_destination_connection_id = Some(
                        packet::ConnectionId::new(value)
                            .ok_or(TransportParameterError::BadValueLength)?,
                    );
                }
                ID_MAX_IDLE_TIMEOUT => {
                    params.max_idle_timeout_ms = Self::parse_varint(value)?;
                }
                ID_STATELESS_RESET_TOKEN => {
                    if value.len() != 16 {
                        return Err(TransportParameterError::BadValueLength);
                    }
                    let mut token = [0u8; 16];
                    token.copy_from_slice(value);
                    params.stateless_reset_token = Some(token);
                }
                ID_MAX_UDP_PAYLOAD_SIZE => {
                    let v = Self::parse_varint(value)?;
                    if v < 1200 {
                        return Err(TransportParameterError::OutOfRange);
                    }
                    params.max_udp_payload_size = v;
                }
                ID_INITIAL_MAX_DATA => {
                    params.initial_max_data = Self::parse_varint(value)?;
                }
                ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    params.initial_max_stream_data_bidi_local = Self::parse_varint(value)?;
                }
                ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    params.initial_max_stream_data_bidi_remote = Self::parse_varint(value)?;
                }
                ID_INITIAL_MAX_STREAM_DATA_UNI => {
                    params.initial_max_stream_data_uni = Self::parse_varint(value)?;
                }
                ID_INITIAL_MAX_STREAMS_BIDI => {
                    let v = Self::parse_varint(value)?;
                    if v > (1u64 << 60) {
                        return Err(TransportParameterError::OutOfRange);
                    }
                    params.initial_max_streams_bidi = v;
                }
                ID_INITIAL_MAX_STREAMS_UNI => {
                    let v = Self::parse_varint(value)?;
                    if v > (1u64 << 60) {
                        return Err(TransportParameterError::OutOfRange);
                    }
                    params.initial_max_streams_uni = v;
                }
                ID_ACK_DELAY_EXPONENT => {
                    let v = Self::parse_varint(value)?;
                    if v > 20 {
                        return Err(TransportParameterError::OutOfRange);
                    }
                    params.ack_delay_exponent = v;
                }
                ID_MAX_ACK_DELAY => {
                    let v = Self::parse_varint(value)?;
                    if v >= (1u64 << 14) {
                        return Err(TransportParameterError::OutOfRange);
                    }
                    params.max_ack_delay_ms = v;
                }
                ID_DISABLE_ACTIVE_MIGRATION => {
                    if !value.is_empty() {
                        return Err(TransportParameterError::BadValueLength);
                    }
                    params.disable_active_migration = true;
                }
                ID_ACTIVE_CONNECTION_ID_LIMIT => {
                    let v = Self::parse_varint(value)?;
                    if v < 2 {
                        return Err(TransportParameterError::OutOfRange);
                    }
                    params.active_connection_id_limit = v;
                }
                ID_INITIAL_SOURCE_CONNECTION_ID => {
                    params.initial_source_connection_id = Some(
                        packet::ConnectionId::new(value)
                            .ok_or(TransportParameterError::BadValueLength)?,
                    );
                }
                ID_RETRY_SOURCE_CONNECTION_ID => {
                    params.retry_source_connection_id = Some(
                        packet::ConnectionId::new(value)
                            .ok_or(TransportParameterError::BadValueLength)?,
                    );
                }
                ID_MAX_DATAGRAM_FRAME_SIZE => {
                    params.max_datagram_frame_size = Some(Self::parse_varint(value)?);
                }
                _ => {}
            }
        }
        Ok(params)
    }
}
