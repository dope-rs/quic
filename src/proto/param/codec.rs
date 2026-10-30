use o3::{alloc, buffer::write, depot::array::sorted};
use std::num::NonZero;

use crate::wire::{packet::cid, varint};

use crate::proto::param;

pub(super) const ID_ORIGINAL_DESTINATION_CONNECTION_ID: u8 = 0x00;
pub(super) const ID_MAX_IDLE_TIMEOUT: u8 = 0x01;
pub(super) const ID_STATELESS_RESET_TOKEN: u8 = 0x02;
pub(super) const ID_MAX_UDP_PAYLOAD_SIZE: u8 = 0x03;
pub(super) const ID_INITIAL_MAX_DATA: u8 = 0x04;
pub(super) const ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u8 = 0x05;
pub(super) const ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u8 = 0x06;
pub(super) const ID_INITIAL_MAX_STREAM_DATA_UNI: u8 = 0x07;
pub(super) const ID_INITIAL_MAX_STREAMS_BIDI: u8 = 0x08;
pub(super) const ID_INITIAL_MAX_STREAMS_UNI: u8 = 0x09;
pub(super) const ID_ACK_DELAY_EXPONENT: u8 = 0x0a;
pub(super) const ID_MAX_ACK_DELAY: u8 = 0x0b;
pub(super) const ID_DISABLE_ACTIVE_MIGRATION: u8 = 0x0c;
pub(super) const ID_PREFERRED_ADDRESS: u8 = 0x0d;
pub(super) const ID_ACTIVE_CONNECTION_ID_LIMIT: u8 = 0x0e;
pub(super) const ID_INITIAL_SOURCE_CONNECTION_ID: u8 = 0x0f;
pub(super) const ID_RETRY_SOURCE_CONNECTION_ID: u8 = 0x10;
pub(super) const ID_MAX_DATAGRAM_FRAME_SIZE: u8 = 0x20;

#[derive(Clone, Copy)]
pub(super) struct Ids<'a> {
    pub(super) initial: cid::Ref<'a>,
    pub(super) original: Option<cid::Ref<'a>>,
    pub(super) retry: Option<cid::Ref<'a>>,
}

pub struct Codec;

impl Codec {
    /// Maximum number of distinct non-reserved parameters accepted per peer.
    pub const MAX_COUNT: usize = 64;

    /// Exact reservation ceiling for every valid parameter set.
    pub const MAX_ENCODED_LEN: usize = 193;

    fn put_varint<S: write::Sink>(
        out: &mut S,
        id: u8,
        value: varint::VarInt,
    ) -> Result<(), S::Error> {
        out.write_slices([&[id, value.encoded_len()], value.pack().as_ref()])
    }

    fn put_cid<S: write::Sink>(out: &mut S, id: u8, value: cid::Ref<'_>) -> Result<(), S::Error> {
        out.write_slices([&[id, value.length().get()], value.into_slice()])
    }

    fn parse_varint(id: u8, value: &[u8]) -> Result<varint::VarInt, param::Error> {
        let (decoded, consumed) = varint::VarInt::decode(value)?;
        if consumed != value.len() {
            return Err(param::Error::Length {
                id: u64::from(id),
                actual: value.len(),
                minimum: consumed,
                maximum: consumed,
            });
        }
        Ok(decoded)
    }

    fn parse_id(id: u8, value: &[u8]) -> Result<cid::Id, param::Error> {
        cid::Id::try_from(value).map_err(|cause| param::Error::Cid {
            id: u64::from(id),
            cause,
        })
    }

    fn parse_addr(value: &[u8]) -> Result<(), param::Error> {
        let Some((header, tail)) = value.split_first_chunk::<25>() else {
            return Err(param::Error::Length {
                id: u64::from(ID_PREFERRED_ADDRESS),
                actual: value.len(),
                minimum: 42,
                maximum: 41 + cid::Id::MAX_LEN,
            });
        };
        let length = NonZero::new(header[24])
            .filter(|length| usize::from(length.get()) <= cid::Id::MAX_LEN)
            .ok_or(param::Error::PreferredCidLength { actual: header[24] })?;
        let length = usize::from(length.get()) + 16;
        if tail.len() != length {
            return Err(param::Error::Length {
                id: u64::from(ID_PREFERRED_ADDRESS),
                actual: value.len(),
                minimum: 25 + length,
                maximum: 25 + length,
            });
        }
        Ok(())
    }

    fn is_reserved(id: u64) -> bool {
        id >= 27 && (id - 27).is_multiple_of(31)
    }

    fn encode_with<S: write::Sink>(
        params: &param::Set,
        out: &mut S,
        ids: Ids<'_>,
        reset: Option<&[u8; 16]>,
    ) -> Result<(), S::Error> {
        Self::put_varint(out, ID_MAX_IDLE_TIMEOUT, params.timing.max_idle_timeout_ms)?;
        Self::put_varint(
            out,
            ID_MAX_UDP_PAYLOAD_SIZE,
            params.flow.max_udp_payload_size,
        )?;
        Self::put_varint(out, ID_INITIAL_MAX_DATA, params.flow.initial_max_data)?;
        Self::put_varint(
            out,
            ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            params.flow.initial_max_stream_data_bidi_local,
        )?;
        Self::put_varint(
            out,
            ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            params.flow.initial_max_stream_data_bidi_remote,
        )?;
        Self::put_varint(
            out,
            ID_INITIAL_MAX_STREAM_DATA_UNI,
            params.flow.initial_max_stream_data_uni,
        )?;
        Self::put_varint(
            out,
            ID_INITIAL_MAX_STREAMS_BIDI,
            params.flow.initial_max_streams_bidi,
        )?;
        Self::put_varint(
            out,
            ID_INITIAL_MAX_STREAMS_UNI,
            params.flow.initial_max_streams_uni,
        )?;
        Self::put_varint(out, ID_ACK_DELAY_EXPONENT, params.timing.ack_delay_exponent)?;
        Self::put_varint(out, ID_MAX_ACK_DELAY, params.timing.max_ack_delay_ms)?;
        if params.identity.disable_active_migration {
            out.write_slice(&[ID_DISABLE_ACTIVE_MIGRATION, 0])?;
        }
        Self::put_varint(
            out,
            ID_ACTIVE_CONNECTION_ID_LIMIT,
            params.identity.active_connection_id_limit,
        )?;
        Self::put_cid(out, ID_INITIAL_SOURCE_CONNECTION_ID, ids.initial)?;
        if let Some(cid) = ids.original {
            Self::put_cid(out, ID_ORIGINAL_DESTINATION_CONNECTION_ID, cid)?;
        }
        if let Some(cid) = ids.retry {
            Self::put_cid(out, ID_RETRY_SOURCE_CONNECTION_ID, cid)?;
        }
        if let Some(size) = params.flow.max_datagram_frame_size {
            Self::put_varint(out, ID_MAX_DATAGRAM_FRAME_SIZE, size)?;
        }
        if let Some(token) = reset {
            out.write_slices([&[ID_STATELESS_RESET_TOKEN, 16], token])?;
        }
        Ok(())
    }

    pub(super) fn encode_vec(
        params: &param::Set,
        out: &mut Vec<u8>,
        ids: Ids<'_>,
        reset: Option<&[u8; 16]>,
    ) -> Result<(), alloc::Error> {
        let mut out = write::Append::new(out);
        let result = Self::encode_with(params, &mut out, ids, reset);
        if result.is_err() {
            out.rollback();
        }
        result
    }

    /// Decodes directly from the borrowed extension body without allocating.
    pub fn decode(input: &[u8]) -> Result<param::Set, param::Error> {
        let mut params = param::Set::default();
        let mut rest = input;
        let mut seen = sorted::Set::<u64, { Self::MAX_COUNT }>::new();
        while !rest.is_empty() {
            let id = varint::Decoded::parse(rest).map_err(varint::Error::from)?;
            let size = varint::Decoded::parse(id.rest()).map_err(varint::Error::from)?;
            let id = id.value().get();
            let body = size.rest();
            let size = size.value().get() as usize;
            let Some((value, next)) = body.split_at_checked(size) else {
                return Err(param::Error::Underflow {
                    offset: input.len() - body.len(),
                    required: size,
                    remaining: body.len(),
                });
            };
            rest = next;

            if Self::is_reserved(id) {
                continue;
            }
            seen.try_insert(id).map_err(param::Error::Id)?;

            let Ok(id) = u8::try_from(id) else {
                continue;
            };
            match id {
                self::ID_ORIGINAL_DESTINATION_CONNECTION_ID => {
                    params.identity.original_destination_connection_id =
                        Some(Self::parse_id(id, value)?);
                }
                self::ID_MAX_IDLE_TIMEOUT => {
                    params.timing.max_idle_timeout_ms = Self::parse_varint(id, value)?;
                }
                self::ID_STATELESS_RESET_TOKEN => {
                    if value.len() != 16 {
                        return Err(param::Error::Length {
                            id: u64::from(id),
                            actual: value.len(),
                            minimum: 16,
                            maximum: 16,
                        });
                    }
                    let mut token = [0; 16];
                    token.copy_from_slice(value);
                    params.identity.stateless_reset_token = Some(token);
                }
                self::ID_MAX_UDP_PAYLOAD_SIZE => {
                    params.flow.max_udp_payload_size = Self::parse_varint(id, value)?;
                }
                self::ID_INITIAL_MAX_DATA => {
                    params.flow.initial_max_data = Self::parse_varint(id, value)?;
                }
                self::ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    params.flow.initial_max_stream_data_bidi_local = Self::parse_varint(id, value)?;
                }
                self::ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    params.flow.initial_max_stream_data_bidi_remote =
                        Self::parse_varint(id, value)?;
                }
                self::ID_INITIAL_MAX_STREAM_DATA_UNI => {
                    params.flow.initial_max_stream_data_uni = Self::parse_varint(id, value)?;
                }
                self::ID_INITIAL_MAX_STREAMS_BIDI => {
                    params.flow.initial_max_streams_bidi = Self::parse_varint(id, value)?;
                }
                self::ID_INITIAL_MAX_STREAMS_UNI => {
                    params.flow.initial_max_streams_uni = Self::parse_varint(id, value)?;
                }
                self::ID_ACK_DELAY_EXPONENT => {
                    params.timing.ack_delay_exponent = Self::parse_varint(id, value)?;
                }
                self::ID_MAX_ACK_DELAY => {
                    params.timing.max_ack_delay_ms = Self::parse_varint(id, value)?;
                }
                self::ID_DISABLE_ACTIVE_MIGRATION => {
                    if !value.is_empty() {
                        return Err(param::Error::Length {
                            id: u64::from(id),
                            actual: value.len(),
                            minimum: 0,
                            maximum: 0,
                        });
                    }
                    params.identity.disable_active_migration = true;
                }
                self::ID_PREFERRED_ADDRESS => {
                    Self::parse_addr(value)?;
                    params.identity.preferred_address = true;
                }
                self::ID_ACTIVE_CONNECTION_ID_LIMIT => {
                    params.identity.active_connection_id_limit = Self::parse_varint(id, value)?;
                }
                self::ID_INITIAL_SOURCE_CONNECTION_ID => {
                    params.identity.initial_source_connection_id = Some(Self::parse_id(id, value)?);
                }
                self::ID_RETRY_SOURCE_CONNECTION_ID => {
                    params.identity.retry_source_connection_id = Some(Self::parse_id(id, value)?);
                }
                self::ID_MAX_DATAGRAM_FRAME_SIZE => {
                    params.flow.max_datagram_frame_size = Some(Self::parse_varint(id, value)?);
                }
                _ => {}
            }
        }
        params.validate()?;
        Ok(params)
    }
}

const _: () = assert!(usize::BITS >= 64);
