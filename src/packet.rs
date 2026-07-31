use subtle::ConstantTimeEq;

use crate::varint::VarInt;

pub const FORM_LONG: u8 = 0x80;
pub const FIXED_BIT: u8 = 0x40;
pub const LONG_TYPE_MASK: u8 = 0x30;
pub const LONG_INITIAL: u8 = 0x00;
pub const LONG_ZERO_RTT: u8 = 0x10;
pub const LONG_HANDSHAKE: u8 = 0x20;
pub const LONG_RETRY: u8 = 0x30;

pub const QUIC_V1: u32 = 0x0000_0001;
const MAX_CONNECTION_ID_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Underflow,
    NotLongHeader,
    UnsupportedVersion,
    BadCidLen,
    BadVarInt,
    BadType,
}

impl_error!(DecodeError {
    Self::Underflow => "truncated packet header",
    Self::NotLongHeader => "expected a long packet header",
    Self::UnsupportedVersion => "unsupported QUIC version",
    Self::BadCidLen => "invalid connection ID length",
    Self::BadVarInt => "invalid packet integer",
    Self::BadType => "invalid packet type",
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    InvalidPacketNumberLength,
    CidTooLong,
    ValueOutOfRange,
    Crypto,
}

impl_error!(EncodeError {
    Self::InvalidPacketNumberLength => "invalid packet number length",
    Self::CidTooLong => "connection ID is too long",
    Self::ValueOutOfRange => "packet value is out of range",
    Self::Crypto => "packet cryptography failed",
});

fn validate_header_fields(pn_len: u8, dcid: &[u8], scid: &[u8]) -> Result<(), EncodeError> {
    if !matches!(pn_len, 1..=4) {
        return Err(EncodeError::InvalidPacketNumberLength);
    }
    if dcid.len() > MAX_CONNECTION_ID_LEN || scid.len() > MAX_CONNECTION_ID_LEN {
        return Err(EncodeError::CidTooLong);
    }
    Ok(())
}

struct LongPrefix<'a> {
    version: u32,
    dcid: &'a [u8],
    scid: &'a [u8],
    pos: usize,
}

fn take<'a>(input: &'a [u8], pos: &mut usize, length: usize) -> Result<&'a [u8], DecodeError> {
    let end = pos
        .checked_add(length)
        .filter(|&end| end <= input.len())
        .ok_or(DecodeError::Underflow)?;
    let value = &input[*pos..end];
    *pos = end;
    Ok(value)
}

fn take_connection_id<'a>(input: &'a [u8], pos: &mut usize) -> Result<&'a [u8], DecodeError> {
    let length = usize::from(*input.get(*pos).ok_or(DecodeError::Underflow)?);
    *pos += 1;
    if length > MAX_CONNECTION_ID_LEN {
        return Err(DecodeError::BadCidLen);
    }
    take(input, pos, length)
}

fn decode_long_prefix(input: &[u8], packet_type: u8) -> Result<LongPrefix<'_>, DecodeError> {
    if input.len() < 7 {
        return Err(DecodeError::Underflow);
    }
    let first = input[0];
    if first & FORM_LONG == 0 {
        return Err(DecodeError::NotLongHeader);
    }
    if first & LONG_TYPE_MASK != packet_type {
        return Err(DecodeError::BadType);
    }
    let version = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);
    if version != QUIC_V1 {
        return Err(DecodeError::UnsupportedVersion);
    }
    let mut pos = 5;
    let dcid = take_connection_id(input, &mut pos)?;
    let scid = take_connection_id(input, &mut pos)?;
    Ok(LongPrefix {
        version,
        dcid,
        scid,
        pos,
    })
}

fn decode_length(input: &[u8], pos: &mut usize) -> Result<usize, DecodeError> {
    let (length, consumed) = VarInt::decode(&input[*pos..]).map_err(|_| DecodeError::BadVarInt)?;
    *pos += consumed;
    usize::try_from(length.get()).map_err(|_| DecodeError::BadVarInt)
}

fn decode_non_initial_prefix(
    input: &[u8],
    packet_type: u8,
) -> Result<DecodedHandshakePrefix, DecodeError> {
    let prefix = decode_long_prefix(input, packet_type)?;
    let mut pos = prefix.pos;
    let length = decode_length(input, &mut pos)?;
    Ok(DecodedHandshakePrefix {
        version: prefix.version,
        dcid: prefix.dcid.to_vec(),
        scid: prefix.scid.to_vec(),
        pn_offset: pos,
        length,
    })
}

pub(crate) struct LongHeader<'a> {
    pub(crate) version: u32,
    pub(crate) packet_type: u8,
    pub(crate) dcid: &'a [u8],
    pub(crate) scid: &'a [u8],
    pub(crate) token: Option<&'a [u8]>,
    pub(crate) packet_number: u64,
    pub(crate) packet_number_len: u8,
}

impl LongHeader<'_> {
    pub(crate) fn encode_into(
        self,
        out: &mut Vec<u8>,
        body_len_after_pn: usize,
    ) -> Result<usize, EncodeError> {
        validate_header_fields(self.packet_number_len, self.dcid, self.scid)?;
        let body_len =
            u64::try_from(body_len_after_pn).map_err(|_| EncodeError::ValueOutOfRange)?;
        let length = u64::from(self.packet_number_len)
            .checked_add(body_len)
            .filter(|&length| length <= VarInt::MAX)
            .ok_or(EncodeError::ValueOutOfRange)?;
        out.push(FORM_LONG | FIXED_BIT | self.packet_type | (self.packet_number_len - 1));
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.dcid.len() as u8);
        out.extend_from_slice(self.dcid);
        out.push(self.scid.len() as u8);
        out.extend_from_slice(self.scid);
        if let Some(token) = self.token {
            let token_len = VarInt::from_usize(token.len()).ok_or(EncodeError::ValueOutOfRange)?;
            token_len.encode(out);
            out.extend_from_slice(token);
        }
        VarInt::new(length)
            .ok_or(EncodeError::ValueOutOfRange)?
            .encode(out);
        let pn_offset = out.len();
        out.extend_from_slice(
            &self.packet_number.to_be_bytes()[8 - usize::from(self.packet_number_len)..],
        );
        Ok(pn_offset)
    }
}

pub(crate) struct ShortHeaderRef<'a> {
    pub(crate) dcid: &'a [u8],
    pub(crate) packet_number: u64,
    pub(crate) pn_len: u8,
}

impl ShortHeaderRef<'_> {
    pub(crate) fn encode_into(self, out: &mut Vec<u8>) -> Result<usize, EncodeError> {
        validate_header_fields(self.pn_len, self.dcid, &[])?;
        out.push(FIXED_BIT | (self.pn_len - 1));
        out.extend_from_slice(self.dcid);
        let pn_offset = out.len();
        out.extend_from_slice(&self.packet_number.to_be_bytes()[8 - usize::from(self.pn_len)..]);
        Ok(pn_offset)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialHeader {
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub packet_number: u64,
    pub pn_len: u8,
}

impl InitialHeader {
    pub fn encode_with_pn(
        &self,
        body_len_after_pn: usize,
    ) -> Result<(Vec<u8>, usize), EncodeError> {
        let mut out = Vec::with_capacity(64 + self.dcid.len() + self.scid.len() + self.token.len());
        let pn_offset = LongHeader {
            version: self.version,
            packet_type: LONG_INITIAL,
            dcid: &self.dcid,
            scid: &self.scid,
            token: Some(&self.token),
            packet_number: self.packet_number,
            packet_number_len: self.pn_len,
        }
        .encode_into(&mut out, body_len_after_pn)?;
        Ok((out, pn_offset))
    }

    pub fn decode_pre_hp(input: &[u8]) -> Result<DecodedInitialPrefix, DecodeError> {
        let prefix = decode_long_prefix(input, LONG_INITIAL)?;
        let mut pos = prefix.pos;
        let token_len = decode_length(input, &mut pos)?;
        let token = take(input, &mut pos, token_len)?.to_vec();
        let length = decode_length(input, &mut pos)?;
        Ok(DecodedInitialPrefix {
            version: prefix.version,
            dcid: prefix.dcid.to_vec(),
            scid: prefix.scid.to_vec(),
            token,
            pn_offset: pos,
            length,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedInitialPrefix {
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub pn_offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LongType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

impl LongType {
    pub fn from_first_byte(b: u8) -> Result<Self, DecodeError> {
        if b & FORM_LONG == 0 {
            return Err(DecodeError::NotLongHeader);
        }
        Ok(match b & LONG_TYPE_MASK {
            LONG_INITIAL => Self::Initial,
            LONG_ZERO_RTT => Self::ZeroRtt,
            LONG_HANDSHAKE => Self::Handshake,
            LONG_RETRY => Self::Retry,
            _ => return Err(DecodeError::BadType),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeHeader {
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub packet_number: u64,
    pub pn_len: u8,
}

impl HandshakeHeader {
    pub fn encode_with_pn(
        &self,
        body_len_after_pn: usize,
    ) -> Result<(Vec<u8>, usize), EncodeError> {
        let mut out = Vec::with_capacity(32 + self.dcid.len() + self.scid.len());
        let pn_offset = LongHeader {
            version: self.version,
            packet_type: LONG_HANDSHAKE,
            dcid: &self.dcid,
            scid: &self.scid,
            token: None,
            packet_number: self.packet_number,
            packet_number_len: self.pn_len,
        }
        .encode_into(&mut out, body_len_after_pn)?;
        Ok((out, pn_offset))
    }

    pub fn decode_pre_hp(input: &[u8]) -> Result<DecodedHandshakePrefix, DecodeError> {
        decode_non_initial_prefix(input, LONG_HANDSHAKE)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedHandshakePrefix {
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub pn_offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeroRttHeader {
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub packet_number: u64,
    pub pn_len: u8,
}

impl ZeroRttHeader {
    pub fn encode_with_pn(
        &self,
        body_len_after_pn: usize,
    ) -> Result<(Vec<u8>, usize), EncodeError> {
        let mut out = Vec::with_capacity(32 + self.dcid.len() + self.scid.len());
        let pn_offset = LongHeader {
            version: self.version,
            packet_type: LONG_ZERO_RTT,
            dcid: &self.dcid,
            scid: &self.scid,
            token: None,
            packet_number: self.packet_number,
            packet_number_len: self.pn_len,
        }
        .encode_into(&mut out, body_len_after_pn)?;
        Ok((out, pn_offset))
    }

    pub fn decode_pre_hp(input: &[u8]) -> Result<DecodedHandshakePrefix, DecodeError> {
        decode_non_initial_prefix(input, LONG_ZERO_RTT)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortHeader {
    pub dcid: Vec<u8>,
    pub packet_number: u64,
    pub pn_len: u8,
}

impl ShortHeader {
    pub fn encode_with_pn(&self) -> Result<(Vec<u8>, usize), EncodeError> {
        let mut out = Vec::with_capacity(1 + self.dcid.len() + self.pn_len as usize);
        let pn_offset = ShortHeaderRef {
            dcid: &self.dcid,
            packet_number: self.packet_number,
            pn_len: self.pn_len,
        }
        .encode_into(&mut out)?;
        Ok((out, pn_offset))
    }

    pub fn pn_offset_for(dcid_len: usize) -> usize {
        1 + dcid_len
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPacket {
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub integrity_tag: [u8; 16],
}

pub const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
pub const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

impl RetryPacket {
    pub fn encode_header(&self) -> Result<Vec<u8>, EncodeError> {
        validate_header_fields(1, &self.dcid, &self.scid)?;
        let mut out = Vec::with_capacity(7 + self.dcid.len() + self.scid.len() + self.token.len());
        out.push(FORM_LONG | FIXED_BIT | LONG_RETRY);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.dcid.len() as u8);
        out.extend_from_slice(&self.dcid);
        out.push(self.scid.len() as u8);
        out.extend_from_slice(&self.scid);
        out.extend_from_slice(&self.token);
        Ok(out)
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut wire = self.encode_header()?;
        wire.extend_from_slice(&self.integrity_tag);
        Ok(wire)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let prefix = decode_long_prefix(input, LONG_RETRY)?;
        let pos = prefix.pos;
        let token_end = input
            .len()
            .checked_sub(16)
            .filter(|&end| pos <= end)
            .ok_or(DecodeError::Underflow)?;
        let token = input[pos..token_end].to_vec();
        let mut integrity_tag = [0u8; 16];
        integrity_tag.copy_from_slice(&input[token_end..]);
        Ok(Self {
            version: prefix.version,
            dcid: prefix.dcid.to_vec(),
            scid: prefix.scid.to_vec(),
            token,
            integrity_tag,
        })
    }

    pub fn compute_integrity_tag(&self, odcid: &[u8]) -> Result<[u8; 16], EncodeError> {
        Self::compute_tag(odcid, &self.encode_header()?)
    }

    pub fn verify_integrity(&self, odcid: &[u8]) -> bool {
        self.compute_integrity_tag(odcid)
            .is_ok_and(|expected| bool::from(self.integrity_tag[..].ct_eq(&expected[..])))
    }

    pub fn compute_tag(odcid: &[u8], retry_header: &[u8]) -> Result<[u8; 16], EncodeError> {
        use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
        if odcid.len() > MAX_CONNECTION_ID_LEN {
            return Err(EncodeError::CidTooLong);
        }
        let unbound = UnboundKey::new(&AES_128_GCM, &RETRY_INTEGRITY_KEY_V1)
            .map_err(|_| EncodeError::Crypto)?;
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE_V1);
        let mut aad = Vec::with_capacity(1 + odcid.len() + retry_header.len());
        aad.push(odcid.len() as u8);
        aad.extend_from_slice(odcid);
        aad.extend_from_slice(retry_header);
        let mut buf = Vec::new();
        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::from(&aad), &mut buf)
            .map_err(|_| EncodeError::Crypto)?;
        let mut out = [0u8; 16];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }
}
