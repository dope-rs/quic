use std::{error, fmt, ops};

use subtle::ConstantTimeEq as _;

use crate::packet_protection;
use crate::varint;

pub const FORM_LONG: u8 = 0x80;
pub const FIXED_BIT: u8 = 0x40;
pub const LONG_TYPE_MASK: u8 = 0x30;
pub const LONG_INITIAL: u8 = 0x00;
pub const LONG_ZERO_RTT: u8 = 0x10;
pub const LONG_HANDSHAKE: u8 = 0x20;
pub const LONG_RETRY: u8 = 0x30;

pub const QUIC_V1: u32 = 0x0000_0001;
pub const MAX_CONNECTION_ID_LEN: usize = 20;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    bytes: [u8; MAX_CONNECTION_ID_LEN],
    len: u8,
}

impl ConnectionId {
    pub const MAX_LEN: usize = MAX_CONNECTION_ID_LEN;

    pub(crate) fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_CONNECTION_ID_LEN {
            return None;
        }
        Some(Self::from_validated(bytes))
    }

    fn from_validated(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= MAX_CONNECTION_ID_LEN);
        let mut cid = Self {
            bytes: [0; MAX_CONNECTION_ID_LEN],
            len: bytes.len() as u8,
        };
        cid.bytes[..bytes.len()].copy_from_slice(bytes);
        cid
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    pub const fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_ref_id(&self) -> ConnectionIdRef<'_> {
        ConnectionIdRef(self.as_slice())
    }
}

const _: () = assert!(std::mem::size_of::<ConnectionId>() == MAX_CONNECTION_ID_LEN + 1);

impl AsRef<[u8]> for ConnectionId {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl ops::Deref for ConnectionId {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl TryFrom<&[u8]> for ConnectionId {
    type Error = ConnectionIdError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::new(bytes).ok_or(ConnectionIdError::TooLong)
    }
}

impl TryFrom<Vec<u8>> for ConnectionId {
    type Error = ConnectionIdError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<const N: usize> TryFrom<[u8; N]> for ConnectionId {
    type Error = ConnectionIdError;

    fn try_from(bytes: [u8; N]) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl From<ConnectionId> for Vec<u8> {
    fn from(cid: ConnectionId) -> Self {
        cid.as_slice().to_vec()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionIdError {
    TooLong,
}

impl fmt::Display for ConnectionIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLong => "connection ID exceeds 20 bytes",
        })
    }
}

impl error::Error for ConnectionIdError {}

/// A validated connection ID borrowing its wire storage for exactly `'a`.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Hash)]
pub struct ConnectionIdRef<'a>(&'a [u8]);

impl<'a> ConnectionIdRef<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self, ConnectionIdError> {
        (bytes.len() <= MAX_CONNECTION_ID_LEN)
            .then_some(Self(bytes))
            .ok_or(ConnectionIdError::TooLong)
    }

    fn from_validated(bytes: &'a [u8]) -> Self {
        debug_assert!(bytes.len() <= MAX_CONNECTION_ID_LEN);
        Self(bytes)
    }

    pub const fn into_slice(self) -> &'a [u8] {
        self.0
    }

    pub const fn len(self) -> usize {
        self.0.len()
    }

    pub const fn is_empty(self) -> bool {
        self.0.is_empty()
    }

    pub fn into_owned(self) -> ConnectionId {
        ConnectionId::from_validated(self.0)
    }
}

impl AsRef<[u8]> for ConnectionIdRef<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl ops::Deref for ConnectionIdRef<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl PartialEq for ConnectionIdRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for ConnectionIdRef<'_> {}

impl<const N: usize> PartialEq<[u8; N]> for ConnectionIdRef<'_> {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.0 == other
    }
}

impl PartialEq<Vec<u8>> for ConnectionIdRef<'_> {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.0 == other.as_slice()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Underflow,
    NotLongHeader,
    UnsupportedVersion,
    BadCidLen,
    BadVarInt,
    BadType,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Underflow => "truncated packet header",
            Self::NotLongHeader => "expected a long packet header",
            Self::UnsupportedVersion => "unsupported QUIC version",
            Self::BadCidLen => "invalid connection ID length",
            Self::BadVarInt => "invalid packet integer",
            Self::BadType => "invalid packet type",
        })
    }
}

impl error::Error for DecodeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    InvalidPacketNumberLength,
    CidTooLong,
    ValueOutOfRange,
    Crypto,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPacketNumberLength => "invalid packet number length",
            Self::CidTooLong => "connection ID is too long",
            Self::ValueOutOfRange => "packet value is out of range",
            Self::Crypto => "packet cryptography failed",
        })
    }
}

impl error::Error for EncodeError {}

fn validate_header_fields(pn_len: u8, dcid: &[u8], scid: &[u8]) -> Result<(), EncodeError> {
    if !matches!(pn_len, 1..=4) {
        return Err(EncodeError::InvalidPacketNumberLength);
    }
    if dcid.len() > MAX_CONNECTION_ID_LEN || scid.len() > MAX_CONNECTION_ID_LEN {
        return Err(EncodeError::CidTooLong);
    }
    Ok(())
}

struct LongPrefix {
    version: u32,
    dcid: ops::Range<usize>,
    scid: ops::Range<usize>,
    pos: usize,
}

fn take_range(
    input: &[u8],
    pos: &mut usize,
    length: usize,
) -> Result<ops::Range<usize>, DecodeError> {
    let end = pos
        .checked_add(length)
        .filter(|&end| end <= input.len())
        .ok_or(DecodeError::Underflow)?;
    let value = *pos..end;
    *pos = end;
    Ok(value)
}

fn take_connection_id(input: &[u8], pos: &mut usize) -> Result<ops::Range<usize>, DecodeError> {
    let length = usize::from(*input.get(*pos).ok_or(DecodeError::Underflow)?);
    *pos += 1;
    if length > MAX_CONNECTION_ID_LEN {
        return Err(DecodeError::BadCidLen);
    }
    take_range(input, pos, length)
}

fn decode_long_prefix(input: &[u8], packet_type: u8) -> Result<LongPrefix, DecodeError> {
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
    let (length, consumed) =
        varint::VarInt::decode(&input[*pos..]).map_err(|_| DecodeError::BadVarInt)?;
    *pos += consumed;
    usize::try_from(length.get()).map_err(|_| DecodeError::BadVarInt)
}

#[derive(Clone)]
struct LongLayout {
    version: u32,
    kind: LongType,
    dcid: ops::Range<usize>,
    scid: ops::Range<usize>,
    token: Option<ops::Range<usize>>,
    pn_offset: usize,
    length: usize,
    packet_len: usize,
}

struct ProtectedLongLayout {
    kind: LongType,
    scid_start: u8,
    scid_len: u8,
    pn_offset: usize,
    packet_len: usize,
}

const _: () = assert!(std::mem::size_of::<ProtectedLongLayout>() <= 24);

fn decode_long_layout(input: &[u8], kind: LongType) -> Result<LongLayout, DecodeError> {
    let packet_type = match kind {
        LongType::Initial => LONG_INITIAL,
        LongType::ZeroRtt => LONG_ZERO_RTT,
        LongType::Handshake => LONG_HANDSHAKE,
        LongType::Retry => return Err(DecodeError::BadType),
    };
    let prefix = decode_long_prefix(input, packet_type)?;
    let mut pos = prefix.pos;
    let token = if kind == LongType::Initial {
        let token_len = decode_length(input, &mut pos)?;
        Some(take_range(input, &mut pos, token_len)?)
    } else {
        None
    };
    let length = decode_length(input, &mut pos)?;
    let packet_len = pos.checked_add(length).ok_or(DecodeError::Underflow)?;
    Ok(LongLayout {
        version: prefix.version,
        kind,
        dcid: prefix.dcid,
        scid: prefix.scid,
        token,
        pn_offset: pos,
        length,
        packet_len,
    })
}

/// Mutable packet storage that can preserve its owner while a coalesced QUIC
/// datagram is split into individually protected long-header packets.
pub(crate) trait LongBuffer: AsRef<[u8]> + AsMut<[u8]> + Sized {
    fn split_at(self, mid: usize) -> Option<(Self, Self)>;
}

impl LongBuffer for &mut [u8] {
    fn split_at(self, mid: usize) -> Option<(Self, Self)> {
        (mid <= self.len()).then(|| self.split_at_mut(mid))
    }
}

impl<'turn, 'd> LongBuffer for dope::manifold::datagram::packet::Split<'turn, 'd> {
    fn split_at(self, mid: usize) -> Option<(Self, Self)> {
        dope::manifold::datagram::packet::Split::split_at(self, mid).ok()
    }
}

/// A validated long-header layout inseparably bound to the packet it describes.
///
/// Parsing owns `packet` for the lifetime of this value. Decryption consumes the
/// value, so no header borrow can overlap the in-place packet mutation.
pub(crate) struct ParsedLong<P> {
    packet: P,
    layout: ProtectedLongLayout,
}

impl<P: AsRef<[u8]>> ParsedLong<P> {
    pub(crate) fn parse(packet: P) -> Result<Self, DecodeError> {
        let input = packet.as_ref();
        let first = *input.first().ok_or(DecodeError::Underflow)?;
        let kind = LongType::from_first_byte(first)?;
        let decoded = decode_long_layout(input, kind)?;
        if decoded.packet_len > input.len() {
            return Err(DecodeError::Underflow);
        }
        debug_assert!(decoded.scid.end <= u8::MAX as usize);
        let layout = ProtectedLongLayout {
            kind: decoded.kind,
            scid_start: decoded.scid.start as u8,
            scid_len: decoded.scid.len() as u8,
            pn_offset: decoded.pn_offset,
            packet_len: decoded.packet_len,
        };
        Ok(Self { packet, layout })
    }

    pub(crate) fn kind(&self) -> LongType {
        self.layout.kind
    }

    pub(crate) fn scid(&self) -> ConnectionId {
        let start = usize::from(self.layout.scid_start);
        let end = start + usize::from(self.layout.scid_len);
        ConnectionId::from_validated(&self.packet.as_ref()[start..end])
    }
}

impl<P: LongBuffer> ParsedLong<P> {
    pub(crate) fn split_first(self) -> Result<(Self, P), DecodeError> {
        let packet_len = self.layout.packet_len;
        let (packet, tail) = self
            .packet
            .split_at(packet_len)
            .ok_or(DecodeError::Underflow)?;
        debug_assert_eq!(packet.as_ref().len(), packet_len);
        Ok((
            Self {
                packet,
                layout: self.layout,
            },
            tail,
        ))
    }
}

impl<P: AsRef<[u8]> + AsMut<[u8]>> ParsedLong<P> {
    pub(crate) fn decrypt(
        mut self,
        protection: &packet_protection::PacketProtection,
        expected_packet_number: u64,
    ) -> Result<DecryptedLong<P>, packet_protection::CryptoFailure> {
        let (packet_number, body) = protection.decrypt_long_in_place(
            self.packet.as_mut(),
            self.layout.pn_offset,
            expected_packet_number,
        )?;
        Ok(DecryptedLong {
            packet: self.packet,
            packet_number,
            body,
        })
    }
}

pub(crate) struct DecryptedLong<P> {
    packet: P,
    packet_number: u64,
    body: ops::Range<usize>,
}

impl<P: AsRef<[u8]>> DecryptedLong<P> {
    pub(crate) fn packet_number(&self) -> u64 {
        self.packet_number
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.packet.as_ref()[self.body.clone()]
    }

    pub(crate) fn into_parts(self) -> (u64, P, ops::Range<usize>) {
        (self.packet_number, self.packet, self.body)
    }
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
            .filter(|&length| length <= varint::VarInt::MAX)
            .ok_or(EncodeError::ValueOutOfRange)?;
        out.push(FORM_LONG | FIXED_BIT | self.packet_type | (self.packet_number_len - 1));
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.dcid.len() as u8);
        out.extend_from_slice(self.dcid);
        out.push(self.scid.len() as u8);
        out.extend_from_slice(self.scid);
        if let Some(token) = self.token {
            let token_len =
                varint::VarInt::from_usize(token.len()).ok_or(EncodeError::ValueOutOfRange)?;
            token_len.encode(out);
            out.extend_from_slice(token);
        }
        varint::VarInt::new(length)
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

    pub fn decode_pre_hp(input: &[u8]) -> Result<DecodedInitialPrefix<'_>, DecodeError> {
        let layout = decode_long_layout(input, LongType::Initial)?;
        let Some(token) = layout.token else {
            return Err(DecodeError::BadType);
        };
        Ok(DecodedInitialPrefix {
            version: layout.version,
            dcid: ConnectionIdRef::from_validated(&input[layout.dcid]),
            scid: ConnectionIdRef::from_validated(&input[layout.scid]),
            token: &input[token],
            pn_offset: layout.pn_offset,
            length: layout.length,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedInitialPrefix<'a> {
    pub version: u32,
    pub dcid: ConnectionIdRef<'a>,
    pub scid: ConnectionIdRef<'a>,
    pub token: &'a [u8],
    pub pn_offset: usize,
    pub length: usize,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    pub fn decode_pre_hp(input: &[u8]) -> Result<DecodedHandshakePrefix<'_>, DecodeError> {
        let layout = decode_long_layout(input, LongType::Handshake)?;
        Ok(DecodedHandshakePrefix {
            version: layout.version,
            dcid: ConnectionIdRef::from_validated(&input[layout.dcid]),
            scid: ConnectionIdRef::from_validated(&input[layout.scid]),
            pn_offset: layout.pn_offset,
            length: layout.length,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedHandshakePrefix<'a> {
    pub version: u32,
    pub dcid: ConnectionIdRef<'a>,
    pub scid: ConnectionIdRef<'a>,
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

    pub fn decode_pre_hp(input: &[u8]) -> Result<DecodedHandshakePrefix<'_>, DecodeError> {
        let layout = decode_long_layout(input, LongType::ZeroRtt)?;
        Ok(DecodedHandshakePrefix {
            version: layout.version,
            dcid: ConnectionIdRef::from_validated(&input[layout.dcid]),
            scid: ConnectionIdRef::from_validated(&input[layout.scid]),
            pn_offset: layout.pn_offset,
            length: layout.length,
        })
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
pub struct Retry {
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub integrity_tag: [u8; RETRY_INTEGRITY_TAG_LEN],
}

pub const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
pub const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];
pub const RETRY_INTEGRITY_TAG_LEN: usize = 16;

/// A structurally valid Retry packet borrowing the exact received wire bytes.
///
/// Its fields remain untrusted until [`RetryRef::verify_into`] succeeds.
#[derive(Debug, Clone, Copy)]
pub struct RetryRef<'wire> {
    version: u32,
    dcid: ConnectionIdRef<'wire>,
    scid: ConnectionIdRef<'wire>,
    token: &'wire [u8],
    header: &'wire [u8],
    integrity_tag: &'wire [u8; RETRY_INTEGRITY_TAG_LEN],
}

/// A Retry packet whose destination binding and integrity tag were verified.
pub struct VerifiedRetry<'wire, 'storage> {
    scid: ConnectionIdRef<'wire>,
    token: &'storage [u8],
}

impl<'wire> RetryRef<'wire> {
    pub fn decode(input: &'wire [u8]) -> Result<Self, DecodeError> {
        let prefix = decode_long_prefix(input, LONG_RETRY)?;
        let token_start = prefix.pos;
        let header_end = input
            .len()
            .checked_sub(RETRY_INTEGRITY_TAG_LEN)
            .filter(|&end| token_start <= end)
            .ok_or(DecodeError::Underflow)?;
        let integrity_tag = input[header_end..]
            .try_into()
            .map_err(|_| DecodeError::Underflow)?;
        Ok(Self {
            version: prefix.version,
            dcid: ConnectionIdRef::from_validated(&input[prefix.dcid]),
            scid: ConnectionIdRef::from_validated(&input[prefix.scid]),
            token: &input[token_start..header_end],
            header: &input[..header_end],
            integrity_tag,
        })
    }

    pub const fn version(self) -> u32 {
        self.version
    }

    pub const fn destination_connection_id(self) -> ConnectionIdRef<'wire> {
        self.dcid
    }

    pub const fn source_connection_id(self) -> ConnectionIdRef<'wire> {
        self.scid
    }

    pub const fn token(self) -> &'wire [u8] {
        self.token
    }

    pub const fn integrity_tag(self) -> &'wire [u8; RETRY_INTEGRITY_TAG_LEN] {
        self.integrity_tag
    }

    /// Verifies the Retry and promotes its token into `storage`.
    ///
    /// `storage` is used first as the contiguous AES-GCM AAD buffer and then
    /// compacted in place to the token bytes. Starting from an empty `Vec`, the
    /// complete receive path therefore performs at most the one allocation
    /// required to retain an arbitrary-length token beyond `'wire`.
    pub fn verify_into<'storage>(
        self,
        original_dcid: ConnectionIdRef<'_>,
        expected_dcid: ConnectionIdRef<'_>,
        storage: &'storage mut Vec<u8>,
    ) -> Result<Option<VerifiedRetry<'wire, 'storage>>, EncodeError> {
        storage.clear();
        if self.dcid.into_slice() != expected_dcid.into_slice() {
            return Ok(None);
        }

        let prefix_len = 1usize
            .checked_add(original_dcid.len())
            .ok_or(EncodeError::ValueOutOfRange)?;
        let aad_len = prefix_len
            .checked_add(self.header.len())
            .ok_or(EncodeError::ValueOutOfRange)?;
        storage.reserve_exact(aad_len);
        storage.push(original_dcid.len() as u8);
        storage.extend_from_slice(original_dcid.into_slice());
        storage.extend_from_slice(self.header);

        let expected = Retry::tag_from_aad(storage)?;
        if !bool::from(self.integrity_tag[..].ct_eq(&expected[..])) {
            storage.clear();
            return Ok(None);
        }

        let token_len = self.token.len();
        let token_start = aad_len - token_len;
        storage.copy_within(token_start..aad_len, 0);
        storage.truncate(token_len);
        Ok(Some(VerifiedRetry {
            scid: self.scid,
            token: storage.as_slice(),
        }))
    }
}

impl<'wire, 'storage> VerifiedRetry<'wire, 'storage> {
    pub const fn source_connection_id(&self) -> ConnectionIdRef<'wire> {
        self.scid
    }

    pub const fn token(&self) -> &'storage [u8] {
        self.token
    }
}

impl Retry {
    pub(crate) const fn prefix_len(dcid: ConnectionIdRef<'_>, scid: ConnectionIdRef<'_>) -> usize {
        7 + dcid.len() + scid.len()
    }

    pub(crate) fn encode_prefix_into(
        out: &mut Vec<u8>,
        version: u32,
        dcid: ConnectionIdRef<'_>,
        scid: ConnectionIdRef<'_>,
    ) {
        out.push(FORM_LONG | FIXED_BIT | LONG_RETRY);
        out.extend_from_slice(&version.to_be_bytes());
        out.push(dcid.len() as u8);
        out.extend_from_slice(dcid.into_slice());
        out.push(scid.len() as u8);
        out.extend_from_slice(scid.into_slice());
    }

    pub fn encode_header(&self) -> Result<Vec<u8>, EncodeError> {
        validate_header_fields(1, &self.dcid, &self.scid)?;
        let dcid = ConnectionIdRef::from_validated(&self.dcid);
        let scid = ConnectionIdRef::from_validated(&self.scid);
        let mut out = Vec::with_capacity(Self::prefix_len(dcid, scid) + self.token.len());
        Self::encode_prefix_into(&mut out, self.version, dcid, scid);
        out.extend_from_slice(&self.token);
        Ok(out)
    }

    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut wire = self.encode_header()?;
        wire.extend_from_slice(&self.integrity_tag);
        Ok(wire)
    }

    pub fn compute_integrity_tag(
        &self,
        odcid: &[u8],
    ) -> Result<[u8; RETRY_INTEGRITY_TAG_LEN], EncodeError> {
        Self::compute_tag(odcid, &self.encode_header()?)
    }

    pub fn compute_tag(
        odcid: &[u8],
        retry_header: &[u8],
    ) -> Result<[u8; RETRY_INTEGRITY_TAG_LEN], EncodeError> {
        if odcid.len() > MAX_CONNECTION_ID_LEN {
            return Err(EncodeError::CidTooLong);
        }
        let mut aad = Vec::with_capacity(1 + odcid.len() + retry_header.len());
        aad.push(odcid.len() as u8);
        aad.extend_from_slice(odcid);
        aad.extend_from_slice(retry_header);
        Self::tag_from_aad(&aad)
    }

    pub(crate) fn tag_from_aad(aad: &[u8]) -> Result<[u8; RETRY_INTEGRITY_TAG_LEN], EncodeError> {
        use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
        let unbound = UnboundKey::new(&AES_128_GCM, &RETRY_INTEGRITY_KEY_V1)
            .map_err(|_| EncodeError::Crypto)?;
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE_V1);
        let mut empty = [];
        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::from(aad), &mut empty)
            .map_err(|_| EncodeError::Crypto)?;
        let mut out = [0u8; RETRY_INTEGRITY_TAG_LEN];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }
}
