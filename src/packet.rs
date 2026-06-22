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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Underflow,
    NotLongHeader,
    UnsupportedVersion,
    BadCidLen,
    BadVarInt,
    BadType,
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
    pub fn encode_with_pn(&self, body_len_after_pn: usize) -> (Vec<u8>, usize) {
        assert!(matches!(self.pn_len, 1..=4), "pn_len must be 1..=4");
        let mut out = Vec::with_capacity(64 + self.dcid.len() + self.scid.len() + self.token.len());
        let first = FORM_LONG | FIXED_BIT | LONG_INITIAL | (self.pn_len - 1);
        out.push(first);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.dcid.len() as u8);
        out.extend_from_slice(&self.dcid);
        out.push(self.scid.len() as u8);
        out.extend_from_slice(&self.scid);
        VarInt::encode(self.token.len() as u64, &mut out).expect("token len fits");
        out.extend_from_slice(&self.token);
        let length_field = self.pn_len as u64 + body_len_after_pn as u64;
        VarInt::encode(length_field, &mut out).expect("length fits");
        let pn_offset = out.len();
        let pn_bytes = self.packet_number.to_be_bytes();
        out.extend_from_slice(&pn_bytes[8 - self.pn_len as usize..]);
        (out, pn_offset)
    }

    pub fn decode_pre_hp(input: &[u8]) -> Result<DecodedInitialPrefix, DecodeError> {
        if input.len() < 7 {
            return Err(DecodeError::Underflow);
        }
        let first = input[0];
        if first & FORM_LONG == 0 {
            return Err(DecodeError::NotLongHeader);
        }
        if first & LONG_TYPE_MASK != LONG_INITIAL {
            return Err(DecodeError::BadType);
        }
        let version = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);
        if version != QUIC_V1 {
            return Err(DecodeError::UnsupportedVersion);
        }
        let mut pos = 5;
        let dcid_len = input[pos] as usize;
        pos += 1;
        if input.len() < pos + dcid_len + 1 {
            return Err(DecodeError::Underflow);
        }
        let dcid = input[pos..pos + dcid_len].to_vec();
        pos += dcid_len;
        let scid_len = input[pos] as usize;
        pos += 1;
        if input.len() < pos + scid_len {
            return Err(DecodeError::Underflow);
        }
        let scid = input[pos..pos + scid_len].to_vec();
        pos += scid_len;
        let (token_len, n) = VarInt::decode(&input[pos..]).map_err(|_| DecodeError::BadVarInt)?;
        pos += n;
        if input.len() < pos + token_len as usize {
            return Err(DecodeError::Underflow);
        }
        let token = input[pos..pos + token_len as usize].to_vec();
        pos += token_len as usize;
        let (length, n) = VarInt::decode(&input[pos..]).map_err(|_| DecodeError::BadVarInt)?;
        pos += n;
        Ok(DecodedInitialPrefix {
            version,
            dcid,
            scid,
            token,
            pn_offset: pos,
            length: length as usize,
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
            _ => unreachable!("only 4 type values for 2 bits"),
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
    pub fn encode_with_pn(&self, body_len_after_pn: usize) -> (Vec<u8>, usize) {
        assert!(matches!(self.pn_len, 1..=4), "pn_len must be 1..=4");
        let mut out = Vec::with_capacity(32 + self.dcid.len() + self.scid.len());
        let first = FORM_LONG | FIXED_BIT | LONG_HANDSHAKE | (self.pn_len - 1);
        out.push(first);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.dcid.len() as u8);
        out.extend_from_slice(&self.dcid);
        out.push(self.scid.len() as u8);
        out.extend_from_slice(&self.scid);
        let length_field = self.pn_len as u64 + body_len_after_pn as u64;
        VarInt::encode(length_field, &mut out).expect("length fits");
        let pn_offset = out.len();
        let pn_bytes = self.packet_number.to_be_bytes();
        out.extend_from_slice(&pn_bytes[8 - self.pn_len as usize..]);
        (out, pn_offset)
    }

    pub fn decode_pre_hp(input: &[u8]) -> Result<DecodedHandshakePrefix, DecodeError> {
        if input.len() < 7 {
            return Err(DecodeError::Underflow);
        }
        let first = input[0];
        if first & FORM_LONG == 0 {
            return Err(DecodeError::NotLongHeader);
        }
        if first & LONG_TYPE_MASK != LONG_HANDSHAKE {
            return Err(DecodeError::BadType);
        }
        let version = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);
        if version != QUIC_V1 {
            return Err(DecodeError::UnsupportedVersion);
        }
        let mut pos = 5;
        let dcid_len = input[pos] as usize;
        pos += 1;
        if input.len() < pos + dcid_len + 1 {
            return Err(DecodeError::Underflow);
        }
        let dcid = input[pos..pos + dcid_len].to_vec();
        pos += dcid_len;
        let scid_len = input[pos] as usize;
        pos += 1;
        if input.len() < pos + scid_len {
            return Err(DecodeError::Underflow);
        }
        let scid = input[pos..pos + scid_len].to_vec();
        pos += scid_len;
        let (length, n) = VarInt::decode(&input[pos..]).map_err(|_| DecodeError::BadVarInt)?;
        pos += n;
        Ok(DecodedHandshakePrefix {
            version,
            dcid,
            scid,
            pn_offset: pos,
            length: length as usize,
        })
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
    pub fn encode_with_pn(&self, body_len_after_pn: usize) -> (Vec<u8>, usize) {
        assert!(matches!(self.pn_len, 1..=4), "pn_len must be 1..=4");
        let mut out = Vec::with_capacity(32 + self.dcid.len() + self.scid.len());
        let first = FORM_LONG | FIXED_BIT | LONG_ZERO_RTT | (self.pn_len - 1);
        out.push(first);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.dcid.len() as u8);
        out.extend_from_slice(&self.dcid);
        out.push(self.scid.len() as u8);
        out.extend_from_slice(&self.scid);
        let length_field = self.pn_len as u64 + body_len_after_pn as u64;
        VarInt::encode(length_field, &mut out).expect("length fits");
        let pn_offset = out.len();
        let pn_bytes = self.packet_number.to_be_bytes();
        out.extend_from_slice(&pn_bytes[8 - self.pn_len as usize..]);
        (out, pn_offset)
    }

    pub fn decode_pre_hp(input: &[u8]) -> Result<DecodedHandshakePrefix, DecodeError> {
        if input.len() < 7 {
            return Err(DecodeError::Underflow);
        }
        let first = input[0];
        if first & FORM_LONG == 0 {
            return Err(DecodeError::NotLongHeader);
        }
        if first & LONG_TYPE_MASK != LONG_ZERO_RTT {
            return Err(DecodeError::BadType);
        }
        let version = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);
        if version != QUIC_V1 {
            return Err(DecodeError::UnsupportedVersion);
        }
        let mut pos = 5;
        let dcid_len = input[pos] as usize;
        pos += 1;
        if input.len() < pos + dcid_len + 1 {
            return Err(DecodeError::Underflow);
        }
        let dcid = input[pos..pos + dcid_len].to_vec();
        pos += dcid_len;
        let scid_len = input[pos] as usize;
        pos += 1;
        if input.len() < pos + scid_len {
            return Err(DecodeError::Underflow);
        }
        let scid = input[pos..pos + scid_len].to_vec();
        pos += scid_len;
        let (length, n) = VarInt::decode(&input[pos..]).map_err(|_| DecodeError::BadVarInt)?;
        pos += n;
        Ok(DecodedHandshakePrefix {
            version,
            dcid,
            scid,
            pn_offset: pos,
            length: length as usize,
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
    pub fn encode_with_pn(&self) -> (Vec<u8>, usize) {
        assert!(matches!(self.pn_len, 1..=4), "pn_len must be 1..=4");
        let mut out = Vec::with_capacity(1 + self.dcid.len() + self.pn_len as usize);
        let first = FIXED_BIT | (self.pn_len - 1);
        out.push(first);
        out.extend_from_slice(&self.dcid);
        let pn_offset = out.len();
        let pn_bytes = self.packet_number.to_be_bytes();
        out.extend_from_slice(&pn_bytes[8 - self.pn_len as usize..]);
        (out, pn_offset)
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
    pub fn encode_header(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(7 + self.dcid.len() + self.scid.len() + self.token.len());
        out.push(FORM_LONG | FIXED_BIT | LONG_RETRY);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.dcid.len() as u8);
        out.extend_from_slice(&self.dcid);
        out.push(self.scid.len() as u8);
        out.extend_from_slice(&self.scid);
        out.extend_from_slice(&self.token);
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut wire = self.encode_header();
        wire.extend_from_slice(&self.integrity_tag);
        wire
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        if input.len() < 7 + 16 {
            return Err(DecodeError::Underflow);
        }
        let first = input[0];
        if first & FORM_LONG == 0 {
            return Err(DecodeError::NotLongHeader);
        }
        if first & LONG_TYPE_MASK != LONG_RETRY {
            return Err(DecodeError::BadType);
        }
        let version = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);
        if version != QUIC_V1 {
            return Err(DecodeError::UnsupportedVersion);
        }
        let mut pos = 5;
        let dcid_len = input[pos] as usize;
        pos += 1;
        if input.len() < pos + dcid_len + 1 {
            return Err(DecodeError::Underflow);
        }
        let dcid = input[pos..pos + dcid_len].to_vec();
        pos += dcid_len;
        let scid_len = input[pos] as usize;
        pos += 1;
        if input.len() < pos + scid_len + 16 {
            return Err(DecodeError::Underflow);
        }
        let scid = input[pos..pos + scid_len].to_vec();
        pos += scid_len;
        let token_end = input.len() - 16;
        if pos > token_end {
            return Err(DecodeError::Underflow);
        }
        let token = input[pos..token_end].to_vec();
        let mut integrity_tag = [0u8; 16];
        integrity_tag.copy_from_slice(&input[token_end..]);
        Ok(Self {
            version,
            dcid,
            scid,
            token,
            integrity_tag,
        })
    }

    pub fn compute_integrity_tag(&self, odcid: &[u8]) -> [u8; 16] {
        Self::compute_tag(odcid, &self.encode_header())
    }

    pub fn verify_integrity(&self, odcid: &[u8]) -> bool {
        let expected = self.compute_integrity_tag(odcid);
        bool::from(self.integrity_tag[..].ct_eq(&expected[..]))
    }

    pub fn compute_tag(odcid: &[u8], retry_header: &[u8]) -> [u8; 16] {
        use ring::aead;
        let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &RETRY_INTEGRITY_KEY_V1)
            .expect("16-byte AES-128-GCM key");
        let key = aead::LessSafeKey::new(unbound);
        let nonce = aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE_V1);
        let mut aad = Vec::with_capacity(1 + odcid.len() + retry_header.len());
        aad.push(odcid.len() as u8);
        aad.extend_from_slice(odcid);
        aad.extend_from_slice(retry_header);
        let mut buf = Vec::new();
        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(&aad), &mut buf)
            .expect("AES-128-GCM seal cannot fail");
        let mut out = [0u8; 16];
        out.copy_from_slice(tag.as_ref());
        out
    }
}
