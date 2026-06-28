use shin::aead::{AeadError, AeadKey};

use crate::hp::HpKey;
use crate::qkdf::PacketKeys;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectError {
    Open,
    Hp,
}

pub struct PacketProtection {
    aead: AeadKey,
    hp: HpKey,
}

/// Header-protection masks for the first byte (RFC 9001 §5.4.1): long headers
/// protect the low 4 bits, short headers the low 5 (the spin bit included).
const LONG_HEADER_MASK: u8 = 0x0f;
const SHORT_HEADER_MASK: u8 = 0x1f;

impl PacketProtection {
    pub fn aes_128(keys: &PacketKeys) -> Self {
        Self {
            aead: AeadKey::aes_128_gcm(&keys.key, keys.iv),
            hp: HpKey::aes_128(&keys.hp),
        }
    }

    pub fn encrypt_long(
        &self,
        header_with_pn: &[u8],
        payload: &[u8],
        packet_number: u64,
        pn_offset: usize,
        pn_len: usize,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encrypt_long_into(&mut buf, header_with_pn, payload, packet_number, pn_offset, pn_len);
        buf
    }

    pub fn encrypt_long_into(
        &self,
        dst: &mut Vec<u8>,
        header_with_pn: &[u8],
        payload: &[u8],
        packet_number: u64,
        pn_offset: usize,
        pn_len: usize,
    ) -> usize {
        self.encrypt_into(
            dst,
            header_with_pn,
            payload,
            packet_number,
            pn_offset,
            pn_len,
            LONG_HEADER_MASK,
        )
    }

    pub fn decrypt_long(
        &self,
        protected: &mut [u8],
        pn_offset: usize,
    ) -> Result<Vec<u8>, ProtectError> {
        self.decrypt_with_first_byte_mask(protected, pn_offset, LONG_HEADER_MASK)
    }

    pub fn encrypt_short(
        &self,
        header_with_pn: &[u8],
        payload: &[u8],
        packet_number: u64,
        pn_offset: usize,
        pn_len: usize,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encrypt_short_into(&mut buf, header_with_pn, payload, packet_number, pn_offset, pn_len);
        buf
    }

    pub fn encrypt_short_into(
        &self,
        dst: &mut Vec<u8>,
        header_with_pn: &[u8],
        payload: &[u8],
        packet_number: u64,
        pn_offset: usize,
        pn_len: usize,
    ) -> usize {
        self.encrypt_into(
            dst,
            header_with_pn,
            payload,
            packet_number,
            pn_offset,
            pn_len,
            SHORT_HEADER_MASK,
        )
    }

    /// Seals the payload in place (AAD = header) and applies header protection,
    /// appending one wire packet to `dst`. Returns the packet's byte length, so
    /// callers can coalesce a burst into one buffer and recover segment bounds.
    #[allow(clippy::too_many_arguments)]
    fn encrypt_into(
        &self,
        dst: &mut Vec<u8>,
        header_with_pn: &[u8],
        payload: &[u8],
        packet_number: u64,
        pn_offset: usize,
        pn_len: usize,
        first_byte_mask: u8,
    ) -> usize {
        let start = dst.len();
        let hdr_len = header_with_pn.len();
        dst.reserve(hdr_len + payload.len() + 16);
        dst.extend_from_slice(header_with_pn);
        dst.extend_from_slice(payload);
        let tag = self
            .aead
            .seal_detached(packet_number, header_with_pn, &mut dst[start + hdr_len..]);
        dst.extend_from_slice(&tag);

        let sample_start = start + pn_offset + 4;
        let mut sample = [0u8; 16];
        sample.copy_from_slice(&dst[sample_start..sample_start + 16]);
        let mask = self.hp.mask(&sample).expect("16-byte sample");

        dst[start] ^= mask[0] & first_byte_mask;
        for i in 0..pn_len {
            dst[start + pn_offset + i] ^= mask[1 + i];
        }
        dst.len() - start
    }

    pub fn decrypt_short(
        &self,
        protected: &mut [u8],
        pn_offset: usize,
    ) -> Result<Vec<u8>, ProtectError> {
        self.decrypt_with_first_byte_mask(protected, pn_offset, SHORT_HEADER_MASK)
    }

    fn decrypt_with_first_byte_mask(
        &self,
        protected: &mut [u8],
        pn_offset: usize,
        first_byte_mask: u8,
    ) -> Result<Vec<u8>, ProtectError> {
        let sample_start = pn_offset + 4;
        let mut sample = [0u8; 16];
        sample.copy_from_slice(&protected[sample_start..sample_start + 16]);
        let mask = self.hp.mask(&sample).map_err(|_| ProtectError::Hp)?;

        protected[0] ^= mask[0] & first_byte_mask;
        let pn_len = ((protected[0] & 0x03) + 1) as usize;
        let mut pn = 0u64;
        for i in 0..pn_len {
            protected[pn_offset + i] ^= mask[1 + i];
            pn = (pn << 8) | (protected[pn_offset + i] as u64);
        }

        let body_start = pn_offset + pn_len;
        let header = protected[..body_start].to_vec();
        let body = &mut protected[body_start..];
        let plaintext = self.aead.open(pn, &header, body).map_err(|e: AeadError| {
            let _ = e;
            ProtectError::Open
        })?;
        Ok(plaintext.to_vec())
    }
}
