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
        let mut buf = Vec::with_capacity(header_with_pn.len() + payload.len() + 16);
        buf.extend_from_slice(header_with_pn);
        let ct = self.aead.seal(packet_number, header_with_pn, payload);
        buf.extend_from_slice(&ct);

        let sample_start = pn_offset + 4;
        let mut sample = [0u8; 16];
        sample.copy_from_slice(&buf[sample_start..sample_start + 16]);
        let mask = self.hp.mask(&sample).expect("16-byte sample");

        buf[0] ^= mask[0] & 0x0f;
        for i in 0..pn_len {
            buf[pn_offset + i] ^= mask[1 + i];
        }
        buf
    }

    pub fn decrypt_long(
        &self,
        protected: &mut [u8],
        pn_offset: usize,
    ) -> Result<Vec<u8>, ProtectError> {
        self.decrypt_with_first_byte_mask(protected, pn_offset, 0x0f)
    }

    pub fn encrypt_short(
        &self,
        header_with_pn: &[u8],
        payload: &[u8],
        packet_number: u64,
        pn_offset: usize,
        pn_len: usize,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(header_with_pn.len() + payload.len() + 16);
        buf.extend_from_slice(header_with_pn);
        let ct = self.aead.seal(packet_number, header_with_pn, payload);
        buf.extend_from_slice(&ct);

        let sample_start = pn_offset + 4;
        let mut sample = [0u8; 16];
        sample.copy_from_slice(&buf[sample_start..sample_start + 16]);
        let mask = self.hp.mask(&sample).expect("16-byte sample");

        buf[0] ^= mask[0] & 0x1f;
        for i in 0..pn_len {
            buf[pn_offset + i] ^= mask[1 + i];
        }
        buf
    }

    pub fn decrypt_short(
        &self,
        protected: &mut [u8],
        pn_offset: usize,
    ) -> Result<Vec<u8>, ProtectError> {
        self.decrypt_with_first_byte_mask(protected, pn_offset, 0x1f)
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
