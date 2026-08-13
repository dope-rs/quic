use std::ops;

use shin::crypto::aead;

use crate::hp;
use crate::qkdf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoFailure {
    InvalidKey,
    Encrypt,
    InvalidPacket,
    Decrypt,
    HeaderProtection,
}

impl_error!(CryptoFailure {
    Self::InvalidKey => "invalid packet protection key",
    Self::Encrypt => "packet encryption failed",
    Self::InvalidPacket => "invalid protected packet",
    Self::Decrypt => "packet decryption failed",
    Self::HeaderProtection => "header protection failed",
});

pub struct PacketProtection {
    aead: aead::Key,
    hp: hp::HeaderProtectionKey,
}

const LONG_HEADER_MASK: u8 = 0x0f;
const SHORT_HEADER_MASK: u8 = 0x1f;
const MAX_PACKET_NUMBER: u64 = (1 << 62) - 1;

impl PacketProtection {
    pub fn aes_128(keys: &qkdf::PacketKeys) -> Result<Self, CryptoFailure> {
        Ok(Self {
            aead: aead::Key::aes_128_gcm(&keys.key, keys.iv)
                .map_err(|_| CryptoFailure::InvalidKey)?,
            hp: hp::HeaderProtectionKey::aes_128(&keys.hp)
                .map_err(|_| CryptoFailure::InvalidKey)?,
        })
    }

    pub fn encrypt_long(
        &self,
        header_with_pn: &[u8],
        payload: &[u8],
        packet_number: u64,
        pn_offset: usize,
        pn_len: usize,
    ) -> Result<Vec<u8>, CryptoFailure> {
        let mut buf = Vec::new();
        self.encrypt_long_into(
            &mut buf,
            header_with_pn,
            payload,
            packet_number,
            pn_offset,
            pn_len,
        )?;
        Ok(buf)
    }

    pub fn encrypt_long_into(
        &self,
        dst: &mut Vec<u8>,
        header_with_pn: &[u8],
        payload: &[u8],
        packet_number: u64,
        pn_offset: usize,
        pn_len: usize,
    ) -> Result<usize, CryptoFailure> {
        let pn_end = pn_offset
            .checked_add(pn_len)
            .ok_or(CryptoFailure::InvalidPacket)?;
        self.encrypt_into(
            dst,
            header_with_pn,
            payload,
            packet_number,
            pn_offset..pn_end,
            LONG_HEADER_MASK,
        )
    }

    pub fn decrypt_long(
        &self,
        protected: &mut [u8],
        pn_offset: usize,
    ) -> Result<Vec<u8>, CryptoFailure> {
        let (_, plaintext) = self.decrypt_long_in_place(protected, pn_offset, 0)?;
        Ok(protected[plaintext].to_vec())
    }

    pub fn decrypt_long_in_place(
        &self,
        protected: &mut [u8],
        pn_offset: usize,
        expected_packet_number: u64,
    ) -> Result<(u64, ops::Range<usize>), CryptoFailure> {
        self.decrypt_in_place(
            protected,
            pn_offset,
            expected_packet_number,
            LONG_HEADER_MASK,
        )
    }

    pub fn encrypt_short(
        &self,
        header_with_pn: &[u8],
        payload: &[u8],
        packet_number: u64,
        pn_offset: usize,
        pn_len: usize,
    ) -> Result<Vec<u8>, CryptoFailure> {
        let mut buf = Vec::new();
        self.encrypt_short_into(
            &mut buf,
            header_with_pn,
            payload,
            packet_number,
            pn_offset,
            pn_len,
        )?;
        Ok(buf)
    }

    pub fn encrypt_short_into(
        &self,
        dst: &mut Vec<u8>,
        header_with_pn: &[u8],
        payload: &[u8],
        packet_number: u64,
        pn_offset: usize,
        pn_len: usize,
    ) -> Result<usize, CryptoFailure> {
        let pn_end = pn_offset
            .checked_add(pn_len)
            .ok_or(CryptoFailure::InvalidPacket)?;
        self.encrypt_into(
            dst,
            header_with_pn,
            payload,
            packet_number,
            pn_offset..pn_end,
            SHORT_HEADER_MASK,
        )
    }

    pub fn protect_short_in_place(
        &self,
        dst: &mut Vec<u8>,
        packet_start: usize,
        payload_start: usize,
        packet_number: u64,
        pn_offset: usize,
        pn_len: usize,
    ) -> Result<usize, CryptoFailure> {
        let pn_end = pn_offset
            .checked_add(pn_len)
            .ok_or(CryptoFailure::InvalidPacket)?;
        if packet_start >= payload_start
            || payload_start > dst.len()
            || pn_len == 0
            || pn_len > 4
            || pn_offset < packet_start
            || pn_end > payload_start
        {
            return Err(CryptoFailure::InvalidPacket);
        }

        let tag = {
            let (header, payload) = dst.split_at_mut(payload_start);
            self.aead
                .seal_detached(packet_number, &header[packet_start..payload_start], payload)
                .map_err(|_| CryptoFailure::Encrypt)?
        };
        dst.extend_from_slice(&tag);

        let sample_start = pn_offset
            .checked_add(4)
            .ok_or(CryptoFailure::InvalidPacket)?;
        let sample_end = sample_start
            .checked_add(16)
            .ok_or(CryptoFailure::InvalidPacket)?;
        let mut sample = [0u8; 16];
        sample.copy_from_slice(
            dst.get(sample_start..sample_end)
                .ok_or(CryptoFailure::InvalidPacket)?,
        );
        let mask = self
            .hp
            .mask(&sample)
            .map_err(|_| CryptoFailure::HeaderProtection)?;

        dst[packet_start] ^= mask[0] & SHORT_HEADER_MASK;
        for (index, byte) in dst[pn_offset..pn_end].iter_mut().enumerate() {
            *byte ^= mask[1 + index];
        }
        Ok(dst.len() - packet_start)
    }

    fn encrypt_into(
        &self,
        dst: &mut Vec<u8>,
        header_with_pn: &[u8],
        payload: &[u8],
        packet_number: u64,
        packet_number_range: ops::Range<usize>,
        first_byte_mask: u8,
    ) -> Result<usize, CryptoFailure> {
        let start = dst.len();
        let hdr_len = header_with_pn.len();
        let pn_len = packet_number_range
            .end
            .checked_sub(packet_number_range.start)
            .ok_or(CryptoFailure::InvalidPacket)?;
        if pn_len == 0 || pn_len > 4 || packet_number_range.end > hdr_len {
            return Err(CryptoFailure::InvalidPacket);
        }
        dst.reserve(hdr_len + payload.len() + 16);
        dst.extend_from_slice(header_with_pn);
        dst.extend_from_slice(payload);
        let tag = self
            .aead
            .seal_detached(packet_number, header_with_pn, &mut dst[start + hdr_len..])
            .map_err(|_| CryptoFailure::Encrypt)?;
        dst.extend_from_slice(&tag);

        let sample_start = start
            .checked_add(packet_number_range.start)
            .and_then(|offset| offset.checked_add(4))
            .ok_or(CryptoFailure::InvalidPacket)?;
        let sample_end = sample_start
            .checked_add(16)
            .ok_or(CryptoFailure::InvalidPacket)?;
        let mut sample = [0u8; 16];
        sample.copy_from_slice(
            dst.get(sample_start..sample_end)
                .ok_or(CryptoFailure::InvalidPacket)?,
        );
        let mask = self
            .hp
            .mask(&sample)
            .map_err(|_| CryptoFailure::HeaderProtection)?;

        let first = dst.get_mut(start).ok_or(CryptoFailure::InvalidPacket)?;
        *first ^= mask[0] & first_byte_mask;
        for (index, byte) in dst[start + packet_number_range.start..start + packet_number_range.end]
            .iter_mut()
            .enumerate()
        {
            *byte ^= mask[1 + index];
        }
        Ok(dst.len() - start)
    }

    pub fn decrypt_short(
        &self,
        protected: &mut [u8],
        pn_offset: usize,
    ) -> Result<Vec<u8>, CryptoFailure> {
        let (_, plaintext) = self.decrypt_short_in_place(protected, pn_offset, 0)?;
        Ok(protected[plaintext].to_vec())
    }

    pub fn decrypt_short_in_place(
        &self,
        protected: &mut [u8],
        pn_offset: usize,
        expected_packet_number: u64,
    ) -> Result<(u64, ops::Range<usize>), CryptoFailure> {
        self.decrypt_in_place(
            protected,
            pn_offset,
            expected_packet_number,
            SHORT_HEADER_MASK,
        )
    }

    fn decrypt_in_place(
        &self,
        protected: &mut [u8],
        pn_offset: usize,
        expected_packet_number: u64,
        first_byte_mask: u8,
    ) -> Result<(u64, ops::Range<usize>), CryptoFailure> {
        let sample_start = pn_offset
            .checked_add(4)
            .ok_or(CryptoFailure::InvalidPacket)?;
        let sample_end = sample_start
            .checked_add(16)
            .ok_or(CryptoFailure::InvalidPacket)?;
        let mut sample = [0u8; 16];
        sample.copy_from_slice(
            protected
                .get(sample_start..sample_end)
                .ok_or(CryptoFailure::InvalidPacket)?,
        );
        let mask = self
            .hp
            .mask(&sample)
            .map_err(|_| CryptoFailure::HeaderProtection)?;

        let first = protected.first_mut().ok_or(CryptoFailure::InvalidPacket)?;
        *first ^= mask[0] & first_byte_mask;
        let pn_len = ((*first & 0x03) + 1) as usize;
        let pn_end = pn_offset
            .checked_add(pn_len)
            .ok_or(CryptoFailure::InvalidPacket)?;
        let pn_bytes = protected
            .get_mut(pn_offset..pn_end)
            .ok_or(CryptoFailure::InvalidPacket)?;
        let mut truncated = 0u64;
        for (index, byte) in pn_bytes.iter_mut().enumerate() {
            *byte ^= mask[1 + index];
            truncated = (truncated << 8) | u64::from(*byte);
        }

        let packet_number = decode_packet_number(expected_packet_number, truncated, pn_len);
        let (header, body) = protected.split_at_mut(pn_end);
        let plaintext_len = self
            .aead
            .open(packet_number, header, body)
            .map_err(|_| CryptoFailure::Decrypt)?
            .len();
        Ok((packet_number, pn_end..pn_end + plaintext_len))
    }
}

fn decode_packet_number(expected: u64, truncated: u64, encoded_len: usize) -> u64 {
    let window = 1u64 << (encoded_len * 8);
    let half_window = window / 2;
    let mask = window - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate <= MAX_PACKET_NUMBER - window && candidate.saturating_add(half_window) <= expected
    {
        candidate + window
    } else if candidate > expected.saturating_add(half_window) && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}
