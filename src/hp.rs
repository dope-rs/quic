use ring::aead::quic;

pub struct HpKey {
    inner: quic::HeaderProtectionKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpError {
    InvalidSample,
}

impl HpKey {
    pub fn aes_128(key: &[u8; 16]) -> Self {
        let inner = quic::HeaderProtectionKey::new(&quic::AES_128, key)
            .expect("AES-128 HP key length is fixed at 16");
        Self { inner }
    }

    pub fn mask(&self, sample: &[u8]) -> Result<[u8; 5], HpError> {
        self.inner
            .new_mask(sample)
            .map_err(|_| HpError::InvalidSample)
    }
}
