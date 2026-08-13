use ring::aead::quic;

pub(crate) struct HeaderProtectionKey {
    inner: quic::HeaderProtectionKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderProtectionError {
    InvalidKey,
    InvalidSample,
}

impl_error!(HeaderProtectionError {
    Self::InvalidKey => "invalid header protection key",
    Self::InvalidSample => "invalid header protection sample",
});

impl HeaderProtectionKey {
    pub fn aes_128(key: &[u8; 16]) -> Result<Self, HeaderProtectionError> {
        let inner = quic::HeaderProtectionKey::new(&quic::AES_128, key)
            .map_err(|_| HeaderProtectionError::InvalidKey)?;
        Ok(Self { inner })
    }

    pub fn mask(&self, sample: &[u8]) -> Result<[u8; 5], HeaderProtectionError> {
        self.inner
            .new_mask(sample)
            .map_err(|_| HeaderProtectionError::InvalidSample)
    }
}
