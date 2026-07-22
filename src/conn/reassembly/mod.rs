use super::ConnError;
use crate::range_buffer::{MAX_RANGES, RangeBuffer};

const MAX_CRYPTO_BUFFERED: usize = 64 * 1024;

#[derive(Default)]
pub(super) struct CryptoReassembly {
    fragments: RangeBuffer,
    pending: Vec<u8>,
}

impl CryptoReassembly {
    pub(super) fn accept(&mut self, offset: u64, data: &[u8]) -> Result<Vec<Vec<u8>>, ConnError> {
        let available = MAX_CRYPTO_BUFFERED.saturating_sub(self.pending.len());
        self.fragments
            .insert(offset, data, available, MAX_RANGES)
            .map_err(|_| ConnError::CryptoBufferExceeded)?;
        self.fragments.drain_contiguous_into(&mut self.pending);
        let mut out = Vec::new();
        loop {
            if self.pending.len() < 4 {
                break;
            }
            let len =
                u32::from_be_bytes([0, self.pending[1], self.pending[2], self.pending[3]]) as usize;
            let total = 4 + len;
            if total > MAX_CRYPTO_BUFFERED {
                return Err(ConnError::CryptoBufferExceeded);
            }
            if self.pending.len() < total {
                break;
            }
            out.push(self.pending.drain(..total).collect());
        }
        if self.pending.len() > MAX_CRYPTO_BUFFERED {
            return Err(ConnError::CryptoBufferExceeded);
        }
        Ok(out)
    }
}
