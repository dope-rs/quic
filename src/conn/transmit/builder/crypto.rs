use crate::conn::{Epoch, commit, delivery};
use crate::varint::VarInt;

use super::Builder;
use crate::stream::ReceiveBuffer;

pub(in crate::conn) trait Crypto {
    fn crypto_data_limit(offset: u64, frame_room: usize) -> usize;
    fn peek_crypto_chunk(
        tx: &crate::conn::crypto_tx::Tx,
        epoch: Epoch,
        frame_room: usize,
    ) -> Option<(commit::Delivery<delivery::Crypto>, &[u8])>;
    fn encode_crypto(out: &mut Vec<u8>, offset: u64, data: &[u8]) -> bool;
    fn crypto_probe(
        &self,
        epoch: Epoch,
        frame_room: usize,
    ) -> Option<(commit::Delivery<delivery::Crypto>, &[u8])>;
}

impl<const DOMAIN: u8, B: ReceiveBuffer> Crypto for Builder<'_, DOMAIN, B> {
    fn crypto_data_limit(offset: u64, frame_room: usize) -> usize {
        let fixed = 1 + Self::varint_len(offset as usize);
        let mut data = frame_room.saturating_sub(fixed + 1);
        loop {
            let next = frame_room.saturating_sub(fixed + Self::varint_len(data));
            if next >= data {
                return data;
            }
            data = next;
        }
    }

    fn peek_crypto_chunk(
        tx: &crate::conn::crypto_tx::Tx,
        epoch: Epoch,
        frame_room: usize,
    ) -> Option<(commit::Delivery<delivery::Crypto>, &[u8])> {
        let candidate = tx.peek(epoch)?;
        let take = Self::crypto_data_limit(candidate.offset, frame_room).min(candidate.len);
        let selected = tx.select(epoch, take)?;
        Some((
            commit::Delivery {
                record: selected.record,
                tracked: selected.handle,
            },
            selected.data,
        ))
    }

    fn encode_crypto(out: &mut Vec<u8>, offset: u64, data: &[u8]) -> bool {
        let start = out.len();
        out.push(0x06);
        let Some(offset) = VarInt::new(offset) else {
            out.truncate(start);
            return false;
        };
        let Some(len) = VarInt::from_usize(data.len()) else {
            out.truncate(start);
            return false;
        };
        offset.encode(out);
        len.encode(out);
        out.extend_from_slice(data);
        true
    }

    fn crypto_probe(
        &self,
        epoch: Epoch,
        frame_room: usize,
    ) -> Option<(commit::Delivery<delivery::Crypto>, &[u8])> {
        let tx = self.connection.handshake.crypto();
        let candidate = tx.select_probe(epoch, usize::MAX)?;
        (Self::crypto_data_limit(candidate.record.offset, frame_room) >= candidate.record.len)
            .then_some((
                commit::Delivery {
                    record: candidate.record,
                    tracked: candidate.handle,
                },
                candidate.data,
            ))
    }
}
