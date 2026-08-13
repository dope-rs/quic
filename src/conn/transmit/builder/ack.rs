use crate::conn::{Epoch, MAX_GENERATED_ACK_FRAME_BYTES};
use crate::frame::TYPE_ACK;
use crate::varint::VarInt;

use super::Builder;
use crate::stream::ReceiveBuffer;

pub(in crate::conn) trait Ack {
    fn append_ack_frame(&mut self, epoch: Epoch, out: &mut Vec<u8>, limit: usize) -> bool;
}

impl<const DOMAIN: u8, B: ReceiveBuffer> Ack for Builder<'_, DOMAIN, B> {
    fn append_ack_frame(&mut self, epoch: Epoch, out: &mut Vec<u8>, limit: usize) -> bool {
        let receive = &self.connection.received[epoch as usize];
        if !receive.ack_pending {
            return false;
        }
        let Some(ack_ranges) = receive.build_ack_ranges() else {
            return false;
        };
        let Some(largest) = VarInt::new(ack_ranges.largest) else {
            return false;
        };
        let Some(first_range) = VarInt::new(ack_ranges.first_range) else {
            return false;
        };
        let available = limit.saturating_sub(out.len());
        let base_encoded = 1
            + largest.encoded_len()
            + VarInt::ZERO.encoded_len()
            + VarInt::ZERO.encoded_len()
            + first_range.encoded_len();
        if base_encoded > available {
            return false;
        }
        let selected = if available >= MAX_GENERATED_ACK_FRAME_BYTES {
            ack_ranges.additional.len()
        } else {
            let mut encoded = base_encoded;
            let mut selected = 0usize;
            for (gap, range) in ack_ranges.additional.clone() {
                let Some(gap) = VarInt::new(gap) else {
                    break;
                };
                let Some(range) = VarInt::new(range) else {
                    break;
                };
                let next = selected + 1;
                let previous_count_len = VarInt::from_usize(selected)
                    .expect("generated ACK range count")
                    .encoded_len();
                let next_count_len = VarInt::from_usize(next)
                    .expect("generated ACK range count")
                    .encoded_len();
                let next_encoded = encoded - previous_count_len
                    + next_count_len
                    + gap.encoded_len()
                    + range.encoded_len();
                if next_encoded > available {
                    break;
                }
                selected = next;
                encoded = next_encoded;
            }
            selected
        };

        let start = out.len();
        out.push(TYPE_ACK);
        largest.encode(out);
        VarInt::ZERO.encode(out);
        VarInt::from_usize(selected)
            .expect("generated ACK range count")
            .encode(out);
        first_range.encode(out);
        for (gap, range) in ack_ranges.additional.take(selected) {
            VarInt::new(gap).expect("generated ACK gap").encode(out);
            VarInt::new(range).expect("generated ACK range").encode(out);
        }
        debug_assert!(out.len() - start <= available);
        true
    }
}
