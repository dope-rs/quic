use crate::conn;

use crate::conn::transmit::builder;
use crate::stream;

pub(in crate::conn) trait Ack {
    fn append_ack_frame(&mut self, epoch: conn::Epoch, out: &mut Vec<u8>, limit: usize) -> bool;
}

impl<const DOMAIN: u8, B: stream::ReceiveBuffer> Ack for builder::Builder<'_, DOMAIN, B> {
    fn append_ack_frame(&mut self, epoch: conn::Epoch, out: &mut Vec<u8>, limit: usize) -> bool {
        let receive = &self.connection.received[epoch as usize];
        if !receive.ack_pending {
            return false;
        }
        let Some(ack_ranges) = receive.build_ack_ranges() else {
            return false;
        };
        let Some(largest) = crate::varint::VarInt::new(ack_ranges.largest) else {
            return false;
        };
        let Some(first_range) = crate::varint::VarInt::new(ack_ranges.first_range) else {
            return false;
        };
        let available = limit.saturating_sub(out.len());
        let base_encoded = 1
            + largest.encoded_len()
            + crate::varint::VarInt::ZERO.encoded_len()
            + crate::varint::VarInt::ZERO.encoded_len()
            + first_range.encoded_len();
        if base_encoded > available {
            return false;
        }
        let selected = if available >= crate::conn::MAX_GENERATED_ACK_FRAME_BYTES {
            ack_ranges.additional.len()
        } else {
            let mut encoded = base_encoded;
            let mut selected = 0usize;
            for (gap, range) in ack_ranges.additional.clone() {
                let Some(gap) = crate::varint::VarInt::new(gap) else {
                    break;
                };
                let Some(range) = crate::varint::VarInt::new(range) else {
                    break;
                };
                let next = selected + 1;
                let previous_count_len = crate::varint::VarInt::from_usize(selected)
                    .expect("generated ACK range count")
                    .encoded_len();
                let next_count_len = crate::varint::VarInt::from_usize(next)
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
        out.push(crate::frame::TYPE_ACK);
        largest.encode(out);
        crate::varint::VarInt::ZERO.encode(out);
        crate::varint::VarInt::from_usize(selected)
            .expect("generated ACK range count")
            .encode(out);
        first_range.encode(out);
        for (gap, range) in ack_ranges.additional.take(selected) {
            crate::varint::VarInt::new(gap)
                .expect("generated ACK gap")
                .encode(out);
            crate::varint::VarInt::new(range)
                .expect("generated ACK range")
                .encode(out);
        }
        debug_assert!(out.len() - start <= available);
        true
    }
}
