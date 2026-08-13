use std::mem::take;

use crate::conn::{Epoch, PN_LEN, TAG_LEN, commit};
use crate::frame::{TYPE_PADDING, TYPE_PING};
use crate::packet::ShortHeaderRef;
use crate::stream::ReceiveBuffer;
use crate::varint::VarInt;

use super::{Application, Builder};

pub(in crate::conn::transmit) trait BuildTerminal {
    fn build_one_rtt_probe(
        &mut self,
        dst: &mut Vec<u8>,
        target_size: u64,
        max_packet_bytes: usize,
    ) -> Option<(usize, commit::Packet)>;

    fn build_one_rtt_close(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
    ) -> Option<(usize, commit::Packet)>;
}

impl<const DOMAIN: u8, B: ReceiveBuffer> BuildTerminal for Application<'_, DOMAIN, B> {
    fn build_one_rtt_probe(
        &mut self,
        dst: &mut Vec<u8>,
        target_size: u64,
        max_packet_bytes: usize,
    ) -> Option<(usize, commit::Packet)> {
        if !self.packet.can_track_packet() {
            return None;
        }
        let target_size = target_size.min(u64::try_from(max_packet_bytes).unwrap_or(u64::MAX));
        let pn = self.packet.connection.egress.spaces[Epoch::Application as usize].next_pn;

        let mut frames = take(&mut self.packet.connection.scratch_frames);
        frames.clear();
        frames.push(TYPE_PING);
        let header_overhead = 1 + self.packet.connection.path.peer_cid().len() + PN_LEN as usize;
        let payload_target = (target_size as usize).saturating_sub(header_overhead + TAG_LEN);
        if payload_target == 0 {
            self.packet.connection.scratch_frames = frames;
            return None;
        }
        while frames.len() < payload_target {
            frames.push(TYPE_PADDING);
        }

        let mut header = take(&mut self.packet.connection.scratch_header);
        header.clear();
        let pn_off = ShortHeaderRef {
            dcid: self.packet.connection.path.peer_cid(),
            packet_number: pn,
            pn_len: PN_LEN,
        }
        .encode_into(&mut header)
        .ok()?;
        let n = self
            .packet
            .connection
            .handshake
            .write_key(Epoch::Application)?
            .encrypt_short_into(dst, &header, &frames, pn, pn_off, PN_LEN as usize)
            .ok()?;

        header.clear();
        self.packet.connection.scratch_header = header;
        frames.clear();
        self.packet.connection.scratch_frames = frames;
        let mut commit = commit::Packet::new(Epoch::Application, pn);
        commit.bytes = n;
        commit.ack_eliciting = true;
        commit.in_flight = true;
        commit.pmtud_probe = Some(target_size);
        Some((n, commit))
    }

    fn build_one_rtt_close(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
    ) -> Option<(usize, commit::Packet)> {
        let close = self.packet.connection.egress.pending_close.as_ref()?;
        let payload_limit = self.packet.short_payload_limit(max_packet_bytes);
        let pn = self.packet.connection.egress.spaces[Epoch::Application as usize].next_pn;

        let fixed = 1
            + Builder::<DOMAIN, B>::varint_len(close.error_code as usize)
            + if close.is_application {
                0
            } else {
                Builder::<DOMAIN, B>::varint_len(close.frame_type as usize)
            };
        if fixed + 1 > payload_limit {
            return None;
        }
        let mut reason_len = close.reason.len();
        while fixed + Builder::<DOMAIN, B>::varint_len(reason_len) + reason_len > payload_limit {
            let encoded = fixed + Builder::<DOMAIN, B>::varint_len(reason_len) + reason_len;
            reason_len = reason_len.saturating_sub((encoded - payload_limit).max(1));
        }
        let mut frames = take(&mut self.packet.connection.scratch_frames);
        frames.clear();
        frames.push(if close.is_application { 0x1d } else { 0x1c });
        VarInt::new(close.error_code)?.encode(&mut frames);
        if !close.is_application {
            VarInt::new(close.frame_type)?.encode(&mut frames);
        }
        VarInt::from_usize(reason_len)?.encode(&mut frames);
        frames.extend_from_slice(&close.reason[..reason_len]);

        let mut header = take(&mut self.packet.connection.scratch_header);
        header.clear();
        let pn_off = ShortHeaderRef {
            dcid: self.packet.connection.path.peer_cid(),
            packet_number: pn,
            pn_len: PN_LEN,
        }
        .encode_into(&mut header)
        .ok()?;
        let n = self
            .packet
            .connection
            .handshake
            .write_key(Epoch::Application)?
            .encrypt_short_into(dst, &header, &frames, pn, pn_off, PN_LEN as usize)
            .ok()?;

        header.clear();
        self.packet.connection.scratch_header = header;
        frames.clear();
        self.packet.connection.scratch_frames = frames;
        let mut commit = commit::Packet::new(Epoch::Application, pn);
        commit.bytes = n;
        commit.close = true;
        Some((n, commit))
    }
}
