use std::mem;

use crate::conn;
use crate::conn::commit;

use crate::packet;
use crate::stream;

use crate::conn::transmit::builder::application;

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

impl<const DOMAIN: u8, B: stream::ReceiveBuffer> BuildTerminal
    for application::Application<'_, DOMAIN, B>
{
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
        let pn = self.packet.connection.egress.spaces[conn::Epoch::Application as usize].next_pn;

        let mut frames = mem::take(&mut self.packet.connection.scratch_frames);
        frames.clear();
        frames.push(crate::frame::TYPE_PING);
        let header_overhead =
            1 + self.packet.connection.path.peer_cid().len() + conn::PN_LEN as usize;
        let payload_target =
            (target_size as usize).saturating_sub(header_overhead + crate::conn::TAG_LEN);
        if payload_target == 0 {
            self.packet.connection.scratch_frames = frames;
            return None;
        }
        while frames.len() < payload_target {
            frames.push(crate::frame::TYPE_PADDING);
        }

        let mut header = mem::take(&mut self.packet.connection.scratch_header);
        header.clear();
        let pn_off = packet::ShortHeaderRef {
            dcid: self.packet.connection.path.peer_cid(),
            packet_number: pn,
            pn_len: conn::PN_LEN,
        }
        .encode_into(&mut header)
        .ok()?;
        let n = self
            .packet
            .connection
            .handshake
            .write_key(conn::Epoch::Application)?
            .encrypt_short_into(dst, &header, &frames, pn, pn_off, conn::PN_LEN as usize)
            .ok()?;

        header.clear();
        self.packet.connection.scratch_header = header;
        frames.clear();
        self.packet.connection.scratch_frames = frames;
        let mut commit = commit::Packet::new(conn::Epoch::Application, pn);
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
        let pn = self.packet.connection.egress.spaces[conn::Epoch::Application as usize].next_pn;

        let fixed =
            1 + crate::conn::transmit::builder::Builder::<DOMAIN, B>::varint_len(
                close.error_code as usize,
            ) + if close.is_application {
                0
            } else {
                crate::conn::transmit::builder::Builder::<DOMAIN, B>::varint_len(
                    close.frame_type as usize,
                )
            };
        if fixed + 1 > payload_limit {
            return None;
        }
        let mut reason_len = close.reason.len();
        while fixed
            + crate::conn::transmit::builder::Builder::<DOMAIN, B>::varint_len(reason_len)
            + reason_len
            > payload_limit
        {
            let encoded = fixed
                + crate::conn::transmit::builder::Builder::<DOMAIN, B>::varint_len(reason_len)
                + reason_len;
            reason_len = reason_len.saturating_sub((encoded - payload_limit).max(1));
        }
        let mut frames = mem::take(&mut self.packet.connection.scratch_frames);
        frames.clear();
        frames.push(if close.is_application { 0x1d } else { 0x1c });
        crate::varint::VarInt::new(close.error_code)?.encode(&mut frames);
        if !close.is_application {
            crate::varint::VarInt::new(close.frame_type)?.encode(&mut frames);
        }
        crate::varint::VarInt::from_usize(reason_len)?.encode(&mut frames);
        frames.extend_from_slice(&close.reason[..reason_len]);

        let mut header = mem::take(&mut self.packet.connection.scratch_header);
        header.clear();
        let pn_off = packet::ShortHeaderRef {
            dcid: self.packet.connection.path.peer_cid(),
            packet_number: pn,
            pn_len: conn::PN_LEN,
        }
        .encode_into(&mut header)
        .ok()?;
        let n = self
            .packet
            .connection
            .handshake
            .write_key(conn::Epoch::Application)?
            .encrypt_short_into(dst, &header, &frames, pn, pn_off, conn::PN_LEN as usize)
            .ok()?;

        header.clear();
        self.packet.connection.scratch_header = header;
        frames.clear();
        self.packet.connection.scratch_frames = frames;
        let mut commit = commit::Packet::new(conn::Epoch::Application, pn);
        commit.bytes = n;
        commit.close = true;
        Some((n, commit))
    }
}
