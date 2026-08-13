use crate::conn::commit;
use crate::conn::datagram;
use crate::conn::packet;

use crate::stream;

use crate::conn::transmit::builder::ack::Ack as _;
use crate::conn::transmit::builder::application;

pub(in crate::conn::transmit) trait BuildDatagram {
    fn build_datagram(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
    ) -> Option<(usize, commit::Datagram)>;
}

impl<const DOMAIN: u8, B: stream::ReceiveBuffer> BuildDatagram
    for application::Application<'_, DOMAIN, B>
{
    fn build_datagram(
        &mut self,
        dst: &mut Vec<u8>,
        max_packet_bytes: usize,
    ) -> Option<(usize, commit::Datagram)> {
        let pn =
            self.packet.connection.egress.spaces[crate::conn::Epoch::Application as usize].next_pn;
        let standard = self.packet.connection.egress.datagram_congestion_control
            == datagram::CongestionControl::Standard;
        if standard && !self.packet.can_track_packet() {
            return None;
        }
        let packet_start = dst.len();
        let pn_off = crate::packet::ShortHeaderRef {
            dcid: self.packet.connection.path.peer_cid(),
            packet_number: pn,
            pn_len: crate::conn::PN_LEN,
        }
        .encode_into(dst)
        .ok()?;
        let payload_start = dst.len();
        let payload_limit =
            payload_start.checked_add(self.packet.short_payload_limit(max_packet_bytes))?;
        let mut frames = packet::Payload::new(dst, payload_start);
        let ack_included = self.packet.append_ack_frame(
            crate::conn::Epoch::Application,
            &mut frames,
            payload_limit,
        );
        let data = self.packet.connection.egress.pending_datagrams.front()?;
        let datagram = if data.len().saturating_add(1) <= payload_limit.saturating_sub(frames.len())
        {
            frames.push(0x30);
            frames.extend_from_slice(data);
            true
        } else {
            false
        };
        if frames.is_empty() {
            return None;
        }
        let bytes = self
            .packet
            .connection
            .handshake
            .write_key(crate::conn::Epoch::Application)?
            .protect_short_in_place(
                frames.out_mut(),
                packet_start,
                payload_start,
                pn,
                pn_off,
                crate::conn::PN_LEN as usize,
            )
            .ok()?;
        Some((
            bytes,
            commit::Datagram {
                pn,
                bytes,
                ack_included,
                datagram,
                in_flight: datagram && standard,
            },
        ))
    }
}
