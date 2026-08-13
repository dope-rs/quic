use std::time;

use dope::manifold::datagram;

use crate::conn;
use crate::conn::handshake;
use crate::packet;
use crate::stream;

use crate::conn::ingress;
use crate::conn::ingress::frames::{self, ProcessFrames as _};

pub(crate) struct Retained<'a, 'd, const DOMAIN: u8> {
    ingress: ingress::Ingress<'a, DOMAIN, stream::RecvBuffer<'d>>,
}

impl<'a, 'd, const DOMAIN: u8> Retained<'a, 'd, DOMAIN> {
    pub(crate) fn routed(
        connection: &'a mut crate::conn::session::Connection<DOMAIN, stream::RecvBuffer<'d>>,
        workspace: &'a mut conn::ReceiveWorkspace,
        routed_local_cid: Option<crate::conn::path::LocalCidKey>,
    ) -> Self {
        Self {
            ingress: ingress::Ingress::routed(connection, workspace, routed_local_cid),
        }
    }
}

impl<'a, 'd, const DOMAIN: u8> Retained<'a, 'd, DOMAIN> {
    pub(crate) fn recv_client_datagram<'turn>(
        &mut self,
        packet: datagram::packet::Packet<'turn, 'd>,
        retainer: datagram::packet::Retainer<'_, 'd>,
        now: time::Instant,
    ) -> Result<(), conn::Error> {
        self.recv_datagram_with(packet, retainer, now, &mut handshake::ClientReader)
    }

    pub(crate) fn recv_client_pooled_datagram<'turn>(
        &mut self,
        packet: datagram::packet::Packet<'turn, 'd>,
        retainer: datagram::packet::Retainer<'_, 'd>,
        now: time::Instant,
        tls: &mut handshake::ClientTls<'_>,
    ) -> Result<(), conn::Error> {
        self.recv_datagram_with(
            packet,
            retainer,
            now,
            &mut handshake::PooledClientReader::new(tls),
        )
    }

    pub(crate) fn recv_server_datagram<'turn, G, V>(
        &mut self,
        packet: datagram::packet::Packet<'turn, 'd>,
        retainer: datagram::packet::Retainer<'_, 'd>,
        now: time::Instant,
        server: &mut shin::server::QuicConnection<handshake::Clock, DOMAIN, G, V>,
    ) -> Result<(), conn::Error>
    where
        G: shin::server::config::EarlyDataGuard,
        V: shin::server::config::ClientCertVerifier,
    {
        self.recv_datagram_with(
            packet,
            retainer,
            now,
            &mut handshake::ServerReader::new(server),
        )
    }

    pub(crate) fn recv_server_pooled_datagram<'turn, G, V>(
        &mut self,
        packet: datagram::packet::Packet<'turn, 'd>,
        retainer: datagram::packet::Retainer<'_, 'd>,
        now: time::Instant,
        server: &mut shin::server::QuicPooledConnection<'_, handshake::Clock, DOMAIN, V, G>,
    ) -> Result<(), conn::Error>
    where
        G: shin::server::config::EarlyDataGuard,
        V: shin::server::config::ClientCertVerifier,
    {
        self.recv_datagram_with(
            packet,
            retainer,
            now,
            &mut handshake::PooledServerReader::new(server),
        )
    }

    pub(crate) fn recv_finished_datagram<'turn>(
        &mut self,
        packet: datagram::packet::Packet<'turn, 'd>,
        retainer: datagram::packet::Retainer<'_, 'd>,
        now: time::Instant,
    ) -> Result<(), conn::Error> {
        self.recv_datagram_with(packet, retainer, now, &mut handshake::FinishedReader)
    }

    fn recv_datagram_with<'turn, R>(
        &mut self,
        packet: datagram::packet::Packet<'turn, 'd>,
        retainer: datagram::packet::Retainer<'_, 'd>,
        now: time::Instant,
        read: &mut R,
    ) -> Result<(), conn::Error>
    where
        R: handshake::Reader<DOMAIN>,
    {
        if !self.ingress.connection.egress.peer_address_validated {
            self.ingress.connection.egress.amplification_received = self
                .ingress
                .connection
                .egress
                .amplification_received
                .saturating_add(packet.len() as u64);
        }
        if self.ingress.receive_stateless_reset(packet.as_ref()) {
            return Ok(());
        }
        let mut rest = Some(packet.into_split());
        while let Some(packet) = rest.take() {
            if packet.is_empty() {
                break;
            }
            let first = packet.as_ref()[0];
            if first & 0x80 == 0 {
                if first & 0x40 != 0 {
                    self.recv_one_rtt_datagram(packet, retainer, now, read)?;
                }
                break;
            }
            if first & 0x30 == 0x30 {
                self.ingress.recv_retry(packet.as_ref())?;
                break;
            }
            let parsed =
                packet::ParsedLong::parse(packet).map_err(|_| conn::Error::HeaderDecode)?;
            let kind = parsed.kind();
            let (packet, tail) = parsed
                .split_first()
                .map_err(|_| conn::Error::HeaderDecode)?;
            match kind {
                crate::packet::LongType::Initial => {
                    self.recv_initial_datagram(packet, now, read)?
                }
                crate::packet::LongType::ZeroRtt => {
                    self.recv_zero_rtt_datagram(packet, retainer, now, read)?
                }
                crate::packet::LongType::Handshake => {
                    self.recv_handshake_datagram(packet, now, read)?
                }
                crate::packet::LongType::Retry => return Err(conn::Error::HeaderDecode),
            }
            rest = Some(tail);
        }
        Ok(())
    }

    fn recv_zero_rtt_datagram<'turn, R>(
        &mut self,
        packet: packet::ParsedLong<datagram::packet::Split<'turn, 'd>>,
        retainer: datagram::packet::Retainer<'_, 'd>,
        now: time::Instant,
        read: &mut R,
    ) -> Result<(), conn::Error>
    where
        R: handshake::Reader<DOMAIN>,
    {
        let Some(zr) = self.ingress.connection.handshake.zero_rtt_read_key() else {
            return Ok(());
        };
        let expected = self.ingress.connection.receive.packet_numbers
            [conn::Epoch::Application as usize]
            .expected_pn();
        let packet = packet
            .decrypt(zr, expected)
            .map_err(|_| conn::Error::PacketDecrypt)?;
        let (pn, packet, body) = packet.into_parts();
        self.process_retained_body(
            frames::PacketMeta::new(conn::Epoch::Application, pn, now),
            packet,
            body,
            retainer,
            read,
            false,
        )
    }

    fn recv_initial_datagram<'turn, R>(
        &mut self,
        packet: packet::ParsedLong<datagram::packet::Split<'turn, 'd>>,
        now: time::Instant,
        read: &mut R,
    ) -> Result<(), conn::Error>
    where
        R: handshake::Reader<DOMAIN>,
    {
        let Some(initial_r) = self
            .ingress
            .connection
            .handshake
            .read_key(conn::Epoch::Initial)
        else {
            return Ok(());
        };
        if self.ingress.connection.peer.is_client
            && self.ingress.connection.path.peer_first_scid.is_none()
        {
            self.ingress
                .connection
                .path
                .set_first_peer_cid(packet.scid());
        }
        let expected = self.ingress.connection.receive.packet_numbers
            [conn::Epoch::Initial as usize]
            .expected_pn();
        let packet = packet
            .decrypt(initial_r, expected)
            .map_err(|_| conn::Error::PacketDecrypt)?;
        let pn = packet.packet_number();
        let mut source = frames::Copied::<stream::RecvBuffer<'d>>::new();
        self.ingress.process_packet_body(
            frames::PacketMeta::new(conn::Epoch::Initial, pn, now),
            None,
            packet.body(),
            read,
            &mut source,
        )
    }

    fn recv_handshake_datagram<'turn, R>(
        &mut self,
        packet: packet::ParsedLong<datagram::packet::Split<'turn, 'd>>,
        now: time::Instant,
        read: &mut R,
    ) -> Result<(), conn::Error>
    where
        R: handshake::Reader<DOMAIN>,
    {
        let Some(hr) = self
            .ingress
            .connection
            .handshake
            .read_key(conn::Epoch::Handshake)
        else {
            return Ok(());
        };
        let expected = self.ingress.connection.receive.packet_numbers
            [conn::Epoch::Handshake as usize]
            .expected_pn();
        let packet = packet
            .decrypt(hr, expected)
            .map_err(|_| conn::Error::PacketDecrypt)?;
        self.ingress.connection.egress.peer_address_validated = true;
        let pn = packet.packet_number();
        let mut source = frames::Copied::<stream::RecvBuffer<'d>>::new();
        self.ingress.process_packet_body(
            frames::PacketMeta::new(conn::Epoch::Handshake, pn, now),
            None,
            packet.body(),
            read,
            &mut source,
        )
    }

    fn recv_one_rtt_datagram<'turn, R>(
        &mut self,
        mut packet: datagram::packet::Split<'turn, 'd>,
        retainer: datagram::packet::Retainer<'_, 'd>,
        now: time::Instant,
        read: &mut R,
    ) -> Result<(), conn::Error>
    where
        R: handshake::Reader<DOMAIN>,
    {
        let Some(ar) = self
            .ingress
            .connection
            .handshake
            .read_key(conn::Epoch::Application)
        else {
            return Ok(());
        };
        let pn_offset =
            packet::ShortHeader::pn_offset_for(self.ingress.connection.path.local_cid().len());
        let expected = self.ingress.connection.receive.packet_numbers
            [conn::Epoch::Application as usize]
            .expected_pn();
        let (pn, body) = ar
            .decrypt_short_in_place(packet.as_mut(), pn_offset, expected)
            .map_err(|_| conn::Error::PacketDecrypt)?;
        self.process_retained_body(
            frames::PacketMeta::new(conn::Epoch::Application, pn, now),
            packet,
            body,
            retainer,
            read,
            true,
        )
    }

    fn process_retained_body<'turn, R>(
        &mut self,
        meta: frames::PacketMeta,
        packet: datagram::packet::Split<'turn, 'd>,
        body: std::ops::Range<usize>,
        retainer: datagram::packet::Retainer<'_, 'd>,
        read: &mut R,
        one_rtt: bool,
    ) -> Result<(), conn::Error>
    where
        R: handshake::Reader<DOMAIN>,
    {
        let packet = packet.freeze();
        let packet_cid = one_rtt.then(|| frames::PacketCid {
            routed: self.ingress.routed_local_cid,
            bytes: &packet.as_ref()[1..packet::ShortHeader::pn_offset_for(
                self.ingress.connection.path.local_cid().len(),
            )],
        });
        let bytes = &packet.as_ref()[body.clone()];
        let mut source = frames::Retained::new(&packet, retainer, body.start);
        self.ingress
            .process_packet_body(meta, packet_cid, bytes, read, &mut source)
    }
}
