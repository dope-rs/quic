mod admitted_packet;
mod frames;
mod retained;

pub(crate) use retained::Retained;

use std::time::Instant;

use crate::packet::{LongType, ParsedLong, RetryRef, ShortHeader};
use crate::packet_protection::PacketProtection;
use crate::qkdf::{InitialSecrets, PacketKeys};

use super::{
    Connection, Epoch, Error, MIN_INITIAL_LEN, ReceiveWorkspace, State, handshake, transmit,
};
use crate::stream::ReceiveBuffer;
use frames::ProcessFrames;
use transmit::builder::crypto::Crypto;

pub(crate) struct Ingress<'a, const DOMAIN: u8, B: ReceiveBuffer> {
    connection: &'a mut Connection<DOMAIN, B>,
    workspace: &'a mut ReceiveWorkspace,
    routed_local_cid: Option<crate::conn::path::LocalCidKey>,
}

impl<'a, const DOMAIN: u8, B: ReceiveBuffer> Ingress<'a, DOMAIN, B> {
    pub(crate) fn new(
        connection: &'a mut Connection<DOMAIN, B>,
        workspace: &'a mut ReceiveWorkspace,
    ) -> Self {
        Self {
            connection,
            workspace,
            routed_local_cid: None,
        }
    }

    pub(crate) fn routed(
        connection: &'a mut Connection<DOMAIN, B>,
        workspace: &'a mut ReceiveWorkspace,
        routed_local_cid: Option<crate::conn::path::LocalCidKey>,
    ) -> Self {
        Self {
            connection,
            workspace,
            routed_local_cid,
        }
    }

    pub(crate) fn recv_client(&mut self, wire: &mut [u8], now: Instant) -> Result<(), Error> {
        self.recv_wire(wire, now, &mut handshake::ClientReader)
    }

    pub(crate) fn recv_client_pooled(
        &mut self,
        wire: &mut [u8],
        now: Instant,
        tls: &mut handshake::ClientTls<'_>,
    ) -> Result<(), Error> {
        self.recv_wire(wire, now, &mut handshake::PooledClientReader::new(tls))
    }

    pub(crate) fn recv_server<G, V>(
        &mut self,
        wire: &mut [u8],
        now: Instant,
        server: &mut shin::server::QuicConnection<handshake::Clock, DOMAIN, G, V>,
    ) -> Result<(), Error>
    where
        G: shin::server::config::EarlyDataGuard,
        V: shin::server::config::ClientCertVerifier,
    {
        self.recv_wire(wire, now, &mut handshake::ServerReader::new(server))
    }

    pub(crate) fn recv_server_pooled<G, V>(
        &mut self,
        wire: &mut [u8],
        now: Instant,
        server: &mut shin::server::QuicPooledConnection<'_, handshake::Clock, DOMAIN, V, G>,
    ) -> Result<(), Error>
    where
        G: shin::server::config::EarlyDataGuard,
        V: shin::server::config::ClientCertVerifier,
    {
        self.recv_wire(wire, now, &mut handshake::PooledServerReader::new(server))
    }

    pub(crate) fn recv_finished(&mut self, wire: &mut [u8], now: Instant) -> Result<(), Error> {
        self.recv_wire(wire, now, &mut handshake::FinishedReader)
    }

    fn recv_wire<R>(&mut self, wire: &mut [u8], now: Instant, read: &mut R) -> Result<(), Error>
    where
        R: handshake::Reader<DOMAIN>,
    {
        if !self.connection.egress.peer_address_validated {
            self.connection.egress.amplification_received = self
                .connection
                .egress
                .amplification_received
                .saturating_add(wire.len() as u64);
        }
        if self.receive_stateless_reset(wire) {
            return Ok(());
        }
        let mut rest = wire;
        while !rest.is_empty() {
            let first = *rest.first().ok_or(Error::HeaderDecode)?;
            if first & 0x80 == 0 {
                if first & 0x40 == 0 {
                    break;
                }
                self.recv_one_rtt(rest, now, read)?;
                break;
            }
            if first & 0x30 == 0x30 {
                self.recv_retry(rest)?;
                break;
            }
            let parsed = ParsedLong::parse(rest).map_err(|_| Error::HeaderDecode)?;
            let kind = parsed.kind();
            let (packet, tail) = parsed.split_first().map_err(|_| Error::HeaderDecode)?;
            match kind {
                LongType::Initial => self.recv_initial(packet, now, read)?,
                LongType::ZeroRtt => self.recv_zero_rtt(packet, now, read)?,
                LongType::Handshake => self.recv_handshake(packet, now, read)?,
                LongType::Retry => return Err(Error::HeaderDecode),
            }
            rest = tail;
        }
        Ok(())
    }

    fn recv_zero_rtt<R>(
        &mut self,
        packet: ParsedLong<&mut [u8]>,
        now: Instant,
        read: &mut R,
    ) -> Result<(), Error>
    where
        R: handshake::Reader<DOMAIN>,
    {
        let Some(zr) = self.connection.handshake.zero_rtt_read_key() else {
            return Ok(());
        };
        let expected = self.connection.received[Epoch::Application as usize].expected_pn();
        let packet = packet
            .decrypt(zr, expected)
            .map_err(|_| Error::PacketDecrypt)?;
        let mut source = frames::Copied::<B>::new();
        self.process_packet_body(
            frames::PacketMeta::new(Epoch::Application, packet.packet_number(), now),
            None,
            packet.body(),
            read,
            &mut source,
        )
    }

    fn recv_retry(&mut self, wire: &[u8]) -> Result<(), Error> {
        if !self.connection.is_client || self.connection.path.retry_processed() {
            return Ok(());
        }
        if self
            .connection
            .handshake
            .read_key(Epoch::Handshake)
            .is_some()
            || self.connection.path.peer_first_scid.is_some()
        {
            return Ok(());
        }
        let retry = RetryRef::decode(wire).map_err(|_| Error::HeaderDecode)?;
        let original_dcid = self.connection.path.original_dcid;
        let local_cid = self.connection.path.local_cid_id();
        let Some((peer_cid, token_len)) = retry
            .verify_into(
                original_dcid.as_ref_id(),
                local_cid.as_ref_id(),
                &mut self.connection.path.retry_token,
            )
            .map_err(|_| Error::Tls)?
            .map(|verified| {
                (
                    verified.source_connection_id().into_owned(),
                    verified.token().len(),
                )
            })
        else {
            return Ok(());
        };
        let active_ceiling = self
            .connection
            .egress
            .packet_ceiling
            .min(usize::try_from(self.connection.egress.pmtud.current()).unwrap_or(usize::MAX));
        let payload_limit = transmit::builder::Builder::<'_, DOMAIN, B>::initial_payload_limit_for(
            peer_cid.len(),
            local_cid.len(),
            token_len,
            active_ceiling,
        );
        let client_hello_len = self
            .connection
            .handshake
            .crypto()
            .bytes(Epoch::Initial)
            .len();
        if active_ceiling < MIN_INITIAL_LEN
            || client_hello_len == 0
            || transmit::builder::Builder::<'_, DOMAIN, B>::crypto_data_limit(0, payload_limit) == 0
        {
            self.connection.egress.state = State::Closed;
            return Err(Error::PacketCeiling);
        }
        let new_secrets = InitialSecrets::from_dcid(peer_cid.as_slice()).map_err(|_| Error::Tls)?;
        super::recovery::epochs::Epochs::new(self.connection).retry_initial();
        let initial_write = PacketProtection::aes_128(
            &PacketKeys::aes_128(&new_secrets.client).map_err(|_| Error::Tls)?,
        )
        .map_err(|_| Error::Tls)?;
        let initial_read = PacketProtection::aes_128(
            &PacketKeys::aes_128(&new_secrets.server).map_err(|_| Error::Tls)?,
        )
        .map_err(|_| Error::Tls)?;
        self.connection
            .handshake
            .replace_initial_keys(initial_read, initial_write);
        self.connection.path.set_initial_peer_cid(peer_cid);
        self.connection.path.mark_retry_processed();
        self.connection.egress.sent_initial = false;
        Ok(())
    }

    fn receive_stateless_reset(&mut self, wire: &[u8]) -> bool {
        let Some(token) = super::path::StatelessResetToken::from_datagram(wire) else {
            return false;
        };
        self.connection.try_receive_stateless_reset_token(token)
    }

    fn recv_initial<R>(
        &mut self,
        packet: ParsedLong<&mut [u8]>,
        now: Instant,
        read: &mut R,
    ) -> Result<(), Error>
    where
        R: handshake::Reader<DOMAIN>,
    {
        let Some(initial_r) = self.connection.handshake.read_key(Epoch::Initial) else {
            return Ok(());
        };
        if self.connection.is_client && self.connection.path.peer_first_scid.is_none() {
            self.connection.path.set_first_peer_cid(packet.scid());
        }
        let expected = self.connection.received[Epoch::Initial as usize].expected_pn();
        let packet = packet
            .decrypt(initial_r, expected)
            .map_err(|_| Error::PacketDecrypt)?;
        let mut source = frames::Copied::<B>::new();
        self.process_packet_body(
            frames::PacketMeta::new(Epoch::Initial, packet.packet_number(), now),
            None,
            packet.body(),
            read,
            &mut source,
        )
    }

    fn recv_handshake<R>(
        &mut self,
        packet: ParsedLong<&mut [u8]>,
        now: Instant,
        read: &mut R,
    ) -> Result<(), Error>
    where
        R: handshake::Reader<DOMAIN>,
    {
        let Some(hr) = self.connection.handshake.read_key(Epoch::Handshake) else {
            return Ok(());
        };
        let expected = self.connection.received[Epoch::Handshake as usize].expected_pn();
        let packet = packet
            .decrypt(hr, expected)
            .map_err(|_| Error::PacketDecrypt)?;
        self.connection.egress.peer_address_validated = true;
        let mut source = frames::Copied::<B>::new();
        self.process_packet_body(
            frames::PacketMeta::new(Epoch::Handshake, packet.packet_number(), now),
            None,
            packet.body(),
            read,
            &mut source,
        )
    }

    fn recv_one_rtt<R>(&mut self, wire: &mut [u8], now: Instant, read: &mut R) -> Result<(), Error>
    where
        R: handshake::Reader<DOMAIN>,
    {
        let Some(ar) = self.connection.handshake.read_key(Epoch::Application) else {
            return Ok(());
        };
        let pn_offset = ShortHeader::pn_offset_for(self.connection.path.local_cid().len());
        let expected = self.connection.received[Epoch::Application as usize].expected_pn();
        let (pn, body) = ar
            .decrypt_short_in_place(wire, pn_offset, expected)
            .map_err(|_| Error::PacketDecrypt)?;
        let mut source = frames::Copied::<B>::new();
        let packet_cid = frames::PacketCid {
            routed: self.routed_local_cid,
            bytes: &wire[1..pn_offset],
        };
        self.process_packet_body(
            frames::PacketMeta::new(Epoch::Application, pn, now),
            Some(packet_cid),
            &wire[body],
            read,
            &mut source,
        )
    }
}
