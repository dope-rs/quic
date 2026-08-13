use std::net::SocketAddr;
use std::time::Instant;

use crate::clock::WallClock;
use crate::conn::path::StatelessResetToken;
use crate::conn::{self, Error};
use crate::packet::{
    ConnectionId, InitialHeader, MAX_CONNECTION_ID_LEN, QUIC_V1, RETRY_INTEGRITY_TAG_LEN,
    RetryPacket,
};
use crate::secrets::{RetryTokenSecret, StatelessResetSecret};
use crate::stream::ReceiveBuffer;

use super::{CidOps as _, DeadlineOps as _, SlotOps as _};
use crate::mux::drive::OutputOps as _;
use crate::mux::{Handler, MAX_CIDS_PER_CONN, MuxInner, ROUTED_CID_LEN, RetryGate};

pub(in crate::mux) trait ResetOps {
    fn maybe_handle_retry_gating(
        &mut self,
        from: SocketAddr,
        data: &[u8],
    ) -> Result<RetryGate, Error>;
    fn emit_stateless_reset(&mut self, from: SocketAddr, trigger: &[u8]) -> bool;
    fn receive_stateless_reset(&mut self, from: SocketAddr, datagram: &[u8], now: Instant) -> bool;
    fn gen_cid(&mut self, prefix: Option<u8>) -> Option<ConnectionId>;
}

impl<'tls, H: Handler<DOMAIN, B>, P: conn::server::Policy, const DOMAIN: u8, B: ReceiveBuffer>
    ResetOps for MuxInner<'tls, H, P, DOMAIN, B>
{
    fn maybe_handle_retry_gating(
        &mut self,
        from: SocketAddr,
        data: &[u8],
    ) -> Result<RetryGate, Error> {
        let (require_address_validation, retry_token_secret, cid_prefix, configured_ceiling) = {
            let server_config = &self.server.as_ref().ok_or(Error::HeaderDecode)?.config;
            (
                server_config.require_address_validation,
                server_config.retry_token_secret,
                server_config.cid_prefix,
                crate::mux::setup::max_packet_bytes(server_config),
            )
        };
        if !require_address_validation {
            return Ok(RetryGate::Accept(None));
        }
        let secret = match retry_token_secret {
            Some(secret) => RetryTokenSecret(secret),
            None => return Ok(RetryGate::Accept(None)),
        };
        let prefix = InitialHeader::decode_pre_hp(data).map_err(|_| Error::HeaderDecode)?;
        if prefix.token.is_empty() {
            let now_secs = WallClock::now().unix_seconds();
            let expiry = now_secs.saturating_add(10);
            let Some(new_scid) = self.gen_cid(cid_prefix) else {
                return Ok(RetryGate::Drop);
            };
            let packet_ceiling = configured_ceiling
                .min(self.outgoing.bytes_capacity)
                .min(data.len().saturating_mul(3));
            let encoded_len = RetryPacket::prefix_len(prefix.scid, new_scid.as_ref_id())
                + RetryTokenSecret::encoded_len(prefix.dcid)
                + RETRY_INTEGRITY_TAG_LEN;
            if !self.packet_fits(encoded_len, packet_ceiling) {
                return Ok(RetryGate::Drop);
            }
            let pseudo_len = 1 + prefix.dcid.len();
            let Some(mut storage) = self.take_packet_buffer(pseudo_len + encoded_len) else {
                return Ok(RetryGate::Drop);
            };
            storage.push(prefix.dcid.len() as u8);
            storage.extend_from_slice(prefix.dcid.as_slice());
            RetryPacket::encode_prefix_into(
                &mut storage,
                QUIC_V1,
                prefix.scid,
                new_scid.as_ref_id(),
            );
            secret.issue_into(&mut storage, &from, prefix.dcid, expiry);
            let Ok(integrity_tag) = RetryPacket::tag_from_aad(&storage) else {
                self.recycle_packet(storage);
                return Ok(RetryGate::Drop);
            };
            storage.extend_from_slice(&integrity_tag);
            let packet = match dope::manifold::datagram::OwnedSuffix::new(storage, pseudo_len) {
                Ok(packet) => packet,
                Err(storage) => {
                    self.recycle_packet(storage);
                    return Ok(RetryGate::Drop);
                }
            };
            return Ok(
                if self.push_or_recycle(crate::mux::Outgoing::Suffix(from, packet)) {
                    RetryGate::IssuedRetry
                } else {
                    RetryGate::Drop
                },
            );
        }
        let now_secs = WallClock::now().unix_seconds();
        match secret.validate(&from, prefix.token, now_secs) {
            None => Ok(RetryGate::Drop),
            Some(odcid) => Ok(RetryGate::Accept(Some(odcid))),
        }
    }

    fn emit_stateless_reset(&mut self, from: SocketAddr, trigger: &[u8]) -> bool {
        let Some(server_config) = self.server.as_ref().map(|server| &server.config) else {
            return false;
        };
        let Some(reset_secret) = server_config.stateless_reset_secret else {
            return false;
        };
        let secret = StatelessResetSecret(reset_secret);
        let Some(dcid) = crate::mux::setup::dcid(trigger, ROUTED_CID_LEN) else {
            return false;
        };
        if trigger.len() < 23 {
            return false;
        }
        let packet_ceiling = crate::mux::setup::max_packet_bytes(server_config)
            .min(self.outgoing.bytes_capacity)
            .min(trigger.len().saturating_mul(3));
        if packet_ceiling < 22 {
            return false;
        }
        let len = (trigger.len() - 1).min(packet_ceiling);
        if !self.packet_fits(len, packet_ceiling) {
            return false;
        }
        let Some(mut reset) = self.take_packet_buffer(len) else {
            return false;
        };
        if !crate::mux::setup::stateless_reset_into(&mut reset, secret.token_for(dcid), len) {
            self.recycle_packet(reset);
            return false;
        }
        self.push_or_recycle(crate::mux::Outgoing::Plain(from, reset))
    }

    fn receive_stateless_reset(&mut self, from: SocketAddr, datagram: &[u8], now: Instant) -> bool {
        let Some(token) = StatelessResetToken::from_datagram(datagram) else {
            return false;
        };
        let Some(handle) = self.registry.indexes.reset.get(token) else {
            return false;
        };
        let Some(index) = self.handle_index(handle) else {
            self.registry.indexes.reset.remove(token, handle);
            return false;
        };
        let matched = self.registry.entries[index].slot_mut().is_some_and(|slot| {
            slot.peer_addr == from && slot.conn.try_receive_stateless_reset_token(token)
        });
        if !matched {
            return false;
        }
        self.refresh_deadline(handle, now);
        true
    }

    fn gen_cid(&mut self, prefix: Option<u8>) -> Option<ConnectionId> {
        let attempts = self
            .registry
            .active_conns
            .saturating_mul(MAX_CIDS_PER_CONN)
            .saturating_add(1);
        for _ in 0..attempts {
            self.registry.indexes.cid_counter = self.registry.indexes.cid_counter.wrapping_add(1);
            let sequence = self.registry.indexes.cid_counter.to_le_bytes();
            let mut out = [0; MAX_CONNECTION_ID_LEN];
            let prefix_len = usize::from(prefix.is_some());
            for index in 0..ROUTED_CID_LEN {
                out[index] =
                    sequence[(index.saturating_sub(prefix_len)) % sequence.len()] ^ index as u8;
            }
            if let Some(prefix) = prefix {
                out[0] = prefix;
            }
            let cid = ConnectionId::new(&out[..ROUTED_CID_LEN])
                .expect("the mux CID width is protocol-valid");
            if self.find_cid(cid.as_slice()).is_none() {
                return Some(cid);
            }
        }
        None
    }
}
