use std::net;
use std::time;

use crate::conn;
use crate::packet;

use crate::stream;

use crate::mux;
use crate::mux::drive::OutputOps as _;
use crate::mux::routing::{CidOps as _, DeadlineOps as _, SlotOps as _};

pub(in crate::mux) trait ResetOps {
    fn maybe_handle_retry_gating(
        &mut self,
        from: net::SocketAddr,
        data: &[u8],
    ) -> Result<mux::RetryGate, conn::Error>;
    fn emit_stateless_reset(&mut self, from: net::SocketAddr, trigger: &[u8]) -> bool;
    fn receive_stateless_reset(
        &mut self,
        from: net::SocketAddr,
        datagram: &[u8],
        now: time::Instant,
    ) -> bool;
    fn gen_cid(&mut self, prefix: Option<u8>) -> Option<packet::ConnectionId>;
}

impl<
    'tls,
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
    const DOMAIN: u8,
    B: stream::ReceiveBuffer,
> ResetOps for mux::Router<'tls, H, P, DOMAIN, B>
{
    fn maybe_handle_retry_gating(
        &mut self,
        from: net::SocketAddr,
        data: &[u8],
    ) -> Result<mux::RetryGate, conn::Error> {
        let (require_address_validation, retry_token_secret, cid_prefix, configured_ceiling) = {
            let server_config = &self
                .server
                .as_ref()
                .ok_or(conn::Error::HeaderDecode)?
                .config;
            (
                server_config.require_address_validation,
                server_config.retry_token_secret,
                server_config.cid_prefix,
                crate::mux::setup::max_packet_bytes(server_config),
            )
        };
        if !require_address_validation {
            return Ok(mux::RetryGate::Accept(None));
        }
        let secret = match retry_token_secret {
            Some(secret) => crate::secrets::RetryTokenSecret(secret),
            None => return Ok(mux::RetryGate::Accept(None)),
        };
        let prefix = crate::packet::InitialHeader::decode_pre_hp(data)
            .map_err(|_| conn::Error::HeaderDecode)?;
        if prefix.token.is_empty() {
            let now_secs = crate::clock::WallClock::now().unix_seconds();
            let expiry = now_secs.saturating_add(10);
            let Some(new_scid) = self.gen_cid(cid_prefix) else {
                return Ok(mux::RetryGate::Drop);
            };
            let packet_ceiling = configured_ceiling
                .min(self.outgoing.bytes_capacity)
                .min(data.len().saturating_mul(3));
            let encoded_len = crate::packet::Retry::prefix_len(prefix.scid, new_scid.as_ref_id())
                + crate::secrets::RetryTokenSecret::encoded_len(prefix.dcid)
                + crate::packet::RETRY_INTEGRITY_TAG_LEN;
            if !self.packet_fits(encoded_len, packet_ceiling) {
                return Ok(mux::RetryGate::Drop);
            }
            let pseudo_len = 1 + prefix.dcid.len();
            let Some(mut storage) = self.take_packet_buffer(pseudo_len + encoded_len) else {
                return Ok(mux::RetryGate::Drop);
            };
            storage.push(prefix.dcid.len() as u8);
            storage.extend_from_slice(prefix.dcid.as_slice());
            crate::packet::Retry::encode_prefix_into(
                &mut storage,
                crate::packet::QUIC_V1,
                prefix.scid,
                new_scid.as_ref_id(),
            );
            secret.issue_into(&mut storage, &from, prefix.dcid, expiry);
            let Ok(integrity_tag) = crate::packet::Retry::tag_from_aad(&storage) else {
                self.recycle_packet(storage);
                return Ok(mux::RetryGate::Drop);
            };
            storage.extend_from_slice(&integrity_tag);
            let packet = match dope::manifold::datagram::OwnedSuffix::new(storage, pseudo_len) {
                Ok(packet) => packet,
                Err(storage) => {
                    self.recycle_packet(storage);
                    return Ok(mux::RetryGate::Drop);
                }
            };
            return Ok(
                if self.push_or_recycle(crate::mux::Outgoing::Suffix(from, packet)) {
                    mux::RetryGate::IssuedRetry
                } else {
                    mux::RetryGate::Drop
                },
            );
        }
        let now_secs = crate::clock::WallClock::now().unix_seconds();
        match secret.validate(&from, prefix.token, now_secs) {
            None => Ok(mux::RetryGate::Drop),
            Some(odcid) => Ok(mux::RetryGate::Accept(Some(odcid))),
        }
    }

    fn emit_stateless_reset(&mut self, from: net::SocketAddr, trigger: &[u8]) -> bool {
        let Some(server_config) = self.server.as_ref().map(|server| &server.config) else {
            return false;
        };
        let Some(reset_secret) = server_config.stateless_reset_secret else {
            return false;
        };
        let secret = crate::secrets::StatelessResetSecret(reset_secret);
        let Some(dcid) = crate::mux::setup::dcid(trigger, mux::ROUTED_CID_LEN) else {
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

    fn receive_stateless_reset(
        &mut self,
        from: net::SocketAddr,
        datagram: &[u8],
        now: time::Instant,
    ) -> bool {
        let Some(token) = crate::conn::path::StatelessResetToken::from_datagram(datagram) else {
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

    fn gen_cid(&mut self, prefix: Option<u8>) -> Option<packet::ConnectionId> {
        let attempts = self
            .registry
            .active_conns
            .saturating_mul(crate::mux::MAX_CIDS_PER_CONN)
            .saturating_add(1);
        for _ in 0..attempts {
            self.registry.indexes.cid_counter = self.registry.indexes.cid_counter.wrapping_add(1);
            let sequence = self.registry.indexes.cid_counter.to_le_bytes();
            let mut out = [0; crate::packet::MAX_CONNECTION_ID_LEN];
            let prefix_len = usize::from(prefix.is_some());
            for index in 0..mux::ROUTED_CID_LEN {
                out[index] =
                    sequence[(index.saturating_sub(prefix_len)) % sequence.len()] ^ index as u8;
            }
            if let Some(prefix) = prefix {
                out[0] = prefix;
            }
            let cid = packet::ConnectionId::new(&out[..mux::ROUTED_CID_LEN])
                .expect("the mux CID width is protocol-valid");
            if self.find_cid(cid.as_slice()).is_none() {
                return Some(cid);
            }
        }
        None
    }
}
