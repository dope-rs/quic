use std::{cell::RefCell, sync::Arc};

use o3::{base::marker::ThreadBound, buffer};
use rustls::{
    ServerConfig,
    server::{NoServerSessionStorage, ServerSessionMemoryCache},
};

use crate::{conn, errors, proto::early, security::secrets, wire::packet::cid};
use conn::life::{initial, options};

/// Connection IDs required to construct one server-side QUIC connection.
pub struct Ids {
    pub(super) initial_dcid: cid::Id,
    pub(super) local_cid: cid::Id,
    pub(super) peer_cid: cid::Id,
    pub(super) tp_original_dcid: cid::Id,
    pub(super) retry_scid: Option<cid::Id>,
    pub(super) peer_address_validated: bool,
    pub(super) issued_address_token: Option<[u8; secrets::Address::WIRE_LEN]>,
}

impl Ids {
    /// Creates IDs for a connection accepted directly from its first Initial.
    pub fn initial(dcid: cid::Id, local: cid::Id, peer: cid::Id) -> Self {
        Self {
            initial_dcid: dcid,
            local_cid: local,
            peer_cid: peer,
            tp_original_dcid: dcid,
            retry_scid: None,
            peer_address_validated: false,
            issued_address_token: None,
        }
    }

    /// Creates IDs for a connection accepted after a validated Retry.
    pub fn retry(
        dcid: cid::Id,
        local: cid::Id,
        peer: cid::Id,
        orig: cid::Id,
        scid: cid::Id,
    ) -> Self {
        Self {
            initial_dcid: dcid,
            local_cid: local,
            peer_cid: peer,
            tp_original_dcid: orig,
            retry_scid: Some(scid),
            peer_address_validated: true,
            issued_address_token: None,
        }
    }

    pub(crate) fn validated(dcid: cid::Id, local: cid::Id, peer: cid::Id) -> Self {
        Self {
            initial_dcid: dcid,
            local_cid: local,
            peer_cid: peer,
            tp_original_dcid: dcid,
            retry_scid: None,
            peer_address_validated: true,
            issued_address_token: None,
        }
    }

    pub(crate) fn with_token(mut self, token: Option<[u8; secrets::Address::WIRE_LEN]>) -> Self {
        self.issued_address_token = token;
        self
    }
}

/// One worker's native TLS policy, session domain, and transport parameters.
pub struct Authority<const DOMAIN: u8 = 0> {
    options: options::Options,
    config: RefCell<Arc<ServerConfig>>,
    capacity: early::ReplayCap,
    _bound: ThreadBound,
}

impl<const DOMAIN: u8> Authority<DOMAIN> {
    pub fn new(config: ServerConfig, opts: options::Options) -> Result<Self, errors::Connect> {
        Self::from_parts(config, opts, None)
    }

    pub fn with_early(
        config: ServerConfig,
        opts: options::Options,
        capacity: early::ReplayCap,
    ) -> Result<Self, errors::Connect> {
        Self::from_parts(config, opts, Some(capacity))
    }

    pub fn accept<D: buffer::raw::Segment>(
        &self,
        ids: Ids,
    ) -> Result<conn::Connection<DOMAIN, Vec<u8>, D>, errors::Connect> {
        initial::Acceptor::new(ids, self.options.copy()).try_owned(self.config())
    }

    /// Future handshakes receive a fresh session domain for this policy.
    pub fn reconfigure(&self, config: ServerConfig) -> Result<(), errors::Connect> {
        let config = Self::prepare(config, self.capacity)?;
        self.config.replace(config);
        Ok(())
    }

    /// Rejects early data while retaining valid tickets for resumption.
    pub fn reject_early(&self) {
        let mut config = self.config.borrow_mut();
        if config.max_early_data_size != 0 {
            Arc::make_mut(&mut config).max_early_data_size = 0;
        }
    }

    pub(crate) fn config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.config.borrow())
    }

    pub(crate) const fn options(&self) -> &options::Options {
        &self.options
    }

    pub(crate) fn from_parts(
        mut config: ServerConfig,
        opts: options::Options,
        cap: Option<early::ReplayCap>,
    ) -> Result<Self, errors::Connect> {
        let capacity = match cap {
            Some(cap) => {
                config.max_early_data_size = u32::MAX;
                if config.send_tls13_tickets == 0 {
                    config.send_tls13_tickets = 1;
                }
                cap
            }
            None => early::ReplayCap::fixed::<256>(),
        };
        Ok(Self {
            options: opts,
            config: RefCell::new(Self::prepare(config, capacity)?),
            capacity,
            _bound: ThreadBound::NEW,
        })
    }

    /// Bounds native session retention by the admitted replay quota.
    fn prepare(
        mut config: ServerConfig,
        capacity: early::ReplayCap,
    ) -> Result<Arc<ServerConfig>, errors::Connect> {
        if !matches!(config.max_early_data_size, 0 | u32::MAX) || config.ticketer.enabled() {
            return Err(errors::Connect::InvalidConfig);
        }
        config.session_storage = if config.send_tls13_tickets == 0 {
            Arc::new(NoServerSessionStorage {})
        } else {
            ServerSessionMemoryCache::new(capacity.get())
        };
        Ok(Arc::new(config))
    }
}
