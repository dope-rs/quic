use std::num::NonZero;

use o3::mem::quota;
use rustls::ServerConfig;

use crate::{conn::life, errors};
use life::{accept, initial};

/// Native server policy with an exact borrowed active-handshake limit.
pub struct Pool<const DOMAIN: u8 = 0> {
    auth: accept::Authority<DOMAIN>,
    permits: quota::Ledger,
    capacity: NonZero<usize>,
}

impl<const DOMAIN: u8> Pool<DOMAIN> {
    pub fn new(auth: accept::Authority<DOMAIN>, capacity: NonZero<usize>) -> Self {
        Self {
            auth,
            permits: quota::Ledger::new(capacity.get()),
            capacity,
        }
    }

    pub const fn authority(&self) -> &accept::Authority<DOMAIN> {
        &self.auth
    }

    pub const fn capacity(&self) -> usize {
        self.capacity.get()
    }

    pub fn accept(
        &self,
        ids: accept::Ids,
    ) -> Result<life::Connection<'_, DOMAIN>, errors::Connect> {
        let (core, permit) =
            initial::Acceptor::new(ids, self.auth.options().copy()).try_pooled(self)?;
        Ok(life::Connection::new(core, permit))
    }

    pub fn reconfigure(&self, config: ServerConfig) -> Result<(), errors::Connect> {
        self.auth.reconfigure(config)
    }

    pub(crate) fn reserve(&self) -> Result<super::Permit<'_>, errors::Connect> {
        self.permits.open().ok_or(errors::Connect::Capacity)
    }
}
