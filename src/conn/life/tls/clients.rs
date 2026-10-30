use std::{num::NonZero, ptr, sync::Arc};

use o3::{
    alloc, buffer,
    mem::{self, quota, rc},
};
use rustls::{ClientConfig, pki_types::ServerName};

use crate::{conn, errors, runtime::routing, stream, wire::packet::cid};
use conn::life;
use life::{initial, options};

/// One worker's native authentication policy and session cache.
pub struct Authority {
    policy: mem::raw::Owner<Policy, usize>,
}

struct Policy {
    count: mem::raw::Count<usize>,
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
}

impl Policy {
    fn try_new(value: Self) -> Result<mem::raw::Owner<Self, usize>, alloc::Exhausted> {
        let owner: Box<Self> = alloc::BoxExt::try_new(value)?;
        // SAFETY: the allocation transfers its one initialized counted edge.
        Ok(unsafe { mem::raw::Owner::from_raw(ptr::NonNull::from(Box::leak(owner))) })
    }
}

// SAFETY: every owning edge uses this policy's stable, private count.
unsafe impl mem::raw::Edge<usize> for Policy {
    fn count(&self) -> &mem::raw::Count<usize> {
        &self.count
    }
}

// SAFETY: the last edge transfers the original allocation and both native owners.
unsafe impl mem::raw::Target<usize> for Policy {
    unsafe fn destroy(pointer: ptr::NonNull<Self>) {
        // SAFETY: this is the unique original Box after its final edge ended.
        unsafe { drop(Box::from_raw(pointer.as_ptr())) };
    }
}

impl Authority {
    pub fn try_new(
        config: ClientConfig,
        name: ServerName<'static>,
    ) -> Result<Self, alloc::Exhausted> {
        let config = Arc::new(config);
        let policy = Policy {
            count: mem::raw::Count::one(),
            config,
            name,
        };
        Ok(Self {
            policy: Policy::try_new(policy)?,
        })
    }

    pub fn try_clone(&self) -> Result<Self, rc::Error> {
        Ok(Self {
            policy: self.policy.try_clone()?,
        })
    }

    pub fn connect<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>(
        &self,
        dcid: cid::Id,
        local: cid::Id,
        opts: options::Options,
        route: impl routing::PeerRoute,
    ) -> Result<conn::Connection<DOMAIN, B, D>, errors::Connect> {
        if !route.matches(&dcid) {
            return Err(errors::Connect::InvalidConfig);
        }
        initial::Client::new(dcid, local, opts).try_direct(self.try_clone()?, route, None)
    }

    /// Reuses an address token; TLS selects its own cached session.
    pub fn reconnect<const DOMAIN: u8>(
        &self,
        dcid: cid::Id,
        local: cid::Id,
        opts: options::Options,
        saved: life::Reconnect,
        route: impl routing::PeerRoute,
    ) -> Result<conn::Connection<DOMAIN>, errors::Reconnect> {
        if !self.matches(saved.auth()) {
            return Err(errors::Reconnect::retained(
                errors::Preflight::AuthorityMismatch,
                saved,
            ));
        }
        if !route.matches(&dcid) || !saved.matches_path(route) {
            return Err(errors::Reconnect::retained(
                errors::Preflight::InvalidConfig,
                saved,
            ));
        }
        let (token, auth) = saved.into_parts();
        initial::Client::new(dcid, local, opts)
            .try_direct(auth, route, Some(token))
            .map_err(errors::Reconnect::consumed)
    }

    pub(crate) fn matches(&self, other: &Self) -> bool {
        self.policy.as_ptr() == other.policy.as_ptr()
    }

    pub(in crate::conn) fn config(&self) -> &Arc<ClientConfig> {
        &self.policy.get().config
    }

    pub(in crate::conn) fn name(&self) -> ServerName<'static> {
        self.policy.get().name.clone()
    }
}

/// Native TLS policy with a borrowed limit on active handshakes.
pub struct Pool {
    auth: Authority,
    permits: quota::Ledger,
    capacity: NonZero<usize>,
}

impl Pool {
    pub fn new(auth: Authority, capacity: NonZero<usize>) -> Self {
        Self {
            auth,
            permits: quota::Ledger::new(capacity.get()),
            capacity,
        }
    }

    pub const fn authority(&self) -> &Authority {
        &self.auth
    }

    pub fn connect<const DOMAIN: u8>(
        &self,
        dcid: cid::Id,
        local: cid::Id,
        opts: options::Options,
        route: impl routing::PeerRoute,
    ) -> Result<life::Connection<'_, DOMAIN>, errors::Connect> {
        let permit = self.reserve()?;
        let core = self.auth.connect(dcid, local, opts, route)?;
        Ok(life::Connection::new(core, permit))
    }

    pub fn reconnect<const DOMAIN: u8>(
        &self,
        dcid: cid::Id,
        local: cid::Id,
        opts: options::Options,
        saved: life::Reconnect,
        route: impl routing::PeerRoute,
    ) -> Result<life::Connection<'_, DOMAIN>, errors::Reconnect> {
        if !self.auth.matches(saved.auth()) {
            return Err(errors::Reconnect::retained(
                errors::Preflight::AuthorityMismatch,
                saved,
            ));
        }
        if !route.matches(&dcid) || !saved.matches_path(route) {
            return Err(errors::Reconnect::retained(
                errors::Preflight::InvalidConfig,
                saved,
            ));
        }
        let permit = match self.reserve() {
            Ok(permit) => permit,
            Err(error) => return Err(errors::Reconnect::retained(error, saved)),
        };
        let (token, auth) = saved.into_parts();
        let core = initial::Client::new(dcid, local, opts)
            .try_direct(auth, route, Some(token))
            .map_err(errors::Reconnect::consumed)?;
        Ok(life::Connection::new(core, permit))
    }

    pub const fn capacity(&self) -> usize {
        self.capacity.get()
    }

    pub(crate) fn reserve(&self) -> Result<super::Permit<'_>, errors::Preflight> {
        self.permits.open().ok_or(errors::Preflight::Capacity)
    }
}
