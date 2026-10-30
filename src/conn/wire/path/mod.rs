use std::{net, num, time};

use o3::depot::capacity;

pub(crate) mod address;
pub(crate) mod local;
pub(crate) mod origin;
pub(crate) mod peer;
pub mod probe;
pub(crate) mod reset;
pub(crate) mod setup;
pub(crate) mod view;

use crate::conn;
use crate::conn::output::control;
use crate::wire::frame::decode;
use crate::wire::packet::{cid, header};

use address::state;
pub(crate) use local::{LocalCidKey, RouteKey};

pub(in crate::conn) struct State {
    pub(in crate::conn) peer: peer::Peer,
    pub(in crate::conn) local: local::State,
    pub(in crate::conn) origin: origin::State,
    address: state::State,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub(in crate::conn) struct Key(num::NonZero<u64>);

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub(in crate::conn) struct ControlKey(num::NonZero<u64>);

#[must_use]
pub(in crate::conn) struct OutputPermit {
    route: OutputRoute,
    ceiling: usize,
}

impl OutputPermit {
    pub(in crate::conn) const fn ceiling(&self) -> usize {
        self.ceiling
    }

    pub(in crate::conn) fn into_route(self) -> OutputRoute {
        self.route
    }

    pub(in crate::conn) const fn route(&self) -> OutputRoute {
        self.route
    }
}

#[derive(Clone, Copy)]
pub(in crate::conn) struct OutputRoute {
    path: Option<Key>,
}

impl OutputRoute {
    pub(in crate::conn) const ACTIVE: Self = Self { path: None };

    pub(in crate::conn) const fn path(self) -> Option<Key> {
        self.path
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Address {
    Capacity {
        address: net::SocketAddr,
        reason: capacity::Reason,
    },
    Keys {
        address: net::SocketAddr,
        next: u64,
    },
    Bytes {
        address: net::SocketAddr,
        received: u64,
        bytes: usize,
    },
    Deadline {
        now: time::Instant,
        period: time::Duration,
    },
}

#[derive(Clone, Copy, Debug)]
pub enum Error {
    Policy {
        active: net::SocketAddr,
        source: net::SocketAddr,
    },
    Address(Address),
    Peer(capacity::Reason),
    Probe(probe::Error),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::conn) enum Migration {
    Pending,
    Committed,
}

impl State {
    pub(in crate::conn) fn new(setup: setup::Setup<'_>) -> Self {
        let setup::Setup {
            identities:
                setup::Identities {
                    local_cid: local,
                    original_dcid: original,
                    peer_cid: peer,
                    peer_first_scid: first,
                },
            tokens,
            peer_shard: shard,
            stateless_reset_secret: reset,
            options,
        } = setup;
        let side = tokens.initiator();
        let limit = options.cid_limit();
        let fixed = options.is_fixed();
        Self {
            peer: peer::Peer::new(peer, shard),
            local: local::State::new(local, reset, limit),
            origin: origin::State::new(original, first, tokens),
            address: state::State::new(side, fixed),
        }
    }

    pub(in crate::conn) const fn ingress(&self) -> view::Ingress<'_> {
        view::Ingress::new(self)
    }

    pub(in crate::conn) const fn output(&self) -> view::Output<'_> {
        view::Output::new(self)
    }

    pub(in crate::conn) fn bind(&mut self, address: net::SocketAddr) {
        if self.address.active.is_none() {
            self.address.active = Some(address);
        }
    }

    pub(in crate::conn) fn begin(
        &mut self,
        address: net::SocketAddr,
        bytes: usize,
        token: Option<[u8; 8]>,
    ) {
        self.address.ingress = Some(state::Ingress {
            address,
            bytes,
            challenge: token,
        });
    }

    pub(in crate::conn) fn end(&mut self, control: &control::Pending) {
        let seen = self
            .address
            .ingress
            .and_then(|source| self.address.key_for(source.address));
        self.address.ingress = None;
        if let Some(path) = seen {
            self.sweep(path, control);
        }
    }

    pub(in crate::conn) fn try_admit(
        &mut self,
        control: &mut control::Pending,
        now: time::Instant,
        pto: time::Duration,
    ) -> conn::Ingress<Result<(), Error>> {
        let mut effects = conn::Effects::none();
        let result = (|| {
            let Some(source) = self.address.ingress else {
                return Ok(());
            };
            let Some(active) = self.address.active else {
                self.address.active = Some(source.address);
                effects.merge(conn::Effects::from_bits(conn::Effects::ROUTING));
                return Ok(());
            };
            if source.address == active {
                return Ok(());
            }
            if !self.address.allows(active, source.address) {
                return Err(Error::Policy {
                    active,
                    source: source.address,
                });
            }
            let path = self
                .address
                .try_observe(source.address, source.bytes)
                .map_err(Error::Address)?;
            if self
                .address
                .candidate
                .is_some_and(|item| item.path() == path)
            {
                effects.merge(conn::Effects::from_bits(conn::Effects::TRANSMIT));
                return Ok(());
            }
            let Some(data) = source.challenge else {
                return Ok(());
            };
            let deadline = now
                .checked_add(pto)
                .ok_or(Error::Address(Address::Deadline { now, period: pto }))?;
            let next = state::Candidate::new(path, deadline);
            let old = self.address.candidate.map(state::Candidate::path);
            if old.is_some() {
                self.peer.try_abandon(control).map_err(Error::Peer)?;
                effects.merge(conn::Effects::from_bits(conn::Effects::TRANSMIT));
            }
            if let Err(error) = control.queue().try_replace(data, path, old) {
                if let Some(old) = old {
                    control.challenges().abandon(old);
                    self.address.candidate = None;
                    self.sweep(old, control);
                }
                return Err(Error::Probe(error));
            }
            self.peer.reserve();
            self.address.candidate = Some(next);
            if let Some(old) = old {
                self.sweep(old, control);
            }
            effects.merge(conn::Effects::from_bits(conn::Effects::TRANSMIT));
            Ok(())
        })();
        conn::Ingress::new(result, effects)
    }

    pub(in crate::conn) fn try_service(
        &mut self,
        now: time::Instant,
        pto: time::Duration,
        token: Option<[u8; 8]>,
        control: &mut control::Pending,
    ) -> Result<conn::Effects, capacity::Reason> {
        let Some(item) = self.address.candidate else {
            return Ok(conn::Effects::none());
        };
        let Some(deadline) = item.deadline() else {
            return Ok(conn::Effects::none());
        };
        if now < deadline {
            return Ok(conn::Effects::none());
        }
        if item.is_expired(now, pto) {
            return self.try_expire(item.path(), control);
        }
        let Some(data) = token else {
            return self.try_expire(item.path(), control);
        };
        let Some(item) = self.address.candidate.as_mut() else {
            return Ok(conn::Effects::none());
        };
        let path = item.path();
        match control.queue().try_path(data, Some(path)) {
            Ok(()) => {
                if item.retry(pto).is_some() {
                    Ok(conn::Effects::from_bits(conn::Effects::TRANSMIT))
                } else {
                    self.try_expire(path, control)
                }
            }
            Err(
                probe::Error::Duplicate { .. }
                | probe::Error::Capacity { .. }
                | probe::Error::Keys { .. }
                | probe::Error::State { .. },
            ) => self.try_expire(path, control),
        }
    }

    fn try_expire(
        &mut self,
        path: Key,
        control: &mut control::Pending,
    ) -> Result<conn::Effects, capacity::Reason> {
        self.peer.try_abandon(control)?;
        control.challenges().abandon(path);
        self.address.candidate = None;
        self.sweep(path, control);
        Ok(conn::Effects::from_bits(conn::Effects::TRANSMIT))
    }

    pub(in crate::conn) fn transmit(
        &mut self,
        path: Option<Key>,
        bytes: usize,
        control: &control::Pending,
    ) -> conn::Effects {
        'record: {
            let Some(path) = path else {
                break 'record;
            };
            if self
                .address
                .candidate
                .is_some_and(|item| item.path() == path)
            {
                self.peer.use_spare();
            }
            let active = self.address.active;
            let Some(item) = self.address.get_mut(path) else {
                break 'record;
            };
            if Some(item.address) != active {
                let Some(sent) = item.sent.checked_add(bytes as u64) else {
                    break 'record;
                };
                item.sent = sent;
            }
            self.sweep(path, control);
        }
        if self.peer.is_dirty() {
            conn::Effects::from_bits(conn::Effects::ROUTING)
        } else {
            conn::Effects::none()
        }
    }

    pub(in crate::conn) fn try_respond(
        &mut self,
        token: [u8; 8],
        control: &mut control::Pending,
    ) -> Result<(), capacity::Reason> {
        let key = match control.queue().try_respond(token)? {
            probe::Completion::Unmatched | probe::Completion::Accepted(None) => return Ok(()),
            probe::Completion::Accepted(Some(key)) => key,
        };
        if let Some(item) = self
            .address
            .candidate
            .as_mut()
            .filter(|item| item.path() == key)
        {
            item.validate();
            control.challenges().abandon(key);
        }
        Ok(())
    }

    /// Only the newest authenticated non-probing 1-RTT packet carries intent.
    pub(in crate::conn) fn observe(&mut self, number: header::Number) {
        if self
            .address
            .highest_non_probing
            .is_some_and(|prior| number <= prior)
        {
            return;
        }
        self.address.highest_non_probing = Some(number);
        let ingress = self.ingress().response();
        if let Some(item) = self.address.candidate.as_mut() {
            item.observe(ingress == Some(item.path()));
        }
    }

    /// Reachability and the latest migration intent may arrive in either order.
    pub(in crate::conn) fn try_migrate(
        &mut self,
        control: &mut control::Pending,
    ) -> Result<Migration, capacity::Reason> {
        let Some(item) = self.address.candidate.as_ref() else {
            return Ok(Migration::Pending);
        };
        if !item.is_complete() {
            return Ok(Migration::Pending);
        }
        self.peer.try_activate(control)?;
        let path = item.path();
        let Some(address) = self.address.get(path).map(|item| item.address) else {
            return Ok(Migration::Pending);
        };
        control.challenges().abandon(path);
        self.address.active = Some(address);
        self.address.candidate = None;
        self.sweep(path, control);
        Ok(Migration::Committed)
    }

    fn sweep(&mut self, path: Key, control: &control::Pending) {
        if self
            .address
            .candidate
            .is_some_and(|item| item.path() == path)
            || control.probe().has_path(path)
        {
            return;
        }
        self.address.remove(path);
    }

    pub(in crate::conn) fn set_peer(&mut self, id: cid::Id) -> Result<(), conn::Error> {
        self.peer.set_id(id)?;
        self.origin.peer_first_scid = Some(id);
        Ok(())
    }

    pub(in crate::conn) fn accept(
        &mut self,
        update: decode::Notice<cid::Id>,
        retire: decode::Retire,
        control: &mut control::Pending,
    ) -> Result<(), peer::Error> {
        self.peer.accept_cid(
            control,
            self.local.active_connection_id_limit,
            update,
            retire,
        )?;
        if self.address.candidate.is_some() {
            self.peer.reserve();
        }
        Ok(())
    }
}

const _: () = {
    assert!(std::mem::size_of::<LocalCidKey>() == 8);
    assert!(std::mem::size_of::<RouteKey>() == 8);
    assert!(std::mem::size_of::<Key>() == 8);
    assert!(std::mem::size_of::<ControlKey>() == 8);
    assert!(std::mem::size_of::<OutputRoute>() == 8);
    assert!(std::mem::size_of::<OutputPermit>() == 16);
};
