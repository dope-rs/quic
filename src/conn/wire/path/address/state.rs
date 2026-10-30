use std::{mem, net, num, time};

use crate::conn::wire::storage;

use crate::conn;
use crate::conn::wire::path;
use crate::conn::wire::path::address;
use crate::wire::packet::header;
use crate::wire::stream::Initiator;

use address::policy;
use path::Address;

#[derive(Clone, Copy)]
pub(in crate::conn::wire::path) struct Ingress {
    pub(in crate::conn::wire::path) address: net::SocketAddr,
    pub(in crate::conn::wire::path) bytes: usize,
    pub(in crate::conn::wire::path) challenge: Option<[u8; 8]>,
}

#[derive(Clone, Copy)]
pub(in crate::conn::wire::path) struct Candidate {
    path: path::Key,
    deadline: time::Instant,
    attempt: Attempt,
    proof: Proof,
}

#[derive(Clone, Copy)]
enum Attempt {
    First,
    Second,
    Last,
}

#[derive(Clone, Copy)]
enum Proof {
    None,
    Reachable,
    NonProbing,
    Complete,
}

impl Attempt {
    const fn can_retry(self) -> bool {
        !matches!(self, Self::Last)
    }

    const fn left(self) -> u32 {
        match self {
            Self::First => 2,
            Self::Second => 1,
            Self::Last => 0,
        }
    }

    fn advance(self) -> Option<Self> {
        match self {
            Self::First => Some(Self::Second),
            Self::Second => Some(Self::Last),
            Self::Last => None,
        }
    }
}

impl Proof {
    const fn is_validated(self) -> bool {
        matches!(self, Self::Reachable | Self::Complete)
    }

    const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    const fn validate(self) -> Self {
        match self {
            Self::None | Self::Reachable => Self::Reachable,
            Self::NonProbing | Self::Complete => Self::Complete,
        }
    }

    const fn observe(self, active: bool) -> Self {
        match (self.is_validated(), active) {
            (false, false) => Self::None,
            (false, true) => Self::NonProbing,
            (true, false) => Self::Reachable,
            (true, true) => Self::Complete,
        }
    }
}

impl Candidate {
    pub(in crate::conn::wire::path) fn new(path: path::Key, deadline: time::Instant) -> Self {
        Self {
            path,
            deadline,
            attempt: Attempt::First,
            proof: Proof::None,
        }
    }

    pub(in crate::conn::wire::path) const fn path(self) -> path::Key {
        self.path
    }

    pub(in crate::conn::wire::path) const fn deadline(self) -> Option<time::Instant> {
        if self.proof.is_validated() {
            None
        } else {
            Some(self.deadline)
        }
    }

    pub(in crate::conn::wire::path) fn is_retry_due(self, now: time::Instant) -> bool {
        !self.proof.is_validated() && now >= self.deadline && self.attempt.can_retry()
    }

    pub(in crate::conn::wire::path) fn is_expired(
        self,
        now: time::Instant,
        pto: time::Duration,
    ) -> bool {
        let Some(expiry) = pto
            .checked_mul(self.attempt.left())
            .and_then(|delay| self.deadline.checked_add(delay))
        else {
            return false;
        };
        now >= expiry
    }

    pub(in crate::conn::wire::path) fn retry(&mut self, pto: time::Duration) -> Option<Retried> {
        if self.proof.is_validated() || !self.attempt.can_retry() {
            return None;
        }
        let deadline = self.deadline.checked_add(pto)?;
        let attempt = self.attempt.advance()?;
        self.deadline = deadline;
        self.attempt = attempt;
        Some(Retried)
    }

    pub(in crate::conn::wire::path) const fn validate(&mut self) {
        self.proof = self.proof.validate();
    }

    pub(in crate::conn::wire::path) const fn observe(&mut self, active: bool) {
        self.proof = self.proof.observe(active);
    }

    pub(in crate::conn::wire::path) const fn is_complete(self) -> bool {
        self.proof.is_complete()
    }
}

pub(in crate::conn::wire::path) struct Retried;

pub(in crate::conn::wire::path) struct Observed {
    pub(in crate::conn::wire::path) key: path::Key,
    pub(in crate::conn::wire::path) address: net::SocketAddr,
    pub(in crate::conn::wire::path) received: u64,
    pub(in crate::conn::wire::path) sent: u64,
}

pub(in crate::conn::wire::path) struct State {
    pub(in crate::conn::wire::path) active: Option<net::SocketAddr>,
    pub(in crate::conn::wire::path) ingress: Option<Ingress>,
    pub(in crate::conn::wire::path) candidate: Option<Candidate>,
    pub(in crate::conn::wire::path) highest_non_probing: Option<header::Number>,
    pub(in crate::conn::wire::path) observed: storage::Vec<Observed, { conn::MAX_PATH_TOKENS }>,
    next_path_key: num::NonZero<u64>,
    policy: policy::Policy,
}

impl State {
    pub(in crate::conn::wire::path) fn new(local: Initiator, fixed: bool) -> Self {
        Self {
            active: None,
            ingress: None,
            candidate: None,
            highest_non_probing: None,
            observed: storage::Vec::new(),
            next_path_key: num::NonZero::<u64>::MIN,
            policy: policy::Policy::new(local, fixed),
        }
    }

    pub(in crate::conn::wire::path) fn allows(
        &self,
        active: net::SocketAddr,
        source: net::SocketAddr,
    ) -> bool {
        self.policy.allows(active, source)
    }

    pub(in crate::conn::wire::path) fn key_for(
        &self,
        address: net::SocketAddr,
    ) -> Option<path::Key> {
        self.observed
            .iter()
            .find(|path| path.address == address)
            .map(|path| path.key)
    }

    pub(in crate::conn::wire::path) fn get(&self, key: path::Key) -> Option<&Observed> {
        self.observed.iter().find(|path| path.key == key)
    }

    pub(in crate::conn::wire::path) fn get_mut(&mut self, key: path::Key) -> Option<&mut Observed> {
        self.observed.iter_mut().find(|path| path.key == key)
    }

    pub(in crate::conn::wire::path) fn try_observe(
        &mut self,
        address: net::SocketAddr,
        bytes: usize,
    ) -> Result<path::Key, Address> {
        if let Some(path) = self
            .observed
            .iter_mut()
            .find(|path| path.address == address)
        {
            let Some(received) = path.received.checked_add(bytes as u64) else {
                return Err(Address::Bytes {
                    address,
                    received: path.received,
                    bytes,
                });
            };
            path.received = received;
            return Ok(path.key);
        }
        let growth = self
            .observed
            .try_insert()
            .map_err(|reason| Address::Capacity { address, reason })?;
        let next = self.next_path_key;
        let Some(after) = next.checked_add(1) else {
            return Err(Address::Keys {
                address,
                next: next.get(),
            });
        };
        let key = path::Key(next);
        self.next_path_key = after;
        growth.push(Observed {
            key,
            address,
            received: bytes as u64,
            sent: 0,
        });
        Ok(key)
    }

    pub(in crate::conn::wire::path) fn remove(&mut self, key: path::Key) {
        self.observed.remove(|path| path.key == key);
    }
}

const _: () = {
    assert!(mem::size_of::<Attempt>() == 1);
    assert!(mem::size_of::<Proof>() == 1);
    assert!(mem::size_of::<Candidate>() == 32);
    assert!(!mem::needs_drop::<Candidate>());
    assert!(mem::size_of::<storage::Vec<Observed, { conn::MAX_PATH_TOKENS }>>() == 120);
};
