use dope::core::Errno;
use std::mem;

use dope::core::driver::{self, schedule::sequence};
use dope::runtime::random::{self, Domain, Namespace};
use o3::buffer::{self, resident, storage};

use crate::conn::id;
use crate::{runtime::routing, wire::packet::cid};

const ROOT_DOMAIN: Domain = Namespace::new(*b"quic\0mux").fixed();
const CID_LANE: u64 = u64::from_be_bytes(*b"quic-cid");
const PATH_LANE: u64 = u64::from_be_bytes(*b"quic-pth");
const RESET_LANE: u64 = u64::from_be_bytes(*b"resetpkt");
pub(in crate::runtime) const CID_HASH_LANE: u64 = u64::from_be_bytes(*b"cidhash\0");
pub(in crate::runtime) const RESET_HASH_LANE: u64 = u64::from_be_bytes(*b"rsthash\0");

pub struct Quic;

impl random::Purpose for Quic {
    const DOMAIN: Domain = ROOT_DOMAIN;
}

/// Compile-time execution binding retained by a mux.
/// It fixes random, identity, and send ownership without a runtime policy.
#[doc(hidden)]
pub trait Binding {
    type Authority: Source;
    type Identity: id::Temporal;
    type Send: buffer::raw::Segment;
}

impl Binding for id::Static {
    type Authority = Issuer<random::Process<Quic>>;
    type Identity = Self;
    type Send = storage::Shared;
}

impl<'d> Binding for id::Driver<'d> {
    type Authority = Issuer<random::Root<'d, Quic>>;
    type Identity = Self;
    type Send = resident::Shared<'d>;
}

pub enum Exhausted {
    Exhausted,
}

/// Operations supplied by either statically or driver-bound mux randomness.
#[doc(hidden)]
pub trait Source {
    fn hash_seed<const LANE: u64>(&self) -> random::HashSeed;
    fn entropy(&mut self) -> Option<[u8; routing::ENTROPY_LEN]>;
    fn challenge(&mut self) -> Option<[u8; 8]>;
    fn initial<R: routing::PeerRoute>(&mut self, route: R) -> Option<cid::Id>;
    fn reset(&mut self, output: &mut [u8]) -> Result<(), Exhausted>;
}

/// The single domain-separated random auth for one mux lifetime.
/// One full-width cursor is shared by every compile-time lane.
#[doc(hidden)]
pub struct Issuer<R> {
    root: R,
    next: u64,
    exhausted: bool,
}

impl Issuer<random::Process<Quic>> {
    pub(in crate::runtime::mux) fn random() -> Result<Self, Errno> {
        Ok(Self::new(random::Process::random()?))
    }
}

impl<'d> Issuer<random::Root<'d, Quic>> {
    pub(in crate::runtime::mux) fn for_driver(
        driver: &driver::Context<'_, 'd>,
    ) -> Result<Self, sequence::Exhausted> {
        Ok(Self::new(random::Root::try_acquire(driver)?))
    }
}

impl<R> Issuer<R> {
    const fn new(root: R) -> Self {
        Self {
            root,
            next: 0,
            exhausted: false,
        }
    }

    fn take(&mut self) -> Option<u64> {
        if self.exhausted {
            return None;
        }
        let value = self.next;
        match self.next.checked_add(1) {
            Some(next) => self.next = next,
            None => self.exhausted = true,
        }
        Some(value)
    }
}

impl<R: random::Entropy<Quic>> Source for Issuer<R> {
    fn hash_seed<const LANE: u64>(&self) -> random::HashSeed {
        self.root.hash_seed::<LANE>()
    }

    fn entropy(&mut self) -> Option<[u8; routing::ENTROPY_LEN]> {
        let input = self.take()?;
        Some(self.root.permute::<CID_LANE>(input).into_bytes())
    }

    fn challenge(&mut self) -> Option<[u8; 8]> {
        let input = self.take()?;
        Some(self.root.permute::<PATH_LANE>(input).into_bytes())
    }

    fn initial<T: routing::PeerRoute>(&mut self, route: T) -> Option<cid::Id> {
        Some(route.issue(self.entropy()?))
    }

    fn reset(&mut self, output: &mut [u8]) -> Result<(), Exhausted> {
        for chunk in output.chunks_mut(mem::size_of::<u64>()) {
            let Some(input) = self.take() else {
                return Err(Exhausted::Exhausted);
            };
            let block = self.root.word::<RESET_LANE>(input).into_bytes();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }
}

const _: () = assert!(routing::ENTROPY_LEN == mem::size_of::<u64>());
const _: () = assert!(mem::size_of::<Issuer<random::Process<Quic>>>() == 4 * mem::size_of::<u64>());
