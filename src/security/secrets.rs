use o3::{
    alloc,
    base::{marker::ThreadBound, time::Positive},
    buffer::write,
};
use std::net;
use write::Sink as _;

use aws_lc_rs::hmac;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize as _;

use crate::{proto::epoch, wire::packet::cid};

pub(crate) const RETRY_TOKEN_TTL: Positive = Positive::from_secs::<10>();
pub(crate) const ADDRESS_TOKEN_TTL: Positive = Positive::from_secs::<{ 7 * 24 * 60 * 60 }>();
const TOKEN_TAG_LEN: usize = 16;

pub(crate) const SOCKET_ADDR_LEN: usize = 1 + 16 + 2 + 4 + 4;

/// Canonical, lossless address representation shared by every stateless
/// address capability.  Including IPv6 flow and scope prevents two local
/// interfaces with the same link-local address from sharing auth.
pub(crate) fn encode_socket_addr(addr: net::SocketAddr) -> [u8; SOCKET_ADDR_LEN] {
    let mut encoded = [0; SOCKET_ADDR_LEN];
    match addr {
        net::SocketAddr::V4(addr) => {
            encoded[0] = 4;
            encoded[1..5].copy_from_slice(&addr.ip().octets());
            encoded[17..19].copy_from_slice(&addr.port().to_be_bytes());
        }
        net::SocketAddr::V6(addr) => {
            encoded[0] = 6;
            encoded[1..17].copy_from_slice(&addr.ip().octets());
            encoded[17..19].copy_from_slice(&addr.port().to_be_bytes());
            encoded[19..23].copy_from_slice(&addr.flowinfo().to_be_bytes());
            encoded[23..27].copy_from_slice(&addr.scope_id().to_be_bytes());
        }
    }
    encoded
}

/// Exclusively owns a SHA-256 context and retains its 32-byte output proof.
#[derive(Debug)]
struct Context {
    inner: hmac::Context,
    _bound: ThreadBound,
}

impl Context {
    fn new(secret: &[u8; 32]) -> Self {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
        Self {
            inner: hmac::Context::with_key(&key),
            _bound: ThreadBound::NEW,
        }
    }

    /// Canonical HMAC prefix shared by time-bounded address capabilities.
    fn address(secret: &[u8; 32], domain: &[u8], addr: net::SocketAddr, expiry: u64) -> Self {
        let mut ctx = Self::new(secret);
        ctx.update(domain);
        ctx.update(&encode_socket_addr(addr));
        ctx.update(&expiry.to_be_bytes());
        ctx
    }

    fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    fn finish(self) -> [u8; TOKEN_TAG_LEN] {
        const { assert!(TOKEN_TAG_LEN <= 32, "tag") };
        let tag = self.inner.sign();
        // SAFETY: new selects HMAC_SHA256 and no operation replaces that
        // algorithm. AWS-LC's successful sign returns its 32-byte tag; the
        // fixed prefix is read while the exclusively owned tag remains live.
        unsafe { tag.as_ref().as_ptr().cast::<[u8; TOKEN_TAG_LEN]>().read() }
    }
}

#[derive(Clone)]
pub(crate) struct Reset(pub(crate) [u8; 32]);

impl Drop for Reset {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

impl Reset {
    pub(crate) fn token_for(&self, cid: &[u8]) -> [u8; 16] {
        let mut ctx = Context::new(&self.0);
        ctx.update(b"qsrt");
        ctx.update(cid);
        ctx.finish()
    }
}

#[derive(Clone)]
pub(crate) struct Retry(pub(crate) [u8; 32]);

impl Drop for Retry {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

impl Retry {
    const FIXED_LEN: usize = 8 + 1 + TOKEN_TAG_LEN;

    pub(crate) const fn encoded_len(odcid: cid::Ref<'_>) -> usize {
        Self::FIXED_LEN + odcid.len()
    }

    pub(crate) fn issue_into(
        &self,
        out: &mut write::Append<'_>,
        addr: &net::SocketAddr,
        odcid: cid::Ref<'_>,
        scid: cid::Ref<'_>,
        expiry: epoch::TokenExpiry<'_>,
    ) -> Result<(), alloc::Error> {
        let expiry = expiry.unix_seconds();
        let tag = self.tag(addr, odcid, scid, expiry);
        out.write_slices([
            &expiry.to_be_bytes(),
            &[odcid.length().get()],
            odcid.into_slice(),
            &tag,
        ])
    }

    pub(crate) fn validate(
        &self,
        addr: &net::SocketAddr,
        token: &[u8],
        dcid: cid::Ref<'_>,
        now: &epoch::Observed<'_>,
    ) -> Option<cid::Id> {
        if token.len() < Self::FIXED_LEN {
            return None;
        }
        let expiry = u64::from_be_bytes(token[..8].try_into().ok()?);
        if now.unix_seconds() >= expiry {
            return None;
        }
        let len = usize::from(token[8]);
        if token.len() != Self::FIXED_LEN + len {
            return None;
        }
        let odcid = cid::Ref::new(&token[9..9 + len]).ok()?;
        let tag = &token[9 + len..];
        let expected = self.tag(addr, odcid, dcid, expiry);
        if !bool::from(tag.ct_eq(&expected[..])) {
            return None;
        }
        Some(odcid.into_owned())
    }

    fn tag(
        &self,
        addr: &net::SocketAddr,
        odcid: cid::Ref<'_>,
        cid: cid::Ref<'_>,
        expiry: u64,
    ) -> [u8; TOKEN_TAG_LEN] {
        let mut ctx = Context::address(&self.0, b"qretrytok", *addr, expiry);
        ctx.update(&[odcid.length().get()]);
        ctx.update(odcid.into_slice());
        ctx.update(&[cid.length().get()]);
        ctx.update(cid.into_slice());
        ctx.finish()
    }
}

/// Stateless NEW_TOKEN auth borrowing the retained secret. The fixed-width
/// wire value uses a domain distinct from Retry so the two Initial-token
/// capabilities stay distinct when an operator rotates one shared secret.
pub(crate) struct Address<'secret>(pub(crate) &'secret [u8; 32]);

impl Address<'_> {
    pub(crate) const WIRE_LEN: usize = 8 + TOKEN_TAG_LEN;

    pub(crate) fn issue(
        &self,
        addr: &net::SocketAddr,
        expiry: epoch::TokenExpiry<'_>,
    ) -> [u8; Address::WIRE_LEN] {
        let expiry = expiry.unix_seconds();
        let tag = self.tag(addr, expiry);
        let mut wire = [0; Address::WIRE_LEN];
        wire[..8].copy_from_slice(&expiry.to_be_bytes());
        wire[8..].copy_from_slice(&tag);
        wire
    }

    pub(crate) fn is_valid(
        &self,
        addr: &net::SocketAddr,
        wire: &[u8],
        now: &epoch::Observed<'_>,
    ) -> bool {
        if wire.len() != Self::WIRE_LEN {
            return false;
        }
        let Some(expiry) = wire[..8].try_into().ok().map(u64::from_be_bytes) else {
            return false;
        };
        if now.unix_seconds() >= expiry {
            return false;
        }
        let expected = self.tag(addr, expiry);
        bool::from(wire[8..].ct_eq(&expected))
    }

    fn tag(&self, addr: &net::SocketAddr, expiry: u64) -> [u8; TOKEN_TAG_LEN] {
        Context::address(self.0, b"qnewtoken", *addr, expiry).finish()
    }
}
