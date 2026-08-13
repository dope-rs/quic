use std::net::SocketAddr;

use ring::hmac;
use ring::hmac::Context;
use ring::hmac::Key;
use subtle::ConstantTimeEq;

use crate::packet::{ConnectionId, ConnectionIdRef};

#[derive(Clone, Copy)]
pub(crate) struct StatelessResetSecret(pub(crate) [u8; 32]);

impl From<[u8; 32]> for StatelessResetSecret {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl StatelessResetSecret {
    pub fn token_for(&self, cid: &[u8]) -> [u8; 16] {
        let key = Key::new(hmac::HMAC_SHA256, &self.0);
        let mut ctx = Context::with_key(&key);
        ctx.update(b"qsrt");
        ctx.update(cid);
        let tag = ctx.sign();
        let mut out = [0u8; 16];
        out.copy_from_slice(&tag.as_ref()[..16]);
        out
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RetryTokenSecret(pub(crate) [u8; 32]);

impl From<[u8; 32]> for RetryTokenSecret {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl RetryTokenSecret {
    const TAG_LEN: usize = 16;
    const FIXED_LEN: usize = 8 + 1 + Self::TAG_LEN;

    pub const fn encoded_len(odcid: ConnectionIdRef<'_>) -> usize {
        Self::FIXED_LEN + odcid.len()
    }

    pub fn issue_into(
        &self,
        out: &mut Vec<u8>,
        addr: &SocketAddr,
        odcid: ConnectionIdRef<'_>,
        expiry_unix_secs: u64,
    ) {
        let (addr_bytes, addr_len) = Self::addr_bytes(addr);
        let odcid = odcid.as_slice();
        let tag = self.tag(&addr_bytes[..addr_len], odcid, expiry_unix_secs);
        out.extend_from_slice(&expiry_unix_secs.to_be_bytes());
        out.push(odcid.len() as u8);
        out.extend_from_slice(odcid);
        out.extend_from_slice(&tag);
    }

    pub fn validate(
        &self,
        addr: &SocketAddr,
        token: &[u8],
        now_unix_secs: u64,
    ) -> Option<ConnectionId> {
        if token.len() < Self::FIXED_LEN {
            return None;
        }
        let expiry = u64::from_be_bytes(token[..8].try_into().ok()?);
        if now_unix_secs >= expiry {
            return None;
        }
        let odcid_len = token[8] as usize;
        if odcid_len > ConnectionId::MAX_LEN {
            return None;
        }
        if token.len() != Self::FIXED_LEN + odcid_len {
            return None;
        }
        let odcid = &token[9..9 + odcid_len];
        let provided_tag = &token[9 + odcid_len..];
        let (addr_bytes, addr_len) = Self::addr_bytes(addr);
        let expected = self.tag(&addr_bytes[..addr_len], odcid, expiry);
        if !bool::from(provided_tag.ct_eq(&expected[..])) {
            return None;
        }
        ConnectionId::new(odcid)
    }

    fn addr_bytes(addr: &SocketAddr) -> ([u8; 19], usize) {
        let mut bytes = [0; 19];
        match addr {
            SocketAddr::V4(a) => {
                bytes[0] = 4;
                bytes[1..5].copy_from_slice(&a.ip().octets());
                bytes[5..7].copy_from_slice(&a.port().to_be_bytes());
                (bytes, 7)
            }
            SocketAddr::V6(a) => {
                bytes[0] = 6;
                bytes[1..17].copy_from_slice(&a.ip().octets());
                bytes[17..19].copy_from_slice(&a.port().to_be_bytes());
                (bytes, 19)
            }
        }
    }

    fn tag(&self, addr_bytes: &[u8], odcid: &[u8], expiry: u64) -> [u8; Self::TAG_LEN] {
        let key = Key::new(hmac::HMAC_SHA256, &self.0);
        let mut ctx = Context::with_key(&key);
        ctx.update(b"qretrytok");
        ctx.update(addr_bytes);
        ctx.update(&expiry.to_be_bytes());
        ctx.update(&[odcid.len() as u8]);
        ctx.update(odcid);
        let tag = ctx.sign();
        let mut out = [0u8; Self::TAG_LEN];
        out.copy_from_slice(&tag.as_ref()[..Self::TAG_LEN]);
        out
    }
}
