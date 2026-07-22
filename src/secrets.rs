use std::net::SocketAddr;

use ring::hmac;
use ring::hmac::Context;
use ring::hmac::Key;
use subtle::ConstantTimeEq;

#[derive(Clone, Copy)]
pub struct StatelessResetSecret(pub [u8; 32]);

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
pub struct RetryTokenSecret(pub [u8; 32]);

impl From<[u8; 32]> for RetryTokenSecret {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl RetryTokenSecret {
    pub fn issue(&self, addr: &SocketAddr, odcid: &[u8], expiry_unix_secs: u64) -> Vec<u8> {
        let addr_bytes = Self::addr_bytes(addr);
        let tag = self.tag(&addr_bytes, odcid, expiry_unix_secs);
        let mut out = Vec::with_capacity(8 + 1 + odcid.len() + 16);
        out.extend_from_slice(&expiry_unix_secs.to_be_bytes());
        out.push(odcid.len() as u8);
        out.extend_from_slice(odcid);
        out.extend_from_slice(&tag);
        out
    }

    pub fn validate(&self, addr: &SocketAddr, token: &[u8], now_unix_secs: u64) -> Option<Vec<u8>> {
        if token.len() < 8 + 1 + 16 {
            return None;
        }
        let expiry = u64::from_be_bytes(token[..8].try_into().ok()?);
        if now_unix_secs >= expiry {
            return None;
        }
        let odcid_len = token[8] as usize;
        if token.len() != 8 + 1 + odcid_len + 16 {
            return None;
        }
        let odcid = &token[9..9 + odcid_len];
        let provided_tag = &token[9 + odcid_len..];
        let addr_bytes = Self::addr_bytes(addr);
        let expected = self.tag(&addr_bytes, odcid, expiry);
        if !bool::from(provided_tag.ct_eq(&expected[..])) {
            return None;
        }
        Some(odcid.to_vec())
    }

    fn addr_bytes(addr: &SocketAddr) -> Vec<u8> {
        match addr {
            SocketAddr::V4(a) => {
                let mut b = Vec::with_capacity(1 + 4 + 2);
                b.push(4);
                b.extend_from_slice(&a.ip().octets());
                b.extend_from_slice(&a.port().to_be_bytes());
                b
            }
            SocketAddr::V6(a) => {
                let mut b = Vec::with_capacity(1 + 16 + 2);
                b.push(6);
                b.extend_from_slice(&a.ip().octets());
                b.extend_from_slice(&a.port().to_be_bytes());
                b
            }
        }
    }

    fn tag(&self, addr_bytes: &[u8], odcid: &[u8], expiry: u64) -> [u8; 16] {
        let key = Key::new(hmac::HMAC_SHA256, &self.0);
        let mut ctx = Context::with_key(&key);
        ctx.update(b"qretrytok");
        ctx.update(addr_bytes);
        ctx.update(&expiry.to_be_bytes());
        ctx.update(&[odcid.len() as u8]);
        ctx.update(odcid);
        let tag = ctx.sign();
        let mut out = [0u8; 16];
        out.copy_from_slice(&tag.as_ref()[..16]);
        out
    }
}
