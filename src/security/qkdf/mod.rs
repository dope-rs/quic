use o3::base::marker::ThreadBound;
use rustls::{Side, crypto::aws_lc_rs::cipher_suite, quic};

use crate::{security::crypto, wire::packet::kind};
use crypto::op;

mod boundary;
pub mod origin;

pub(crate) use boundary::Boundary;

/// A sealed sender-origin marker for key provenance.
pub trait KeyOrigin: Boundary {}
impl KeyOrigin for origin::Client {}
impl KeyOrigin for origin::Server {}
impl KeyOrigin for origin::Local {}
impl KeyOrigin for origin::Peer {}

/// Both Initial directions admitted by one absolute-to-relative role mapping.
pub(crate) struct Pair {
    pub(crate) local: crypto::Key<kind::Initial, origin::Local, op::Seal>,
    pub(crate) peer: crypto::Key<kind::Initial, origin::Peer, op::Open>,
}

/// Initial packet protection derived by the upstream QUIC implementation.
pub struct Initial {
    keys: quic::Keys,
    _bound: ThreadBound,
}

impl Initial {
    pub fn try_new(dcid: &[u8]) -> Result<Self, crypto::Error> {
        let suite = cipher_suite::TLS13_AES_128_GCM_SHA256
            .tls13()
            .and_then(|suite| suite.quic_suite())
            .ok_or(crypto::Error::InitialSuite)?;
        Ok(Self {
            keys: suite.keys(dcid, Side::Client, quic::Version::V1),
            _bound: ThreadBound::NEW,
        })
    }

    pub fn try_client(
        self,
    ) -> Result<crypto::Key<kind::Initial, origin::Client, op::Open>, crypto::Error> {
        crypto::Key::try_new(self.keys.local)
    }

    pub fn try_server(
        self,
    ) -> Result<crypto::Key<kind::Initial, origin::Server, op::Open>, crypto::Error> {
        crypto::Key::try_new(self.keys.remote)
    }
}

impl Pair {
    pub(crate) fn try_client(initial: Initial) -> Result<Self, crypto::Error> {
        let Initial { keys, _bound: _ } = initial;
        Ok(Self {
            local: crypto::Key::try_new(keys.local)?,
            peer: crypto::Key::try_new(keys.remote)?,
        })
    }

    pub(crate) fn try_server(initial: Initial) -> Result<Self, crypto::Error> {
        let Initial { keys, _bound: _ } = initial;
        Ok(Self {
            local: crypto::Key::try_new(keys.remote)?,
            peer: crypto::Key::try_new(keys.local)?,
        })
    }
}
