use std::sync::Arc;

use o3::buffer;
use rustls::{ServerConfig, quic};

use crate::{conn, errors, security::qkdf, stream};
use conn::{life, wire};
use initial::{assembly, seed};
use life::{accept, initial, options, tls::servers};
use wire::tls;

pub(crate) struct Acceptor {
    seed: seed::Seed<seed::Server>,
    input: options::Options,
}

impl Acceptor {
    pub(crate) fn new(ids: accept::Ids, opts: options::Options) -> Self {
        Self {
            seed: seed::Seed::server(ids),
            input: opts,
        }
    }

    pub(crate) fn try_owned<const DOMAIN: u8, B, D>(
        self,
        config: Arc<ServerConfig>,
    ) -> Result<conn::Connection<DOMAIN, B, D>, errors::Connect>
    where
        B: stream::Recv,
        D: buffer::raw::Segment,
    {
        let reset = self
            .input
            .security
            .stateless_reset_secret
            .as_ref()
            .map(|secret| secret.token_for(&self.seed.local_cid));
        let mut params = Vec::new();
        self.input
            .transport
            .params()
            .bind_server(
                &self.seed.local_cid,
                &self.seed.original_dcid,
                self.seed.retry_scid.as_ref(),
                reset.as_ref(),
            )
            .encode(&mut params)?;
        let state = quic::ServerConnection::new(config, quic::Version::V1, params)
            .map_err(errors::Connect::Setup)?;
        let keys = qkdf::Initial::try_new(&self.seed.initial_dcid)
            .and_then(qkdf::Pair::try_server)
            .map_err(|error| errors::Connect::Protocol(error.into()))?;
        let hs = tls::Handshake::try_new(
            state.into(),
            keys.peer,
            keys.local,
            self.input.journals.crypto(),
            None,
        )
        .map_err(errors::Connect::TlsCrypto)?;
        let Self { seed, input } = self;
        assembly::Assembly {
            input,
            wire: hs,
            role: assembly::Server { seed },
        }
        .try_finish()
    }

    pub(crate) fn try_pooled<'pool, const DOMAIN: u8, B, D>(
        self,
        pool: &'pool servers::Pool<DOMAIN>,
    ) -> Result<(conn::Connection<DOMAIN, B, D>, life::tls::Permit<'pool>), errors::Connect>
    where
        B: stream::Recv,
        D: buffer::raw::Segment,
    {
        let permit = pool.reserve()?;
        let conn = self.try_owned(pool.authority().config())?;
        Ok((conn, permit))
    }
}
