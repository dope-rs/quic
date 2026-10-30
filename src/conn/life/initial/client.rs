use std::sync::Arc;

use o3::{
    alloc::{self, BoxSliceExt as _, array::Block},
    buffer,
};
use rustls::{ClientConfig, client::Resumption, quic};

use crate::proto::param;
use crate::{conn, errors, runtime::routing, security::qkdf, stream, wire::packet::cid};
use conn::{life, wire};
use life::{
    initial::{assembly, seed},
    options,
    tls::clients,
};
use wire::tls::Handshake;

pub(crate) struct Client {
    seed: seed::Seed<seed::Client>,
    input: options::Options,
}

impl Client {
    pub(crate) fn new(dcid: cid::Id, local: cid::Id, opts: options::Options) -> Self {
        Self {
            seed: seed::Seed::client(dcid, local),
            input: opts,
        }
    }

    pub(crate) fn try_direct<const DOMAIN: u8, B, D>(
        self,
        auth: clients::Authority,
        route: impl routing::PeerRoute,
        token: Option<life::Token>,
    ) -> Result<conn::Connection<DOMAIN, B, D>, errors::Connect>
    where
        B: stream::Recv,
        D: buffer::raw::Segment,
    {
        let shard = route.shard();
        let token = token.map(life::Token::into_wire);
        let mut hs = self.try_tls(&auth, Arc::clone(auth.config()))?;
        let mut peer = match hs.early_params() {
            None => None,
            Some(bytes) => {
                let bytes = bytes.map_err(errors::Connect::Protocol)?;
                let peer = match param::Codec::decode(bytes) {
                    Ok(peer) => peer,
                    Err(error) => {
                        return Err(errors::Connect::Protocol(conn::Error::from(error)));
                    }
                };
                if peer
                    .identity()
                    .initial()
                    .is_none_or(|cid| !routing::matches_peer(shard, cid.as_ref_id()))
                {
                    drop(hs);
                    let mut config = auth.config().as_ref().clone();
                    config.resumption = Resumption::disabled();
                    hs = self.try_tls(&auth, Arc::new(config))?;
                    None
                } else {
                    Some(peer)
                }
            }
        };
        let hs = hs.bind_auth(auth);
        let Self { seed, input } = self;
        assembly::Assembly {
            input,
            wire: hs,
            role: assembly::Client { seed, token, shard },
        }
        .try_finish(&mut peer)
    }

    fn try_tls<const DOMAIN: u8>(
        &self,
        auth: &clients::Authority,
        config: Arc<ClientConfig>,
    ) -> Result<Handshake<DOMAIN, ()>, errors::Connect> {
        let mut params = Vec::new();
        self.input
            .transport
            .params()
            .bind_client(&self.seed.local_cid)
            .encode(&mut params)?;
        let entries = config.alpn_protocols.as_slice();
        let alpn = Block::try_clone(entries, |protocol| {
            Ok(Box::<[u8]>::try_copy(protocol)?.into_vec())
        })
        .map_err(alloc::Error::from)?
        .into_vec();
        let state = quic::ClientConnection::new_with_alpn(
            config,
            quic::Version::V1,
            auth.name(),
            params,
            alpn,
        )
        .map_err(errors::Connect::Setup)?;
        let keys = qkdf::Initial::try_new(&self.seed.initial_dcid)
            .and_then(qkdf::Pair::try_client)
            .map_err(|error| errors::Connect::Protocol(error.into()))?;
        let mut hs = Handshake::try_new(
            state.into(),
            keys.peer,
            keys.local,
            self.input.journals.crypto(),
            (),
        )
        .map_err(errors::Connect::TlsCrypto)?;
        hs.try_start().map_err(errors::Connect::Protocol)?;
        Ok(hs)
    }
}
