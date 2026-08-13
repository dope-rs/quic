use std::ops::{Deref, DerefMut};
use std::time::Instant;

use shin::crypto::ticket::Keys;
use shin::server::{
    self, PreparedShard, ReplayDomain, Shard,
    config::{
        ClientAuth, ClientAuthVerifier, ClientCertVerifier, EarlyDataGuard, NoClientAuth, NoGuard,
    },
};

use super::Error;
use crate::packet::ConnectionId;

/// Replay protection owned by one server lane.
///
/// A guard that returns a domain must share one atomic replay store with every
/// clone that returns the same domain. This binds ticket authority to the
/// actual replay store instead of to an individual QUIC connection.
pub trait ReplayGuard: EarlyDataGuard {
    fn replay_domain(&self) -> Option<ReplayDomain>;
}

impl ReplayGuard for NoGuard {
    fn replay_domain(&self) -> Option<ReplayDomain> {
        None
    }
}

fn build_standard_shard<const DOMAIN: u8, G: ReplayGuard>(
    config: server::config::Config,
    guard: G,
) -> Result<Shard<G, NoClientAuth, DOMAIN>, shin::connection::Error> {
    let prepared = match guard.replay_domain() {
        Some(domain) => {
            PreparedShard::with_early_data_guard_in_replay_domain(config, domain, guard)
        }
        None => PreparedShard::with_early_data_guard(config, guard),
    }?;
    Ok(prepared.bind_domain::<DOMAIN>())
}

/// Connection IDs required to construct one server-side QUIC connection.
pub struct Ids {
    pub(super) initial_dcid: ConnectionId,
    pub(super) local_cid: ConnectionId,
    pub(super) peer_cid: ConnectionId,
    pub(super) tp_original_dcid: ConnectionId,
    pub(super) retry_scid: Option<ConnectionId>,
}

impl Ids {
    /// Creates IDs for a connection accepted directly from its first Initial.
    pub fn initial(
        initial_dcid: ConnectionId,
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
    ) -> Self {
        Self {
            initial_dcid,
            local_cid,
            peer_cid,
            tp_original_dcid: initial_dcid,
            retry_scid: None,
        }
    }

    /// Creates IDs for a connection accepted after a validated Retry.
    pub fn retry(
        initial_dcid: ConnectionId,
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
        original_dcid: ConnectionId,
        retry_scid: ConnectionId,
    ) -> Self {
        Self {
            initial_dcid,
            local_cid,
            peer_cid,
            tp_original_dcid: original_dcid,
            retry_scid: Some(retry_scid),
        }
    }
}

mod sealed {
    pub trait Sealed {}
}

pub trait Policy: sealed::Sealed + 'static {
    type Guard: EarlyDataGuard + 'static;
    type Verifier: server::config::ClientCertVerifier + 'static;

    /// Lane-owned input consumed when constructing this concrete policy.
    type Setup;

    #[doc(hidden)]
    fn build<const DOMAIN: u8>(
        config: server::config::Config,
        setup: Self::Setup,
    ) -> Result<Shard<Self::Guard, Self::Verifier, DOMAIN>, shin::connection::Error>;
}

pub struct Standard<G = NoGuard>(core::marker::PhantomData<fn() -> G>);

impl<G> sealed::Sealed for Standard<G> {}

impl<G> Policy for Standard<G>
where
    G: ReplayGuard + 'static,
{
    type Guard = G;
    type Verifier = NoClientAuth;
    type Setup = G;

    fn build<const DOMAIN: u8>(
        config: server::config::Config,
        guard: G,
    ) -> Result<Shard<G, NoClientAuth, DOMAIN>, shin::connection::Error> {
        build_standard_shard::<DOMAIN, G>(config, guard)
    }
}

pub struct Mutual<G, V>(core::marker::PhantomData<fn() -> (G, V)>);

impl<G, V> sealed::Sealed for Mutual<G, V> {}

impl<G, V> Policy for Mutual<G, V>
where
    G: ReplayGuard + 'static,
    V: ClientCertVerifier + 'static,
{
    type Guard = G;
    type Verifier = ClientAuthVerifier<V>;
    type Setup = Authentication<V, G>;

    fn build<const DOMAIN: u8>(
        config: server::config::Config,
        authentication: Authentication<V, G>,
    ) -> Result<Shard<G, ClientAuthVerifier<V>, DOMAIN>, shin::connection::Error> {
        authentication.build_shard::<DOMAIN>(config)
    }
}

pub struct Authentication<V, G = NoGuard> {
    guard: G,
    mode: ClientAuth,
    verifier: V,
}

impl<V> Authentication<V> {
    pub fn new(mode: ClientAuth, verifier: V) -> Self {
        Self {
            guard: NoGuard,
            mode,
            verifier,
        }
    }
}

impl<V, G> Authentication<V, G> {
    pub fn with_early_data_guard(guard: G, mode: ClientAuth, verifier: V) -> Self {
        Self {
            guard,
            mode,
            verifier,
        }
    }
}

impl<V: ClientCertVerifier, G: ReplayGuard> Authentication<V, G> {
    fn build_shard<const DOMAIN: u8>(
        self,
        config: server::config::Config,
    ) -> Result<Shard<G, ClientAuthVerifier<V>, DOMAIN>, shin::connection::Error> {
        let (guard, mode, verifier) = self.into_parts();
        let prepared = match guard.replay_domain() {
            Some(domain) => PreparedShard::with_early_data_guard_and_client_auth_in_replay_domain(
                config, domain, guard, mode, verifier,
            ),
            None => {
                PreparedShard::with_early_data_guard_and_client_auth(config, guard, mode, verifier)
            }
        }?;
        Ok(prepared.bind_domain::<DOMAIN>())
    }

    fn into_parts(self) -> (G, ClientAuth, V) {
        (self.guard, self.mode, self.verifier)
    }
}

pub struct Connection<
    G: EarlyDataGuard = NoGuard,
    V: ClientCertVerifier = NoClientAuth,
    const DOMAIN: u8 = 0,
> {
    conn: super::Connection<DOMAIN>,
    tls: Box<server::QuicConnection<super::handshake::Clock, DOMAIN, G, V>>,
    shard: Shard<G, V, DOMAIN>,
}

impl<G, V, const DOMAIN: u8> Connection<G, V, DOMAIN>
where
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    pub(super) fn new(
        conn: super::Connection<DOMAIN>,
        tls: Box<server::QuicConnection<super::handshake::Clock, DOMAIN, G, V>>,
        shard: Shard<G, V, DOMAIN>,
    ) -> Self {
        Self { conn, tls, shard }
    }

    /// Receives and decrypts one datagram in place.
    ///
    /// The contents of `wire` are unspecified after this call.
    pub fn recv_packet(
        &mut self,
        workspace: &mut super::ReceiveWorkspace,
        wire: &mut [u8],
        now: Instant,
    ) -> Result<(), Error> {
        super::ingress::Ingress::new(&mut self.conn, workspace).recv_server(
            wire,
            now,
            &mut self.tls,
        )
    }

    pub fn replace_ticket_keys(&mut self, keys: Option<Keys>) {
        self.shard.replace_ticket_keys(keys);
    }
}

impl<G, V, const DOMAIN: u8> Deref for Connection<G, V, DOMAIN>
where
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    type Target = super::Connection<DOMAIN>;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl<G, V, const DOMAIN: u8> DerefMut for Connection<G, V, DOMAIN>
where
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}
