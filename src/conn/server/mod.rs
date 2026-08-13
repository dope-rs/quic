use std::ops;
use std::time;

use shin::crypto::ticket;
use shin::server;
use shin::server::config;

use crate::conn;
use crate::packet;

/// Replay protection owned by one server lane.
/// Guards returning the same domain must share one atomic replay store, binding
/// ticket authority to that store instead of an individual connection.
pub trait ReplayGuard: config::EarlyDataGuard {
    fn replay_domain(&self) -> Option<server::ReplayDomain>;
}

impl ReplayGuard for config::NoGuard {
    fn replay_domain(&self) -> Option<server::ReplayDomain> {
        None
    }
}

fn build_standard_shard<const DOMAIN: u8, G: ReplayGuard>(
    config: server::config::Config,
    guard: G,
) -> Result<server::Shard<G, config::NoClientAuth, DOMAIN>, shin::connection::Error> {
    let prepared = match guard.replay_domain() {
        Some(domain) => {
            server::PreparedShard::with_early_data_guard_in_replay_domain(config, domain, guard)
        }
        None => server::PreparedShard::with_early_data_guard(config, guard),
    }?;
    Ok(prepared.bind_domain::<DOMAIN>())
}

/// Connection IDs required to construct one server-side QUIC connection.
pub struct Ids {
    pub(super) initial_dcid: packet::ConnectionId,
    pub(super) local_cid: packet::ConnectionId,
    pub(super) peer_cid: packet::ConnectionId,
    pub(super) tp_original_dcid: packet::ConnectionId,
    pub(super) retry_scid: Option<packet::ConnectionId>,
}

impl Ids {
    /// Creates IDs for a connection accepted directly from its first Initial.
    pub fn initial(
        initial_dcid: packet::ConnectionId,
        local_cid: packet::ConnectionId,
        peer_cid: packet::ConnectionId,
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
        initial_dcid: packet::ConnectionId,
        local_cid: packet::ConnectionId,
        peer_cid: packet::ConnectionId,
        original_dcid: packet::ConnectionId,
        retry_scid: packet::ConnectionId,
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

mod boundary;

pub trait Policy: boundary::Boundary + 'static {
    type Guard: config::EarlyDataGuard + 'static;
    type Verifier: server::config::ClientCertVerifier + 'static;

    /// Lane-owned input consumed when constructing this concrete policy.
    type Setup;

    #[doc(hidden)]
    fn build<const DOMAIN: u8>(
        config: server::config::Config,
        setup: Self::Setup,
    ) -> Result<server::Shard<Self::Guard, Self::Verifier, DOMAIN>, shin::connection::Error>;
}

pub struct Standard<G = config::NoGuard>(core::marker::PhantomData<fn() -> G>);

impl<G> boundary::Boundary for Standard<G> {}

impl<G> Policy for Standard<G>
where
    G: ReplayGuard + 'static,
{
    type Guard = G;
    type Verifier = config::NoClientAuth;
    type Setup = G;

    fn build<const DOMAIN: u8>(
        config: server::config::Config,
        guard: G,
    ) -> Result<server::Shard<G, config::NoClientAuth, DOMAIN>, shin::connection::Error> {
        build_standard_shard::<DOMAIN, G>(config, guard)
    }
}

pub struct Mutual<G, V>(core::marker::PhantomData<fn() -> (G, V)>);

impl<G, V> boundary::Boundary for Mutual<G, V> {}

impl<G, V> Policy for Mutual<G, V>
where
    G: ReplayGuard + 'static,
    V: config::ClientCertVerifier + 'static,
{
    type Guard = G;
    type Verifier = config::ClientAuthVerifier<V>;
    type Setup = Authentication<V, G>;

    fn build<const DOMAIN: u8>(
        config: server::config::Config,
        authentication: Authentication<V, G>,
    ) -> Result<server::Shard<G, config::ClientAuthVerifier<V>, DOMAIN>, shin::connection::Error>
    {
        authentication.build_shard::<DOMAIN>(config)
    }
}

pub struct Authentication<V, G = config::NoGuard> {
    guard: G,
    mode: config::ClientAuth,
    verifier: V,
}

impl<V> Authentication<V> {
    pub fn new(mode: config::ClientAuth, verifier: V) -> Self {
        Self {
            guard: config::NoGuard,
            mode,
            verifier,
        }
    }
}

impl<V, G> Authentication<V, G> {
    pub fn with_early_data_guard(guard: G, mode: config::ClientAuth, verifier: V) -> Self {
        Self {
            guard,
            mode,
            verifier,
        }
    }
}

impl<V: config::ClientCertVerifier, G: ReplayGuard> Authentication<V, G> {
    fn build_shard<const DOMAIN: u8>(
        self,
        config: server::config::Config,
    ) -> Result<server::Shard<G, config::ClientAuthVerifier<V>, DOMAIN>, shin::connection::Error>
    {
        let (guard, mode, verifier) = self.into_parts();
        let prepared = match guard.replay_domain() {
            Some(domain) => {
                server::PreparedShard::with_early_data_guard_and_client_auth_in_replay_domain(
                    config, domain, guard, mode, verifier,
                )
            }
            None => server::PreparedShard::with_early_data_guard_and_client_auth(
                config, guard, mode, verifier,
            ),
        }?;
        Ok(prepared.bind_domain::<DOMAIN>())
    }

    fn into_parts(self) -> (G, config::ClientAuth, V) {
        (self.guard, self.mode, self.verifier)
    }
}

pub struct Connection<
    G: config::EarlyDataGuard = config::NoGuard,
    V: config::ClientCertVerifier = config::NoClientAuth,
    const DOMAIN: u8 = 0,
> {
    conn: crate::conn::session::Connection<DOMAIN>,
    tls: Box<server::QuicConnection<super::handshake::Clock, DOMAIN, G, V>>,
    shard: server::Shard<G, V, DOMAIN>,
}

impl<G, V, const DOMAIN: u8> Connection<G, V, DOMAIN>
where
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    pub(super) fn new(
        conn: crate::conn::session::Connection<DOMAIN>,
        tls: Box<server::QuicConnection<super::handshake::Clock, DOMAIN, G, V>>,
        shard: server::Shard<G, V, DOMAIN>,
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
        now: time::Instant,
    ) -> Result<(), conn::Error> {
        if wire.is_empty() {
            return Ok(());
        }
        super::ingress::Ingress::new(&mut self.conn, workspace).recv_server(
            wire,
            now,
            &mut self.tls,
        )
    }

    pub fn replace_ticket_keys(&mut self, keys: Option<ticket::Keys>) {
        self.shard.replace_ticket_keys(keys);
    }
}

impl<G, V, const DOMAIN: u8> ops::Deref for Connection<G, V, DOMAIN>
where
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    type Target = crate::conn::session::Connection<DOMAIN>;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl<G, V, const DOMAIN: u8> ops::DerefMut for Connection<G, V, DOMAIN>
where
    G: config::EarlyDataGuard,
    V: config::ClientCertVerifier,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}
