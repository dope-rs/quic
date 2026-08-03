use std::ops::{Deref, DerefMut};
use std::time::Instant;

use shin::crypto::ticket::TicketKeys;
use shin::server::{
    self, Shard,
    config::{ClientAuth, ClientCertVerifier, EarlyDataGuard, NoClientAuth, NoGuard},
};

use super::Error;

type ShardBuilder<G, V, S> = fn(server::config::Config, S) -> Shard<G, V>;

/// Connection IDs required to construct one server-side QUIC connection.
pub struct Ids {
    pub(super) initial_dcid: Vec<u8>,
    pub(super) local_cid: Vec<u8>,
    pub(super) peer_cid: Vec<u8>,
    pub(super) tp_original_dcid: Vec<u8>,
    pub(super) retry_scid: Option<Vec<u8>>,
}

impl Ids {
    /// Creates IDs for a connection accepted directly from its first Initial.
    pub fn initial(initial_dcid: Vec<u8>, local_cid: Vec<u8>, peer_cid: Vec<u8>) -> Self {
        let tp_original_dcid = initial_dcid.clone();
        Self {
            initial_dcid,
            local_cid,
            peer_cid,
            tp_original_dcid,
            retry_scid: None,
        }
    }

    /// Creates IDs for a connection accepted after a validated Retry.
    pub fn retry(
        initial_dcid: Vec<u8>,
        local_cid: Vec<u8>,
        peer_cid: Vec<u8>,
        original_dcid: Vec<u8>,
        retry_scid: Vec<u8>,
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
    type Verifier: ClientCertVerifier + 'static;

    /// Lane-owned input consumed when constructing this concrete policy.
    type Setup;

    #[doc(hidden)]
    const BUILD_SHARD: ShardBuilder<Self::Guard, Self::Verifier, Self::Setup>;
}

pub struct Standard<G = NoGuard>(core::marker::PhantomData<fn() -> G>);

impl<G> sealed::Sealed for Standard<G> {}

impl<G> Policy for Standard<G>
where
    G: EarlyDataGuard + 'static,
{
    type Guard = G;
    type Verifier = NoClientAuth;
    type Setup = G;

    const BUILD_SHARD: ShardBuilder<G, NoClientAuth, G> = Shard::with_early_data_guard;
}

pub struct Mutual<G, V>(core::marker::PhantomData<fn() -> (G, V)>);

impl<G, V> sealed::Sealed for Mutual<G, V> {}

impl<G, V> Policy for Mutual<G, V>
where
    G: EarlyDataGuard + 'static,
    V: ClientCertVerifier + 'static,
{
    type Guard = G;
    type Verifier = V;
    type Setup = Authentication<V, G>;

    const BUILD_SHARD: ShardBuilder<G, V, Authentication<V, G>> = Authentication::build_shard;
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

impl<V: ClientCertVerifier, G: EarlyDataGuard> Authentication<V, G> {
    fn build_shard(config: server::config::Config, setup: Self) -> Shard<G, V> {
        let (guard, mode, verifier) = setup.into_parts();
        Shard::with_early_data_guard_and_client_auth(config, guard, mode, verifier)
    }

    fn into_parts(self) -> (G, ClientAuth, V) {
        (self.guard, self.mode, self.verifier)
    }
}

pub struct Connection<G: EarlyDataGuard = NoGuard, V: ClientCertVerifier = NoClientAuth> {
    conn: super::Connection,
    shard: Shard<G, V>,
}

impl<G, V> Connection<G, V>
where
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    pub(super) fn new(conn: super::Connection, shard: Shard<G, V>) -> Self {
        Self { conn, shard }
    }

    /// Receives and decrypts one datagram in place.
    ///
    /// The contents of `wire` are unspecified after this call.
    pub fn recv_packet(&mut self, wire: &mut [u8], now: Instant) -> Result<(), Error> {
        self.conn.recv_packet_server(wire, now, &mut self.shard)
    }

    pub fn replace_ticket_keys(&mut self, keys: Option<TicketKeys>) {
        self.shard.replace_ticket_keys(keys);
    }
}

impl<G, V> Deref for Connection<G, V>
where
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    type Target = super::Connection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl<G, V> DerefMut for Connection<G, V>
where
    G: EarlyDataGuard,
    V: ClientCertVerifier,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}
