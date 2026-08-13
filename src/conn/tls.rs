use o3::collections::slab;
use shin::client;

use crate::conn;
use crate::errors;
use crate::transport_params;
use std::ops;
use std::time;

pub type ServerPool<
    V = shin::server::config::NoClientAuth,
    const DOMAIN: u8 = 0,
    G = shin::server::config::NoGuard,
> = shin::server::workspace::QuicPool<fn() -> u64, V, DOMAIN, G>;

/// Builds the only server TLS pool shape accepted by QUIC: framed handshake
/// storage plus the exact maximum encoded transport-parameter reservation.
pub fn server_pool<G, V, const DOMAIN: u8>(
    shard: &shin::server::Shard<G, V, DOMAIN>,
    capacity: usize,
) -> Result<ServerPool<V, DOMAIN, G>, errors::ConnectFailure>
where
    G: shin::server::config::EarlyDataGuard,
    V: shin::server::config::ClientCertVerifier,
{
    let capacity =
        slab::Capacity::try_from(capacity).map_err(|_| errors::ConnectFailure::InvalidConfig)?;
    let profile = shard
        .quic_profile(transport_params::Params::MAX_ENCODED_LEN)
        .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
    Ok(profile.into_pool::<fn() -> u64>(capacity))
}

/// Exact, externally owned TLS storage for one QUIC client authority.
/// Active sessions borrow this value and therefore cannot outlive it.
pub struct ClientPool {
    inner: client::workspace::FramedPool<conn::handshake::Clock>,
}

impl ClientPool {
    pub fn new(
        server_pubkey: [u8; 32],
        alpn_protocols: Vec<Vec<u8>>,
        enable_early_data: bool,
        identity: Option<client::config::Identity>,
        capacity: usize,
    ) -> Result<Self, errors::ConnectFailure> {
        let capacity = slab::Capacity::try_from(capacity)
            .map_err(|_| errors::ConnectFailure::InvalidConfig)?;
        let prepared = client::config::Config {
            verifier: client::config::Verifier::RawPublicKey {
                expected_pubkey: server_pubkey,
            },
            transport_params: Vec::new(),
            alpn_protocols,
            enable_early_data,
        }
        .try_into_prepared_with_transport(shin::transport::Mode::Quic)
        .map_err(errors::ConnectFailure::InvalidTlsConfig)?;
        let identity = identity
            .map(client::config::Identity::try_into_template)
            .transpose()
            .map_err(errors::ConnectFailure::InvalidTlsConfig)?;
        let inner = prepared
            .try_into_framed_pool(
                identity,
                capacity,
                transport_params::Params::MAX_ENCODED_LEN,
            )
            .map_err(errors::ConnectFailure::InvalidTlsConfig)?;
        Ok(Self { inner })
    }

    pub(crate) fn reserve(
        &self,
        resumption: Option<conn::session::Ticket>,
    ) -> Result<
        client::workspace::FramedReservation<'_, conn::handshake::Clock>,
        errors::ConnectFailure,
    > {
        let reservation = match resumption {
            Some(ticket) => self
                .inner
                .reserve_restored(
                    ticket
                        .into_restore()
                        .map_err(errors::ConnectFailure::InvalidTlsConfig)?,
                )
                .map_err(errors::ConnectFailure::InvalidTlsConfig)?,
            None => self.inner.reserve(),
        };
        reservation.ok_or(errors::ConnectFailure::Capacity)
    }

    pub fn capacity_profile(&self) -> (usize, usize, usize) {
        self.inner.capacities()
    }
}

/// Client connection whose TLS state borrows its exact external pool.
///
/// ```compile_fail
/// use dope_quic::conn::tls::Connection;
///
/// fn erase_pool_lifetime(connection: Connection<'_>) -> Connection<'static> {
///     connection
/// }
/// ```
pub struct Connection<'pool, const DOMAIN: u8 = 0, B: crate::stream::ReceiveBuffer = Vec<u8>> {
    conn: conn::session::Connection<DOMAIN, B>,
    tls: conn::handshake::ClientTls<'pool>,
}

impl<'pool, const DOMAIN: u8, B: crate::stream::ReceiveBuffer> Connection<'pool, DOMAIN, B> {
    pub(crate) fn new(
        conn: conn::session::Connection<DOMAIN, B>,
        tls: conn::handshake::ClientTls<'pool>,
    ) -> Self {
        Self { conn, tls }
    }

    pub fn recv_packet(
        &mut self,
        workspace: &mut conn::ReceiveWorkspace,
        wire: &mut [u8],
        now: time::Instant,
    ) -> Result<(), conn::Error> {
        conn::ingress::Ingress::new(&mut self.conn, workspace).recv_client_pooled(
            wire,
            now,
            &mut self.tls,
        )
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        conn::session::Connection<DOMAIN, B>,
        conn::handshake::ClientTls<'pool>,
    ) {
        (self.conn, self.tls)
    }
}

impl<const DOMAIN: u8, B: crate::stream::ReceiveBuffer> ops::Deref for Connection<'_, DOMAIN, B> {
    type Target = conn::session::Connection<DOMAIN, B>;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl<const DOMAIN: u8, B: crate::stream::ReceiveBuffer> ops::DerefMut
    for Connection<'_, DOMAIN, B>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

/// Server connection whose full TLS handshake state is returned to its pool
/// immediately after the handshake completes.
pub struct ServerConnection<
    'pool,
    G: shin::server::config::EarlyDataGuard,
    V: shin::server::config::ClientCertVerifier,
    const DOMAIN: u8 = 0,
    B: crate::stream::ReceiveBuffer = Vec<u8>,
> {
    conn: conn::session::Connection<DOMAIN, B>,
    tls: Option<shin::server::QuicPooledConnection<'pool, conn::handshake::Clock, DOMAIN, V, G>>,
}

impl<'pool, G, V, const DOMAIN: u8, B: crate::stream::ReceiveBuffer>
    ServerConnection<'pool, G, V, DOMAIN, B>
where
    G: shin::server::config::EarlyDataGuard,
    V: shin::server::config::ClientCertVerifier,
{
    pub(crate) fn new(
        conn: conn::session::Connection<DOMAIN, B>,
        tls: shin::server::QuicPooledConnection<'pool, conn::handshake::Clock, DOMAIN, V, G>,
    ) -> Self {
        Self {
            conn,
            tls: Some(tls),
        }
    }

    pub fn recv_packet(
        &mut self,
        workspace: &mut conn::ReceiveWorkspace,
        wire: &mut [u8],
        now: time::Instant,
    ) -> Result<(), conn::Error> {
        let result = match self.tls.as_mut() {
            Some(tls) => conn::ingress::Ingress::new(&mut self.conn, workspace)
                .recv_server_pooled(wire, now, tls),
            None => conn::ingress::Ingress::new(&mut self.conn, workspace).recv_finished(wire, now),
        };
        if self.tls.as_ref().is_some_and(|tls| tls.is_done()) {
            self.tls = None;
        }
        result
    }
}

impl<G, V, const DOMAIN: u8, B: crate::stream::ReceiveBuffer> ops::Deref
    for ServerConnection<'_, G, V, DOMAIN, B>
where
    G: shin::server::config::EarlyDataGuard,
    V: shin::server::config::ClientCertVerifier,
{
    type Target = conn::session::Connection<DOMAIN, B>;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl<G, V, const DOMAIN: u8, B: crate::stream::ReceiveBuffer> ops::DerefMut
    for ServerConnection<'_, G, V, DOMAIN, B>
where
    G: shin::server::config::EarlyDataGuard,
    V: shin::server::config::ClientCertVerifier,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}
