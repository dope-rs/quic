use std::marker;

use ring::rand::SecureRandom as _;
use shin::crypto::sig;

use crate::conn;
use crate::stream;

use crate::mux;
use crate::mux::drive;
use crate::mux::lifecycle;
use crate::mux::output;
use crate::mux::routing;

pub struct Client<H, const DOMAIN: u8 = 0, B: stream::ReceiveBuffer = Vec<u8>>
where
    H: mux::Handler<DOMAIN, B>,
{
    handler: H,
    max_connections: usize,
    outgoing_capacity: usize,
    outgoing_bytes_capacity: usize,
    _buffer: marker::PhantomData<fn() -> B>,
}

impl<H: mux::Handler<DOMAIN, B>, const DOMAIN: u8, B: stream::ReceiveBuffer> Client<H, DOMAIN, B> {
    pub fn new(handler: H) -> Self {
        Self {
            handler,
            max_connections: mux::DEFAULT_MAX_CONNS,
            outgoing_capacity: mux::DEFAULT_OUTGOING_CAP,
            outgoing_bytes_capacity: mux::DEFAULT_OUTGOING_BYTES_CAP,
            _buffer: marker::PhantomData,
        }
    }

    pub fn outgoing_capacity(mut self, capacity: usize) -> Self {
        self.outgoing_capacity = capacity;
        self
    }

    pub fn outgoing_limits(mut self, capacity: usize, bytes_capacity: usize) -> Self {
        self.outgoing_capacity = capacity;
        self.outgoing_bytes_capacity = bytes_capacity;
        self
    }

    pub fn limits(
        mut self,
        max_connections: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Self {
        self.max_connections = max_connections;
        self.outgoing_capacity = outgoing_capacity;
        self.outgoing_bytes_capacity = outgoing_bytes_capacity;
        self
    }

    pub fn build(
        self,
    ) -> Result<mux::Mux<H, conn::server::Standard, DOMAIN, B>, crate::ConnectFailure> {
        construct(
            self.handler,
            None,
            self.max_connections,
            self.outgoing_capacity,
            self.outgoing_bytes_capacity,
        )
    }

    pub fn build_pooled<'tls>(
        self,
    ) -> Result<mux::PooledRouter<'tls, H, conn::server::Standard, DOMAIN, B>, crate::ConnectFailure>
    {
        construct_inner(
            self.handler,
            None,
            self.max_connections,
            self.outgoing_capacity,
            self.outgoing_bytes_capacity,
        )
    }
}

pub struct Server<P: conn::server::Policy = conn::server::Standard, const DOMAIN: u8 = 0>(
    marker::PhantomData<fn() -> P>,
);

impl<const DOMAIN: u8> Server<conn::server::Standard, DOMAIN> {
    pub fn accept<H: mux::Handler<DOMAIN>>(
        handler: H,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
    ) -> Result<mux::Mux<H, conn::server::Standard, DOMAIN>, crate::ConnectFailure> {
        Self::with_limits(
            handler,
            signing_key,
            server_config,
            mux::DEFAULT_MAX_CONNS,
            mux::DEFAULT_OUTGOING_CAP,
            mux::DEFAULT_OUTGOING_BYTES_CAP,
        )
    }

    pub fn with_outgoing_capacity<H: mux::Handler<DOMAIN>>(
        handler: H,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        outgoing_capacity: usize,
    ) -> Result<mux::Mux<H, conn::server::Standard, DOMAIN>, crate::ConnectFailure> {
        Self::with_limits(
            handler,
            signing_key,
            server_config,
            mux::DEFAULT_MAX_CONNS,
            outgoing_capacity,
            mux::DEFAULT_OUTGOING_BYTES_CAP,
        )
    }

    pub fn with_outgoing_limits<H: mux::Handler<DOMAIN>>(
        handler: H,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<mux::Mux<H, conn::server::Standard, DOMAIN>, crate::ConnectFailure> {
        Self::with_limits(
            handler,
            signing_key,
            server_config,
            mux::DEFAULT_MAX_CONNS,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }

    pub fn with_limits<H: mux::Handler<DOMAIN>>(
        handler: H,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<mux::Mux<H, conn::server::Standard, DOMAIN>, crate::ConnectFailure> {
        Self::build(
            handler,
            signing_key,
            server_config,
            shin::server::config::NoGuard,
            max_conns,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }
}

impl<G, const DOMAIN: u8> Server<conn::server::Standard<G>, DOMAIN>
where
    G: conn::server::ReplayGuard + 'static,
{
    pub fn with_early_data_guard<H: mux::Handler<DOMAIN>>(
        handler: H,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        guard: G,
    ) -> Result<mux::Mux<H, conn::server::Standard<G>, DOMAIN>, crate::ConnectFailure> {
        Self::with_early_data_guard_and_limits(
            handler,
            signing_key,
            server_config,
            guard,
            mux::DEFAULT_MAX_CONNS,
            mux::DEFAULT_OUTGOING_CAP,
            mux::DEFAULT_OUTGOING_BYTES_CAP,
        )
    }

    pub fn with_early_data_guard_and_limits<H: mux::Handler<DOMAIN>>(
        handler: H,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        guard: G,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<mux::Mux<H, conn::server::Standard<G>, DOMAIN>, crate::ConnectFailure> {
        Self::build(
            handler,
            signing_key,
            server_config,
            guard,
            max_conns,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }
}

impl<V, const DOMAIN: u8> Server<conn::server::Mutual<shin::server::config::NoGuard, V>, DOMAIN>
where
    V: shin::server::config::ClientCertVerifier + 'static,
{
    pub fn mutual<H: mux::Handler<DOMAIN>>(
        handler: H,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        authentication: conn::server::Authentication<V>,
    ) -> Result<
        mux::Mux<H, conn::server::Mutual<shin::server::config::NoGuard, V>, DOMAIN>,
        crate::ConnectFailure,
    > {
        Self::mutual_with_limits(
            handler,
            signing_key,
            server_config,
            authentication,
            mux::DEFAULT_MAX_CONNS,
            mux::DEFAULT_OUTGOING_CAP,
            mux::DEFAULT_OUTGOING_BYTES_CAP,
        )
    }

    pub fn mutual_with_limits<H: mux::Handler<DOMAIN>>(
        handler: H,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        authentication: conn::server::Authentication<V>,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<
        mux::Mux<H, conn::server::Mutual<shin::server::config::NoGuard, V>, DOMAIN>,
        crate::ConnectFailure,
    > {
        Self::build(
            handler,
            signing_key,
            server_config,
            authentication,
            max_conns,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }
}

impl<G, V, const DOMAIN: u8> Server<conn::server::Mutual<G, V>, DOMAIN>
where
    G: conn::server::ReplayGuard + 'static,
    V: shin::server::config::ClientCertVerifier + 'static,
{
    pub fn mutual_with_early_data_guard<H: mux::Handler<DOMAIN>>(
        handler: H,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        authentication: conn::server::Authentication<V, G>,
    ) -> Result<mux::Mux<H, conn::server::Mutual<G, V>, DOMAIN>, crate::ConnectFailure> {
        Self::mutual_with_early_data_guard_and_limits(
            handler,
            signing_key,
            server_config,
            authentication,
            mux::DEFAULT_MAX_CONNS,
            mux::DEFAULT_OUTGOING_CAP,
            mux::DEFAULT_OUTGOING_BYTES_CAP,
        )
    }

    pub fn mutual_with_early_data_guard_and_limits<H: mux::Handler<DOMAIN>>(
        handler: H,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        authentication: conn::server::Authentication<V, G>,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<mux::Mux<H, conn::server::Mutual<G, V>, DOMAIN>, crate::ConnectFailure> {
        Self::build(
            handler,
            signing_key,
            server_config,
            authentication,
            max_conns,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }
}

impl<P: conn::server::Policy, const DOMAIN: u8> Server<P, DOMAIN> {
    pub fn with_pool<'tls, H, B>(
        handler: H,
        server_config: conn::config::Options,
        shard: &'tls shin::server::Shard<P::Guard, P::Verifier, DOMAIN>,
        pool: &'tls crate::conn::tls::ServerPool<P::Verifier, DOMAIN, P::Guard>,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<mux::PooledRouter<'tls, H, P, DOMAIN, B>, crate::ConnectFailure>
    where
        H: mux::Handler<DOMAIN, B>,
        B: stream::ReceiveBuffer,
    {
        if pool.capacities().3 != crate::transport_params::Params::MAX_ENCODED_LEN
            || !pool.matches_shard(shard)
        {
            return Err(crate::ConnectFailure::InvalidConfig);
        }
        let server_config = crate::conn::config::Validated::new_pooled_server(server_config)?;
        let server = mux::ServerRuntime::pooled(server_config, shard, pool);
        construct_inner(
            handler,
            Some(server),
            max_conns,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }

    pub fn with_policy<H: mux::Handler<DOMAIN>>(
        handler: H,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        policy_setup: P::Setup,
    ) -> Result<mux::Mux<H, P, DOMAIN>, crate::ConnectFailure> {
        Self::with_policy_and_limits(
            handler,
            signing_key,
            server_config,
            policy_setup,
            mux::DEFAULT_MAX_CONNS,
            mux::DEFAULT_OUTGOING_CAP,
            mux::DEFAULT_OUTGOING_BYTES_CAP,
        )
    }

    pub fn with_policy_and_limits<H: mux::Handler<DOMAIN>>(
        handler: H,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        policy_setup: P::Setup,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<mux::Mux<H, P, DOMAIN>, crate::ConnectFailure> {
        let server_config = crate::conn::config::Validated::new(server_config)?;
        Self::build_validated(
            handler,
            signing_key,
            server_config,
            policy_setup,
            max_conns,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }

    pub(crate) fn build<H: mux::Handler<DOMAIN>>(
        handler: H,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        policy_setup: P::Setup,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<mux::Mux<H, P, DOMAIN>, crate::ConnectFailure> {
        let server_config = crate::conn::config::Validated::new(server_config)?;
        Self::build_validated(
            handler,
            signing_key,
            server_config,
            policy_setup,
            max_conns,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }

    pub(crate) fn build_validated<H, B>(
        handler: H,
        signing_key: sig::SigningKey,
        mut server_config: crate::conn::config::Validated,
        policy_setup: P::Setup,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<mux::Mux<H, P, DOMAIN, B>, crate::ConnectFailure>
    where
        H: mux::Handler<DOMAIN, B>,
        B: stream::ReceiveBuffer,
    {
        let shard_config = server_config.take_server_config(signing_key)?;
        let shard = P::build::<DOMAIN>(shard_config, policy_setup)
            .map_err(|_| crate::ConnectFailure::Tls)?;
        let server = mux::ServerRuntime::new(server_config, shard);
        construct(
            handler,
            Some(server),
            max_conns,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }
}

pub(super) fn is_initial(wire: &[u8]) -> bool {
    matches!(wire.first(), Some(&byte) if (byte & 0xb0) == 0x80)
}

pub(super) fn stateless_reset_into(out: &mut Vec<u8>, token: [u8; 16], len: usize) -> bool {
    use ring::rand::SystemRandom;

    let len = len.max(22);
    out.clear();
    if out.try_reserve_exact(len).is_err() {
        return false;
    }
    out.resize(len, 0);
    if SystemRandom::new().fill(out).is_err() {
        out.clear();
        return false;
    }
    out[0] = (out[0] & 0x3f) | 0x40;
    let tail = len - 16;
    out[tail..].copy_from_slice(&token);
    true
}

pub(super) fn dcid(wire: &[u8], short_header_dcid_len: usize) -> Option<&[u8]> {
    let first = *wire.first()?;
    if first & 0x80 != 0 {
        let dcid_len = usize::from(*wire.get(5)?);
        wire.get(6..6usize.checked_add(dcid_len)?)
    } else {
        wire.get(1..1usize.checked_add(short_header_dcid_len)?)
    }
}

pub(super) fn max_packet_bytes(config: &conn::config::Options) -> usize {
    config.max_pmtu as usize
}

pub(super) fn connection_ceiling(
    config: &conn::config::Options,
    outgoing_capacity: usize,
) -> usize {
    max_packet_bytes(config).min(outgoing_capacity)
}

fn construct<H, P, const DOMAIN: u8, B: stream::ReceiveBuffer>(
    handler: H,
    server: Option<mux::ServerRuntime<'static, P, DOMAIN>>,
    max_conns: usize,
    outgoing_capacity: usize,
    outgoing_bytes_capacity: usize,
) -> Result<mux::Mux<H, P, DOMAIN, B>, crate::ConnectFailure>
where
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
{
    construct_inner(
        handler,
        server,
        max_conns,
        outgoing_capacity,
        outgoing_bytes_capacity,
    )
}

fn construct_inner<'tls, H, P, const DOMAIN: u8, B: stream::ReceiveBuffer>(
    handler: H,
    server: Option<mux::ServerRuntime<'tls, P, DOMAIN>>,
    max_conns: usize,
    outgoing_capacity: usize,
    outgoing_bytes_capacity: usize,
) -> Result<mux::PooledRouter<'tls, H, P, DOMAIN, B>, crate::ConnectFailure>
where
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
{
    if max_conns == 0
        || max_conns > crate::mux::MAX_CONNECTIONS
        || outgoing_capacity == 0
        || outgoing_capacity > crate::mux::MAX_OUTGOING_CAPACITY
        || outgoing_bytes_capacity == 0
        || outgoing_bytes_capacity > crate::mux::MAX_OUTGOING_BYTES
    {
        return Err(crate::ConnectFailure::InvalidConfig);
    }
    Ok(super::Router {
        registry: routing::registry::Registry::new(max_conns),
        outgoing: output::Storage::new(outgoing_capacity, outgoing_bytes_capacity),
        queues: drive::Queues::default(),
        receive_workspace: conn::ReceiveWorkspace::new(),
        handler,
        server,
        lifecycle: lifecycle::State::default(),
    })
}
