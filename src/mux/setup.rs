use std::marker::PhantomData;

use shin::crypto::sig::SigningKey;
use shin::server::{config::ClientCertVerifier, config::NoGuard};

use crate::ConnectFailure;
use crate::conn::{self, config::Validated};
use crate::stream::ReceiveBuffer;

use super::{
    DEFAULT_MAX_CONNS, DEFAULT_OUTGOING_BYTES_CAP, DEFAULT_OUTGOING_CAP, Handler, MAX_CONNECTIONS,
    MAX_OUTGOING_BYTES, MAX_OUTGOING_CAPACITY, Mux, PooledRouter, ServerRuntime, drive, lifecycle,
    output, routing,
};

pub struct Client<H, const DOMAIN: u8 = 0, B: ReceiveBuffer = Vec<u8>>
where
    H: Handler<DOMAIN, B>,
{
    handler: H,
    max_connections: usize,
    outgoing_capacity: usize,
    outgoing_bytes_capacity: usize,
    _buffer: PhantomData<fn() -> B>,
}

impl<H: Handler<DOMAIN, B>, const DOMAIN: u8, B: ReceiveBuffer> Client<H, DOMAIN, B> {
    pub fn new(handler: H) -> Self {
        Self {
            handler,
            max_connections: DEFAULT_MAX_CONNS,
            outgoing_capacity: DEFAULT_OUTGOING_CAP,
            outgoing_bytes_capacity: DEFAULT_OUTGOING_BYTES_CAP,
            _buffer: PhantomData,
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

    pub fn build(self) -> Result<Mux<H, conn::server::Standard, DOMAIN, B>, ConnectFailure> {
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
    ) -> Result<PooledRouter<'tls, H, conn::server::Standard, DOMAIN, B>, ConnectFailure> {
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
    PhantomData<fn() -> P>,
);

impl<const DOMAIN: u8> Server<conn::server::Standard, DOMAIN> {
    pub fn accept<H: Handler<DOMAIN>>(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::config::Options,
    ) -> Result<Mux<H, conn::server::Standard, DOMAIN>, ConnectFailure> {
        Self::with_limits(
            handler,
            signing_key,
            server_config,
            DEFAULT_MAX_CONNS,
            DEFAULT_OUTGOING_CAP,
            DEFAULT_OUTGOING_BYTES_CAP,
        )
    }

    pub fn with_outgoing_capacity<H: Handler<DOMAIN>>(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        outgoing_capacity: usize,
    ) -> Result<Mux<H, conn::server::Standard, DOMAIN>, ConnectFailure> {
        Self::with_limits(
            handler,
            signing_key,
            server_config,
            DEFAULT_MAX_CONNS,
            outgoing_capacity,
            DEFAULT_OUTGOING_BYTES_CAP,
        )
    }

    pub fn with_outgoing_limits<H: Handler<DOMAIN>>(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<Mux<H, conn::server::Standard, DOMAIN>, ConnectFailure> {
        Self::with_limits(
            handler,
            signing_key,
            server_config,
            DEFAULT_MAX_CONNS,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }

    pub fn with_limits<H: Handler<DOMAIN>>(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<Mux<H, conn::server::Standard, DOMAIN>, ConnectFailure> {
        Self::build(
            handler,
            signing_key,
            server_config,
            NoGuard,
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
    pub fn with_early_data_guard<H: Handler<DOMAIN>>(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        guard: G,
    ) -> Result<Mux<H, conn::server::Standard<G>, DOMAIN>, ConnectFailure> {
        Self::with_early_data_guard_and_limits(
            handler,
            signing_key,
            server_config,
            guard,
            DEFAULT_MAX_CONNS,
            DEFAULT_OUTGOING_CAP,
            DEFAULT_OUTGOING_BYTES_CAP,
        )
    }

    pub fn with_early_data_guard_and_limits<H: Handler<DOMAIN>>(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        guard: G,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<Mux<H, conn::server::Standard<G>, DOMAIN>, ConnectFailure> {
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

impl<V, const DOMAIN: u8> Server<conn::server::Mutual<NoGuard, V>, DOMAIN>
where
    V: ClientCertVerifier + 'static,
{
    pub fn mutual<H: Handler<DOMAIN>>(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        authentication: conn::server::Authentication<V>,
    ) -> Result<Mux<H, conn::server::Mutual<NoGuard, V>, DOMAIN>, ConnectFailure> {
        Self::mutual_with_limits(
            handler,
            signing_key,
            server_config,
            authentication,
            DEFAULT_MAX_CONNS,
            DEFAULT_OUTGOING_CAP,
            DEFAULT_OUTGOING_BYTES_CAP,
        )
    }

    pub fn mutual_with_limits<H: Handler<DOMAIN>>(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        authentication: conn::server::Authentication<V>,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<Mux<H, conn::server::Mutual<NoGuard, V>, DOMAIN>, ConnectFailure> {
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
    V: ClientCertVerifier + 'static,
{
    pub fn mutual_with_early_data_guard<H: Handler<DOMAIN>>(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        authentication: conn::server::Authentication<V, G>,
    ) -> Result<Mux<H, conn::server::Mutual<G, V>, DOMAIN>, ConnectFailure> {
        Self::mutual_with_early_data_guard_and_limits(
            handler,
            signing_key,
            server_config,
            authentication,
            DEFAULT_MAX_CONNS,
            DEFAULT_OUTGOING_CAP,
            DEFAULT_OUTGOING_BYTES_CAP,
        )
    }

    pub fn mutual_with_early_data_guard_and_limits<H: Handler<DOMAIN>>(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        authentication: conn::server::Authentication<V, G>,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<Mux<H, conn::server::Mutual<G, V>, DOMAIN>, ConnectFailure> {
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
    ) -> Result<PooledRouter<'tls, H, P, DOMAIN, B>, ConnectFailure>
    where
        H: Handler<DOMAIN, B>,
        B: ReceiveBuffer,
    {
        if pool.capacities().3 != crate::transport_params::Params::MAX_ENCODED_LEN
            || !pool.matches_shard(shard)
        {
            return Err(ConnectFailure::InvalidConfig);
        }
        let server_config = Validated::new_pooled_server(server_config)?;
        let server = ServerRuntime::pooled(server_config, shard, pool);
        construct_inner(
            handler,
            Some(server),
            max_conns,
            outgoing_capacity,
            outgoing_bytes_capacity,
        )
    }

    pub fn with_policy<H: Handler<DOMAIN>>(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        policy_setup: P::Setup,
    ) -> Result<Mux<H, P, DOMAIN>, ConnectFailure> {
        Self::with_policy_and_limits(
            handler,
            signing_key,
            server_config,
            policy_setup,
            DEFAULT_MAX_CONNS,
            DEFAULT_OUTGOING_CAP,
            DEFAULT_OUTGOING_BYTES_CAP,
        )
    }

    pub fn with_policy_and_limits<H: Handler<DOMAIN>>(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        policy_setup: P::Setup,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<Mux<H, P, DOMAIN>, ConnectFailure> {
        let server_config = Validated::new(server_config)?;
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

    pub(crate) fn build<H: Handler<DOMAIN>>(
        handler: H,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        policy_setup: P::Setup,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<Mux<H, P, DOMAIN>, ConnectFailure> {
        let server_config = Validated::new(server_config)?;
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
        signing_key: SigningKey,
        mut server_config: Validated,
        policy_setup: P::Setup,
        max_conns: usize,
        outgoing_capacity: usize,
        outgoing_bytes_capacity: usize,
    ) -> Result<Mux<H, P, DOMAIN, B>, ConnectFailure>
    where
        H: Handler<DOMAIN, B>,
        B: ReceiveBuffer,
    {
        let shard_config = server_config.take_server_config(signing_key)?;
        let shard =
            P::build::<DOMAIN>(shard_config, policy_setup).map_err(|_| ConnectFailure::Tls)?;
        let server = ServerRuntime::new(server_config, shard);
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
    use ring::rand::{SecureRandom, SystemRandom};

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

fn construct<H, P, const DOMAIN: u8, B: ReceiveBuffer>(
    handler: H,
    server: Option<ServerRuntime<'static, P, DOMAIN>>,
    max_conns: usize,
    outgoing_capacity: usize,
    outgoing_bytes_capacity: usize,
) -> Result<Mux<H, P, DOMAIN, B>, ConnectFailure>
where
    H: Handler<DOMAIN, B>,
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

fn construct_inner<'tls, H, P, const DOMAIN: u8, B: ReceiveBuffer>(
    handler: H,
    server: Option<ServerRuntime<'tls, P, DOMAIN>>,
    max_conns: usize,
    outgoing_capacity: usize,
    outgoing_bytes_capacity: usize,
) -> Result<PooledRouter<'tls, H, P, DOMAIN, B>, ConnectFailure>
where
    H: Handler<DOMAIN, B>,
    P: conn::server::Policy,
{
    if max_conns == 0
        || max_conns > MAX_CONNECTIONS
        || outgoing_capacity == 0
        || outgoing_capacity > MAX_OUTGOING_CAPACITY
        || outgoing_bytes_capacity == 0
        || outgoing_bytes_capacity > MAX_OUTGOING_BYTES
    {
        return Err(ConnectFailure::InvalidConfig);
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
