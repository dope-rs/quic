pub mod raw;
mod runtime;
mod sealed;

use std::io;
use std::net;
use std::pin;
use std::time;

use dope::core::driver;
use dope::manifold::datagram;
use pin_project;
use shin::crypto::sig;
use shin::crypto::ticket;
use shin::server::config;

use crate::conn;
use crate::conn::session;
use crate::mux;

use crate::packet;
use crate::stream;
use crate::transport_params;

#[pin_project::pin_project]
pub struct Socket<
    'd,
    'tls,
    const ID: u8,
    H: mux::Handler<ID, B>,
    P: conn::server::Policy = conn::server::Standard,
    B: stream::ReceiveBuffer = Vec<u8>,
> {
    #[pin]
    udp: datagram::Endpoint<'d, ID, runtime::Runtime<'d, 'tls, H, P, ID, B>>,
    packet_buffer_bytes: u32,
}

/// Endpoint whose receive payloads may retain driver-owned packet storage.
pub type Endpoint<'d, const ID: u8, H, P = conn::server::Standard, B = Vec<u8>> =
    Socket<'d, 'static, ID, H, P, B>;

pub type PooledSocket<'d, 'tls, const ID: u8, H, P = conn::server::Standard, B = Vec<u8>> =
    Socket<'d, 'tls, ID, H, P, B>;

pub type RetainedSocket<'d, const ID: u8, H, P = conn::server::Standard> =
    Endpoint<'d, ID, H, P, stream::RecvBuffer<'d>>;

pub type PooledRetainedSocket<'d, 'tls, const ID: u8, H, P = conn::server::Standard> =
    PooledSocket<'d, 'tls, ID, H, P, stream::RecvBuffer<'d>>;

/// Lifecycle-preserving endpoint operations for one application step.
pub struct ControlInner<'step, 'd, 'tls, const ID: u8, H, P = conn::server::Standard, B = Vec<u8>>
where
    'd: 'step,
    H: mux::Handler<ID, B>,
    P: conn::server::Policy,
    B: Storage<'d>,
{
    inner: pin::Pin<&'step mut PooledSocket<'d, 'tls, ID, H, P, B>>,
}

pub type Control<'step, 'd, const ID: u8, H, P = conn::server::Standard, B = Vec<u8>> =
    ControlInner<'step, 'd, 'static, ID, H, P, B>;

pub type PooledControl<'step, 'd, 'tls, const ID: u8, H, P = conn::server::Standard, B = Vec<u8>> =
    ControlInner<'step, 'd, 'tls, ID, H, P, B>;

/// Lifecycle control for a [`RetainedSocket`].
pub type RetainedControl<'step, 'd, const ID: u8, H, P = conn::server::Standard> =
    Control<'step, 'd, ID, H, P, stream::RecvBuffer<'d>>;

/// Lifecycle control for a [`PooledRetainedSocket`].
pub type PooledRetainedControl<'step, 'd, 'tls, const ID: u8, H, P = conn::server::Standard> =
    PooledControl<'step, 'd, 'tls, ID, H, P, stream::RecvBuffer<'d>>;

impl<'step, 'd, 'tls, const ID: u8, H, P, B> ControlInner<'step, 'd, 'tls, ID, H, P, B>
where
    'd: 'step,
    H: mux::Handler<ID, B>,
    P: conn::server::Policy,
    B: Storage<'d>,
{
    pub fn handler(&self) -> &H {
        self.inner.as_ref().get_ref().handler()
    }

    pub fn connect(
        &mut self,
        peer_addr: net::SocketAddr,
        server_pubkey: [u8; 32],
        client_tp: transport_params::Params,
        initial_dcid: Vec<u8>,
    ) -> Result<conn::Handle, crate::errors::ConnectFailure> {
        self.inner
            .as_mut()
            .connect(peer_addr, server_pubkey, client_tp, initial_dcid)
    }

    pub fn connect_pooled(
        &mut self,
        peer_addr: net::SocketAddr,
        pool: &'tls conn::tls::ClientPool,
        client_tp: transport_params::Params,
        initial_dcid: Vec<u8>,
    ) -> Result<conn::Handle, crate::errors::ConnectFailure> {
        self.inner
            .as_mut()
            .connect_pooled(peer_addr, pool, client_tp, initial_dcid)
    }

    pub fn conn_mut(
        &mut self,
        handle: conn::Handle,
    ) -> Option<mux::ConnectionMut<'_, 'tls, H, P, ID, B>> {
        self.inner.as_mut().conn_mut(handle)
    }

    pub fn try_send_datagram(
        &mut self,
        handle: conn::Handle,
        data: Vec<u8>,
    ) -> Result<(), crate::errors::SendFailure<Vec<u8>>> {
        self.inner.as_mut().try_send_datagram(handle, data)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub max_conns: usize,
    pub outgoing_capacity: usize,
    pub outgoing_bytes_capacity: usize,
    pub packet_buffer_slots: u32,
    pub packet_buffer_bytes: u32,
}

impl Config {
    pub(crate) fn validate(self) -> io::Result<Self> {
        if self.max_conns == 0
            || self.outgoing_capacity == 0
            || self.outgoing_bytes_capacity < 1200
            || self.packet_buffer_slots == 0
            || self.packet_buffer_bytes < 1200
            || self.max_conns > crate::mux::MAX_CONNECTIONS
            || self.outgoing_capacity > crate::mux::MAX_OUTGOING_CAPACITY
            || self.outgoing_bytes_capacity > crate::mux::MAX_OUTGOING_BYTES
            || self.packet_buffer_slots as usize > crate::mux::MAX_OUTGOING_CAPACITY
            || self.packet_buffer_bytes > u32::from(u16::MAX)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid endpoint capacity",
            ));
        }
        Ok(self)
    }

    fn datagram(self, retained_receive_bytes: usize) -> io::Result<datagram::Config> {
        datagram::Config::new(
            self.outgoing_capacity,
            self.outgoing_bytes_capacity,
            self.outgoing_capacity,
        )
        .map(|config| config.with_retained_receive_bytes(retained_receive_bytes))
    }
}

/// Compile-time receive policy used by [`Endpoint`].
///
/// `Vec<u8>` selects independently owned copied ranges. [`RecvBuffer`] selects
/// driver-branded retention when resident amplification is bounded and falls
/// back to one exact shared owner for all packet payload bytes that escape.
/// Dispatch is statically resolved for each endpoint type.
#[doc(hidden)]
pub trait Storage<'d>: stream::ReceiveBuffer {
    fn datagram_config(config: Config) -> io::Result<datagram::Config>;

    fn receive_packet<'turn, 'tls, const ID: u8, H, P>(
        mux: &mut mux::PooledRouter<'tls, H, P, ID, Self>,
        addr: net::SocketAddr,
        packet: datagram::packet::Packet<'turn, 'd>,
        socket: pin::Pin<&'turn mut datagram::Socket<'d, ID>>,
        now: time::Instant,
    ) -> Result<(), conn::Error>
    where
        H: mux::Handler<ID, Self>,
        P: conn::server::Policy;
}

impl<'d> Storage<'d> for Vec<u8> {
    fn datagram_config(config: Config) -> io::Result<datagram::Config> {
        config.datagram(0)
    }

    fn receive_packet<'turn, 'tls, const ID: u8, H, P>(
        mux: &mut mux::PooledRouter<'tls, H, P, ID, Self>,
        addr: net::SocketAddr,
        mut packet: datagram::packet::Packet<'turn, 'd>,
        _socket: pin::Pin<&'turn mut datagram::Socket<'d, ID>>,
        now: time::Instant,
    ) -> Result<(), conn::Error>
    where
        H: mux::Handler<ID, Self>,
        P: conn::server::Policy,
    {
        mux.protocol().recv(addr, packet.as_mut(), now)
    }
}

impl<'d> Storage<'d> for stream::RecvBuffer<'d> {
    fn datagram_config(config: Config) -> io::Result<datagram::Config> {
        let retained_receive_bytes = (config.packet_buffer_slots as usize)
            .checked_mul(config.packet_buffer_bytes as usize)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "receive byte budget overflow")
            })?;
        config.datagram(retained_receive_bytes)
    }

    fn receive_packet<'turn, 'tls, const ID: u8, H, P>(
        mux: &mut mux::PooledRouter<'tls, H, P, ID, Self>,
        addr: net::SocketAddr,
        packet: datagram::packet::Packet<'turn, 'd>,
        socket: pin::Pin<&'turn mut datagram::Socket<'d, ID>>,
        now: time::Instant,
    ) -> Result<(), conn::Error>
    where
        H: mux::Handler<ID, Self>,
        P: conn::server::Policy,
    {
        mux.protocol()
            .recv_packet(addr, packet, socket.as_ref().packet_retainer(), now)
    }
}

impl<'d, const ID: u8, H, B> Endpoint<'d, ID, H, conn::server::Standard, B>
where
    H: mux::Handler<ID, B>,
    B: Storage<'d>,
{
    pub fn build_server(
        bind: net::SocketAddr,
        signing_key: sig::SigningKey,
        server_tp: transport_params::Params,
        handler: H,
        config: Config,
        driver: &mut driver::Context<'_, 'd>,
    ) -> io::Result<Self> {
        Self::build_server_with_config(bind, signing_key, server_tp.into(), handler, config, driver)
    }

    pub fn build_server_with_config(
        bind: net::SocketAddr,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        handler: H,
        config: Config,
        driver: &mut driver::Context<'_, 'd>,
    ) -> io::Result<Self> {
        Self::build_server_with_policy(
            bind,
            signing_key,
            server_config,
            config::NoGuard,
            handler,
            config,
            driver,
        )
    }

    pub fn build_client(
        bind: net::SocketAddr,
        handler: H,
        config: Config,
        driver: &mut driver::Context<'_, 'd>,
    ) -> io::Result<Self> {
        let config = config.validate()?;
        let mux = mux::setup::Client::new(handler)
            .limits(
                config.max_conns,
                config.outgoing_capacity,
                config.outgoing_bytes_capacity,
            )
            .build()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let udp = datagram::Endpoint::bind_with_config(
            bind,
            runtime::Runtime::new(mux),
            B::datagram_config(config)?,
            driver,
        )?;
        Ok(Self {
            udp,
            packet_buffer_bytes: config.packet_buffer_bytes,
        })
    }
}

impl<'d, const ID: u8, H, G, B> Endpoint<'d, ID, H, conn::server::Standard<G>, B>
where
    H: mux::Handler<ID, B>,
    G: conn::server::ReplayGuard + 'static,
    B: Storage<'d>,
{
    pub fn build_server_with_early_data_guard(
        bind: net::SocketAddr,
        signing_key: sig::SigningKey,
        server_tp: transport_params::Params,
        guard: G,
        handler: H,
        config: Config,
        driver: &mut driver::Context<'_, 'd>,
    ) -> io::Result<Self> {
        Self::build_server_with_config_and_early_data_guard(
            bind,
            signing_key,
            server_tp.into(),
            guard,
            handler,
            config,
            driver,
        )
    }

    pub fn build_server_with_config_and_early_data_guard(
        bind: net::SocketAddr,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        guard: G,
        handler: H,
        config: Config,
        driver: &mut driver::Context<'_, 'd>,
    ) -> io::Result<Self> {
        Self::build_server_with_policy(
            bind,
            signing_key,
            server_config,
            guard,
            handler,
            config,
            driver,
        )
    }
}

impl<'d, const ID: u8, H, V, B> Endpoint<'d, ID, H, conn::server::Mutual<config::NoGuard, V>, B>
where
    H: mux::Handler<ID, B>,
    V: config::ClientCertVerifier + 'static,
    B: Storage<'d>,
{
    pub fn build_server_mutual(
        bind: net::SocketAddr,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        authentication: conn::server::Authentication<V>,
        handler: H,
        config: Config,
        driver: &mut driver::Context<'_, 'd>,
    ) -> io::Result<Self> {
        Self::build_server_with_policy(
            bind,
            signing_key,
            server_config,
            authentication,
            handler,
            config,
            driver,
        )
    }
}

impl<'d, const ID: u8, H, G, V, B> Endpoint<'d, ID, H, conn::server::Mutual<G, V>, B>
where
    H: mux::Handler<ID, B>,
    G: conn::server::ReplayGuard + 'static,
    V: config::ClientCertVerifier + 'static,
    B: Storage<'d>,
{
    pub fn build_server_mutual_with_early_data_guard(
        bind: net::SocketAddr,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        authentication: conn::server::Authentication<V, G>,
        handler: H,
        config: Config,
        driver: &mut driver::Context<'_, 'd>,
    ) -> io::Result<Self> {
        Self::build_server_with_policy(
            bind,
            signing_key,
            server_config,
            authentication,
            handler,
            config,
            driver,
        )
    }
}

impl<'d, const ID: u8, H, P, B> Endpoint<'d, ID, H, P, B>
where
    H: mux::Handler<ID, B>,
    P: conn::server::Policy,
    B: Storage<'d>,
{
    pub fn build_server_with_policy(
        bind: net::SocketAddr,
        signing_key: sig::SigningKey,
        server_config: conn::config::Options,
        setup: P::Setup,
        handler: H,
        config: Config,
        driver: &mut driver::Context<'_, 'd>,
    ) -> io::Result<Self> {
        let config = config.validate()?;
        let mut server_config = crate::conn::config::Validated::new(server_config)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        server_config
            .cap_max_pmtu(u64::from(config.packet_buffer_bytes))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let mux = mux::setup::Server::<P, ID>::build_validated(
            handler,
            signing_key,
            server_config,
            setup,
            config.max_conns,
            config.outgoing_capacity,
            config.outgoing_bytes_capacity,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let udp = datagram::Endpoint::bind_with_config(
            bind,
            runtime::Runtime::new(mux),
            B::datagram_config(config)?,
            driver,
        )?;
        Ok(Self {
            udp,
            packet_buffer_bytes: config.packet_buffer_bytes,
        })
    }
}

impl<'d, 'tls, const ID: u8, H, P, B> Socket<'d, 'tls, ID, H, P, B>
where
    H: mux::Handler<ID, B>,
    P: conn::server::Policy,
    B: Storage<'d>,
{
    pub fn local_addr(&self) -> net::SocketAddr {
        self.udp.local_addr()
    }

    pub fn enable_gso(self: pin::Pin<&mut Self>) -> io::Result<()> {
        self.project()
            .udp
            .handler_mut()
            .mux
            .configuration()
            .enable_gso()
    }

    pub fn disable_gso(self: pin::Pin<&mut Self>) {
        self.project()
            .udp
            .handler_mut()
            .mux
            .configuration()
            .disable_gso();
    }

    pub fn handler(&self) -> &H {
        self.udp.handler().mux.handler()
    }

    pub(crate) fn handler_mut(self: pin::Pin<&mut Self>) -> &mut H {
        self.project().udp.handler_mut().mux.handler_mut()
    }

    pub fn connect(
        self: pin::Pin<&mut Self>,
        peer_addr: net::SocketAddr,
        server_pubkey: [u8; 32],
        client_tp: transport_params::Params,
        initial_dcid: Vec<u8>,
    ) -> Result<conn::Handle, crate::errors::ConnectFailure> {
        self.connect_with_config(peer_addr, server_pubkey, client_tp.into(), initial_dcid)
    }

    pub fn connect_with_config(
        self: pin::Pin<&mut Self>,
        peer_addr: net::SocketAddr,
        server_pubkey: [u8; 32],
        client_config: conn::config::Options,
        initial_dcid: Vec<u8>,
    ) -> Result<conn::Handle, crate::errors::ConnectFailure> {
        let initial_dcid = packet::ConnectionId::try_from(initial_dcid)
            .map_err(|_| crate::errors::ConnectFailure::InvalidConfig)?;
        self.connect_with_config_id(peer_addr, server_pubkey, client_config, initial_dcid)
    }

    pub(crate) fn connect_with_config_id(
        self: pin::Pin<&mut Self>,
        peer_addr: net::SocketAddr,
        server_pubkey: [u8; 32],
        mut client_config: conn::config::Options,
        initial_dcid: packet::ConnectionId,
    ) -> Result<conn::Handle, crate::errors::ConnectFailure> {
        let now = time::Instant::now();
        client_config.max_pmtu = client_config
            .max_pmtu
            .min(u64::from(self.packet_buffer_bytes))
            .min(crate::pmtud::MAX_PMTU);
        self.project().udp.handler_mut().mux.protocol().connect_id(
            peer_addr,
            server_pubkey,
            client_config,
            initial_dcid,
            now,
        )
    }

    pub fn conn(&self, handle: conn::Handle) -> Option<&session::Connection<ID, B>> {
        self.udp.handler().mux.conn(handle)
    }

    pub fn conn_mut(
        self: pin::Pin<&mut Self>,
        handle: conn::Handle,
    ) -> Option<mux::ConnectionMut<'_, 'tls, H, P, ID, B>> {
        self.project()
            .udp
            .handler_mut()
            .mux
            .protocol()
            .conn_mut(handle)
    }

    pub fn try_send_datagram(
        self: pin::Pin<&mut Self>,
        handle: conn::Handle,
        data: Vec<u8>,
    ) -> Result<(), crate::errors::SendFailure<Vec<u8>>> {
        let now = time::Instant::now();
        self.project()
            .udp
            .handler_mut()
            .mux
            .protocol()
            .try_send_datagram(handle, data, now)
    }

    pub fn close(self: pin::Pin<&mut Self>, handle: conn::Handle) {
        self.project()
            .udp
            .handler_mut()
            .mux
            .protocol()
            .close(handle);
    }

    pub fn replace_ticket_keys(self: pin::Pin<&mut Self>, keys: Option<ticket::Keys>) -> bool {
        self.project()
            .udp
            .handler_mut()
            .mux
            .configuration()
            .replace_ticket_keys(keys)
    }
}

impl<'d, 'tls, const ID: u8, H, B> Socket<'d, 'tls, ID, H, conn::server::Standard, B>
where
    H: mux::Handler<ID, B>,
    B: Storage<'d>,
{
    /// Builds a client endpoint whose connection slots may borrow external TLS
    /// pools for exactly `'tls`.
    pub fn build_client_pooled(
        bind: net::SocketAddr,
        handler: H,
        config: Config,
        driver: &mut driver::Context<'_, 'd>,
    ) -> io::Result<Self> {
        let config = config.validate()?;
        let mux = mux::setup::Client::new(handler)
            .limits(
                config.max_conns,
                config.outgoing_capacity,
                config.outgoing_bytes_capacity,
            )
            .build_pooled()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let udp = datagram::Endpoint::bind_with_config(
            bind,
            runtime::Runtime::new(mux),
            B::datagram_config(config)?,
            driver,
        )?;
        Ok(Self {
            udp,
            packet_buffer_bytes: config.packet_buffer_bytes,
        })
    }
}

impl<'d, 'tls, const ID: u8, H, P, B> Socket<'d, 'tls, ID, H, P, B>
where
    H: mux::Handler<ID, B>,
    P: conn::server::Policy,
    B: Storage<'d>,
{
    /// Builds a server endpoint over one externally owned, shard-bound TLS
    /// pool. The endpoint cannot outlive either borrowed authority.
    pub fn build_server_pooled(
        bind: net::SocketAddr,
        mut server_config: conn::config::Options,
        shard: &'tls shin::server::Shard<P::Guard, P::Verifier, ID>,
        pool: &'tls conn::tls::ServerPool<P::Verifier, ID, P::Guard>,
        handler: H,
        config: Config,
        driver: &mut driver::Context<'_, 'd>,
    ) -> io::Result<Self> {
        let config = config.validate()?;
        server_config.max_pmtu = server_config
            .max_pmtu
            .min(u64::from(config.packet_buffer_bytes))
            .min(crate::pmtud::MAX_PMTU);
        let mux = mux::setup::Server::<P, ID>::with_pool(
            handler,
            server_config,
            shard,
            pool,
            config.max_conns,
            config.outgoing_capacity,
            config.outgoing_bytes_capacity,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let udp = datagram::Endpoint::bind_with_config(
            bind,
            runtime::Runtime::new(mux),
            B::datagram_config(config)?,
            driver,
        )?;
        Ok(Self {
            udp,
            packet_buffer_bytes: config.packet_buffer_bytes,
        })
    }

    pub fn connect_pooled(
        self: pin::Pin<&mut Self>,
        peer_addr: net::SocketAddr,
        pool: &'tls conn::tls::ClientPool,
        client_tp: transport_params::Params,
        initial_dcid: Vec<u8>,
    ) -> Result<conn::Handle, crate::errors::ConnectFailure> {
        self.connect_pooled_with_config(peer_addr, pool, client_tp.into(), initial_dcid)
    }

    pub fn connect_pooled_with_config(
        self: pin::Pin<&mut Self>,
        peer_addr: net::SocketAddr,
        pool: &'tls conn::tls::ClientPool,
        client_config: conn::config::Options,
        initial_dcid: Vec<u8>,
    ) -> Result<conn::Handle, crate::errors::ConnectFailure> {
        let initial_dcid = packet::ConnectionId::try_from(initial_dcid)
            .map_err(|_| crate::errors::ConnectFailure::InvalidConfig)?;
        self.connect_pooled_with_config_id(peer_addr, pool, client_config, initial_dcid)
    }

    pub(crate) fn connect_pooled_with_config_id(
        self: pin::Pin<&mut Self>,
        peer_addr: net::SocketAddr,
        pool: &'tls conn::tls::ClientPool,
        mut client_config: conn::config::Options,
        initial_dcid: packet::ConnectionId,
    ) -> Result<conn::Handle, crate::errors::ConnectFailure> {
        let now = time::Instant::now();
        client_config.max_pmtu = client_config
            .max_pmtu
            .min(u64::from(self.packet_buffer_bytes))
            .min(crate::pmtud::MAX_PMTU);
        self.project()
            .udp
            .handler_mut()
            .mux
            .protocol()
            .connect_pooled_id(peer_addr, pool, client_config, initial_dcid, now)
    }
}
