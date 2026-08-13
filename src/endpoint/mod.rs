pub mod raw;
mod runtime;
mod sealed;

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Instant;

use dope::core::driver::Context;
use dope::manifold::datagram;
use pin_project::pin_project;
use shin::crypto::sig::SigningKey;
use shin::crypto::ticket::Keys;
use shin::server::{config::ClientCertVerifier, config::NoGuard};

use crate::ConnectError;
use crate::TrySendError;
use crate::conn::session::Connection;
use crate::conn::{self, Handle, config::Validated};
use crate::mux;
use crate::mux::{MAX_CONNECTIONS, MAX_OUTGOING_BYTES, MAX_OUTGOING_CAPACITY};
use crate::packet::ConnectionId;
use crate::stream::{ReceiveBuffer, RecvBuffer};
use crate::transport_params;
use std::io::Error;
use std::io::ErrorKind;

#[pin_project]
pub struct EndpointInner<
    'd,
    'tls,
    const ID: u8,
    H: mux::Handler<ID, B>,
    P: conn::server::Policy = conn::server::Standard,
    B: ReceiveBuffer = Vec<u8>,
> {
    #[pin]
    udp: datagram::Endpoint<'d, ID, runtime::Runtime<'d, 'tls, H, P, ID, B>>,
    packet_buffer_bytes: u32,
}

/// Endpoint whose receive payloads may retain driver-owned packet storage.
pub type Endpoint<'d, const ID: u8, H, P = conn::server::Standard, B = Vec<u8>> =
    EndpointInner<'d, 'static, ID, H, P, B>;

pub type PooledEndpoint<'d, 'tls, const ID: u8, H, P = conn::server::Standard, B = Vec<u8>> =
    EndpointInner<'d, 'tls, ID, H, P, B>;

pub type RetainedEndpoint<'d, const ID: u8, H, P = conn::server::Standard> =
    Endpoint<'d, ID, H, P, RecvBuffer<'d>>;

pub type PooledRetainedEndpoint<'d, 'tls, const ID: u8, H, P = conn::server::Standard> =
    PooledEndpoint<'d, 'tls, ID, H, P, RecvBuffer<'d>>;

/// Lifecycle-preserving endpoint operations for one application step.
pub struct ControlInner<'step, 'd, 'tls, const ID: u8, H, P = conn::server::Standard, B = Vec<u8>>
where
    'd: 'step,
    H: mux::Handler<ID, B>,
    P: conn::server::Policy,
    B: EndpointBuffer<'d>,
{
    inner: Pin<&'step mut PooledEndpoint<'d, 'tls, ID, H, P, B>>,
}

pub type Control<'step, 'd, const ID: u8, H, P = conn::server::Standard, B = Vec<u8>> =
    ControlInner<'step, 'd, 'static, ID, H, P, B>;

pub type PooledControl<'step, 'd, 'tls, const ID: u8, H, P = conn::server::Standard, B = Vec<u8>> =
    ControlInner<'step, 'd, 'tls, ID, H, P, B>;

/// Lifecycle control for a [`RetainedEndpoint`].
pub type RetainedControl<'step, 'd, const ID: u8, H, P = conn::server::Standard> =
    Control<'step, 'd, ID, H, P, RecvBuffer<'d>>;

/// Lifecycle control for a [`PooledRetainedEndpoint`].
pub type PooledRetainedControl<'step, 'd, 'tls, const ID: u8, H, P = conn::server::Standard> =
    PooledControl<'step, 'd, 'tls, ID, H, P, RecvBuffer<'d>>;

impl<'step, 'd, 'tls, const ID: u8, H, P, B> ControlInner<'step, 'd, 'tls, ID, H, P, B>
where
    'd: 'step,
    H: mux::Handler<ID, B>,
    P: conn::server::Policy,
    B: EndpointBuffer<'d>,
{
    pub fn handler(&self) -> &H {
        self.inner.as_ref().get_ref().handler()
    }

    pub fn connect(
        &mut self,
        peer_addr: SocketAddr,
        server_pubkey: [u8; 32],
        client_tp: transport_params::Params,
        initial_dcid: Vec<u8>,
    ) -> Result<Handle, ConnectError> {
        self.inner
            .as_mut()
            .connect(peer_addr, server_pubkey, client_tp, initial_dcid)
    }

    pub fn connect_pooled(
        &mut self,
        peer_addr: SocketAddr,
        pool: &'tls conn::tls::ClientPool,
        client_tp: transport_params::Params,
        initial_dcid: Vec<u8>,
    ) -> Result<Handle, ConnectError> {
        self.inner
            .as_mut()
            .connect_pooled(peer_addr, pool, client_tp, initial_dcid)
    }

    pub fn conn_mut(
        &mut self,
        handle: Handle,
    ) -> Option<mux::ConnectionMut<'_, 'tls, H, P, ID, B>> {
        self.inner.as_mut().conn_mut(handle)
    }

    pub fn try_send_datagram(
        &mut self,
        handle: Handle,
        data: Vec<u8>,
    ) -> Result<(), TrySendError<Vec<u8>>> {
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
            || self.max_conns > MAX_CONNECTIONS
            || self.outgoing_capacity > MAX_OUTGOING_CAPACITY
            || self.outgoing_bytes_capacity > MAX_OUTGOING_BYTES
            || self.packet_buffer_slots as usize > MAX_OUTGOING_CAPACITY
            || self.packet_buffer_bytes > u32::from(u16::MAX)
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
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
pub trait EndpointBuffer<'d>: ReceiveBuffer {
    fn datagram_config(config: Config) -> io::Result<datagram::Config>;

    fn receive_packet<'turn, 'tls, const ID: u8, H, P>(
        mux: &mut mux::PooledMux<'tls, H, P, ID, Self>,
        addr: SocketAddr,
        packet: datagram::packet::Packet<'turn, 'd>,
        socket: Pin<&'turn mut datagram::Socket<'d, ID>>,
        now: Instant,
    ) -> Result<(), conn::Error>
    where
        H: mux::Handler<ID, Self>,
        P: conn::server::Policy;
}

impl<'d> EndpointBuffer<'d> for Vec<u8> {
    fn datagram_config(config: Config) -> io::Result<datagram::Config> {
        config.datagram(0)
    }

    fn receive_packet<'turn, 'tls, const ID: u8, H, P>(
        mux: &mut mux::PooledMux<'tls, H, P, ID, Self>,
        addr: SocketAddr,
        mut packet: datagram::packet::Packet<'turn, 'd>,
        _socket: Pin<&'turn mut datagram::Socket<'d, ID>>,
        now: Instant,
    ) -> Result<(), conn::Error>
    where
        H: mux::Handler<ID, Self>,
        P: conn::server::Policy,
    {
        mux.protocol().recv(addr, packet.as_mut(), now)
    }
}

impl<'d> EndpointBuffer<'d> for RecvBuffer<'d> {
    fn datagram_config(config: Config) -> io::Result<datagram::Config> {
        let retained_receive_bytes = (config.packet_buffer_slots as usize)
            .checked_mul(config.packet_buffer_bytes as usize)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "receive byte budget overflow"))?;
        config.datagram(retained_receive_bytes)
    }

    fn receive_packet<'turn, 'tls, const ID: u8, H, P>(
        mux: &mut mux::PooledMux<'tls, H, P, ID, Self>,
        addr: SocketAddr,
        packet: datagram::packet::Packet<'turn, 'd>,
        socket: Pin<&'turn mut datagram::Socket<'d, ID>>,
        now: Instant,
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
    B: EndpointBuffer<'d>,
{
    pub fn build_server(
        bind: SocketAddr,
        signing_key: SigningKey,
        server_tp: transport_params::Params,
        handler: H,
        config: Config,
        driver: &mut Context<'_, 'd>,
    ) -> io::Result<Self> {
        Self::build_server_with_config(bind, signing_key, server_tp.into(), handler, config, driver)
    }

    pub fn build_server_with_config(
        bind: SocketAddr,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        handler: H,
        config: Config,
        driver: &mut Context<'_, 'd>,
    ) -> io::Result<Self> {
        Self::build_server_with_policy(
            bind,
            signing_key,
            server_config,
            NoGuard,
            handler,
            config,
            driver,
        )
    }

    pub fn build_client(
        bind: SocketAddr,
        handler: H,
        config: Config,
        driver: &mut Context<'_, 'd>,
    ) -> io::Result<Self> {
        let config = config.validate()?;
        let mux = mux::setup::Client::new(handler)
            .limits(
                config.max_conns,
                config.outgoing_capacity,
                config.outgoing_bytes_capacity,
            )
            .build()
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
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
    B: EndpointBuffer<'d>,
{
    pub fn build_server_with_early_data_guard(
        bind: SocketAddr,
        signing_key: SigningKey,
        server_tp: transport_params::Params,
        guard: G,
        handler: H,
        config: Config,
        driver: &mut Context<'_, 'd>,
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
        bind: SocketAddr,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        guard: G,
        handler: H,
        config: Config,
        driver: &mut Context<'_, 'd>,
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

impl<'d, const ID: u8, H, V, B> Endpoint<'d, ID, H, conn::server::Mutual<NoGuard, V>, B>
where
    H: mux::Handler<ID, B>,
    V: ClientCertVerifier + 'static,
    B: EndpointBuffer<'d>,
{
    pub fn build_server_mutual(
        bind: SocketAddr,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        authentication: conn::server::Authentication<V>,
        handler: H,
        config: Config,
        driver: &mut Context<'_, 'd>,
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
    V: ClientCertVerifier + 'static,
    B: EndpointBuffer<'d>,
{
    pub fn build_server_mutual_with_early_data_guard(
        bind: SocketAddr,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        authentication: conn::server::Authentication<V, G>,
        handler: H,
        config: Config,
        driver: &mut Context<'_, 'd>,
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
    B: EndpointBuffer<'d>,
{
    pub fn build_server_with_policy(
        bind: SocketAddr,
        signing_key: SigningKey,
        server_config: conn::config::Options,
        setup: P::Setup,
        handler: H,
        config: Config,
        driver: &mut Context<'_, 'd>,
    ) -> io::Result<Self> {
        let config = config.validate()?;
        let mut server_config = Validated::new(server_config)
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
        server_config
            .cap_max_pmtu(u64::from(config.packet_buffer_bytes))
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
        let mux = mux::setup::Server::<P, ID>::build_validated(
            handler,
            signing_key,
            server_config,
            setup,
            config.max_conns,
            config.outgoing_capacity,
            config.outgoing_bytes_capacity,
        )
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
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

impl<'d, 'tls, const ID: u8, H, P, B> EndpointInner<'d, 'tls, ID, H, P, B>
where
    H: mux::Handler<ID, B>,
    P: conn::server::Policy,
    B: EndpointBuffer<'d>,
{
    pub fn local_addr(&self) -> SocketAddr {
        self.udp.local_addr()
    }

    pub fn enable_gso(self: Pin<&mut Self>) -> io::Result<()> {
        self.project()
            .udp
            .handler_mut()
            .mux
            .configuration()
            .enable_gso()
    }

    pub fn disable_gso(self: Pin<&mut Self>) {
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

    pub(crate) fn handler_mut(self: Pin<&mut Self>) -> &mut H {
        self.project().udp.handler_mut().mux.handler_mut()
    }

    pub fn connect(
        self: Pin<&mut Self>,
        peer_addr: SocketAddr,
        server_pubkey: [u8; 32],
        client_tp: transport_params::Params,
        initial_dcid: Vec<u8>,
    ) -> Result<Handle, ConnectError> {
        self.connect_with_config(peer_addr, server_pubkey, client_tp.into(), initial_dcid)
    }

    pub fn connect_with_config(
        self: Pin<&mut Self>,
        peer_addr: SocketAddr,
        server_pubkey: [u8; 32],
        client_config: conn::config::Options,
        initial_dcid: Vec<u8>,
    ) -> Result<Handle, ConnectError> {
        let initial_dcid =
            ConnectionId::try_from(initial_dcid).map_err(|_| ConnectError::InvalidConfig)?;
        self.connect_with_config_id(peer_addr, server_pubkey, client_config, initial_dcid)
    }

    pub(crate) fn connect_with_config_id(
        self: Pin<&mut Self>,
        peer_addr: SocketAddr,
        server_pubkey: [u8; 32],
        mut client_config: conn::config::Options,
        initial_dcid: ConnectionId,
    ) -> Result<Handle, ConnectError> {
        let now = Instant::now();
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

    pub fn conn(&self, handle: Handle) -> Option<&Connection<ID, B>> {
        self.udp.handler().mux.conn(handle)
    }

    pub fn conn_mut(
        self: Pin<&mut Self>,
        handle: Handle,
    ) -> Option<mux::ConnectionMut<'_, 'tls, H, P, ID, B>> {
        self.project()
            .udp
            .handler_mut()
            .mux
            .protocol()
            .conn_mut(handle)
    }

    pub fn try_send_datagram(
        self: Pin<&mut Self>,
        handle: Handle,
        data: Vec<u8>,
    ) -> Result<(), TrySendError<Vec<u8>>> {
        let now = Instant::now();
        self.project()
            .udp
            .handler_mut()
            .mux
            .protocol()
            .try_send_datagram(handle, data, now)
    }

    pub fn close(self: Pin<&mut Self>, handle: Handle) {
        self.project()
            .udp
            .handler_mut()
            .mux
            .protocol()
            .close(handle);
    }

    pub fn replace_ticket_keys(self: Pin<&mut Self>, keys: Option<Keys>) -> bool {
        self.project()
            .udp
            .handler_mut()
            .mux
            .configuration()
            .replace_ticket_keys(keys)
    }
}

impl<'d, 'tls, const ID: u8, H, B> EndpointInner<'d, 'tls, ID, H, conn::server::Standard, B>
where
    H: mux::Handler<ID, B>,
    B: EndpointBuffer<'d>,
{
    /// Builds a client endpoint whose connection slots may borrow external TLS
    /// pools for exactly `'tls`.
    pub fn build_client_pooled(
        bind: SocketAddr,
        handler: H,
        config: Config,
        driver: &mut Context<'_, 'd>,
    ) -> io::Result<Self> {
        let config = config.validate()?;
        let mux = mux::setup::Client::new(handler)
            .limits(
                config.max_conns,
                config.outgoing_capacity,
                config.outgoing_bytes_capacity,
            )
            .build_pooled()
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
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

impl<'d, 'tls, const ID: u8, H, P, B> EndpointInner<'d, 'tls, ID, H, P, B>
where
    H: mux::Handler<ID, B>,
    P: conn::server::Policy,
    B: EndpointBuffer<'d>,
{
    /// Builds a server endpoint over one externally owned, shard-bound TLS
    /// pool. The endpoint cannot outlive either borrowed authority.
    pub fn build_server_pooled(
        bind: SocketAddr,
        mut server_config: conn::config::Options,
        shard: &'tls shin::server::Shard<P::Guard, P::Verifier, ID>,
        pool: &'tls conn::tls::ServerPool<P::Verifier, ID, P::Guard>,
        handler: H,
        config: Config,
        driver: &mut Context<'_, 'd>,
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
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
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
        self: Pin<&mut Self>,
        peer_addr: SocketAddr,
        pool: &'tls conn::tls::ClientPool,
        client_tp: transport_params::Params,
        initial_dcid: Vec<u8>,
    ) -> Result<Handle, ConnectError> {
        self.connect_pooled_with_config(peer_addr, pool, client_tp.into(), initial_dcid)
    }

    pub fn connect_pooled_with_config(
        self: Pin<&mut Self>,
        peer_addr: SocketAddr,
        pool: &'tls conn::tls::ClientPool,
        client_config: conn::config::Options,
        initial_dcid: Vec<u8>,
    ) -> Result<Handle, ConnectError> {
        let initial_dcid =
            ConnectionId::try_from(initial_dcid).map_err(|_| ConnectError::InvalidConfig)?;
        self.connect_pooled_with_config_id(peer_addr, pool, client_config, initial_dcid)
    }

    pub(crate) fn connect_pooled_with_config_id(
        self: Pin<&mut Self>,
        peer_addr: SocketAddr,
        pool: &'tls conn::tls::ClientPool,
        mut client_config: conn::config::Options,
        initial_dcid: ConnectionId,
    ) -> Result<Handle, ConnectError> {
        let now = Instant::now();
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
