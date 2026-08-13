pub mod raw;
mod sealed;

use std::io;
use std::net;
use std::pin;
use std::time;

use dope::core::driver;
use o3::collections::heap;
use o3::collections::queue::slot;
use pin_project;
use ring::rand::SecureRandom as _;

use crate::conn;
use crate::conn::session;
use crate::endpoint;
use crate::mux;
use crate::packet;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SlotId(u32);

impl SlotId {
    pub fn from_index(index: u32) -> Self {
        Self(index)
    }

    pub fn index(self) -> u32 {
        self.0
    }
}

pub trait BackoffPolicy: 'static {
    fn next_retry_at(&self, attempt: u32, now: time::Instant) -> time::Instant;
}

pub trait Protocol: 'static {
    fn connect(&mut self, slot: SlotId);
    fn datagram(&mut self, slot: SlotId, data: Vec<u8>);
    fn close(&mut self, slot: SlotId);
}

pub trait ConfigProvider: 'static {
    fn config(&mut self, slot: SlotId) -> Option<conn::config::Options>;
}

pub struct StaticConfig(conn::config::Options);

impl ConfigProvider for StaticConfig {
    fn config(&mut self, _slot: SlotId) -> Option<conn::config::Options> {
        self.0.duplicate_connection().ok()
    }
}

#[derive(Clone)]
pub struct EndpointSpec {
    pub addr: net::SocketAddr,
    pub pubkey: [u8; 32],
}

#[derive(Clone, Copy)]
/// One remote endpoint backed by externally owned, exactly reserved TLS state.
pub struct PooledEndpointSpec<'tls> {
    pub addr: net::SocketAddr,
    pub pool: &'tls conn::tls::ClientPool,
}

mod authority;
pub(crate) use authority::Authority;

#[doc(hidden)]
pub trait EndpointAuthority<'tls>: Copy + Authority {
    fn connect<'d, const ID: u8, H: mux::Handler<ID>>(
        self,
        endpoint: pin::Pin<&mut endpoint::PooledSocket<'d, 'tls, ID, H>>,
        addr: net::SocketAddr,
        config: conn::config::Options,
        dcid: packet::ConnectionId,
    ) -> Result<conn::Handle, crate::errors::ConnectFailure>;
}

impl Authority for [u8; 32] {}

impl<'tls> EndpointAuthority<'tls> for [u8; 32] {
    fn connect<'d, const ID: u8, H: mux::Handler<ID>>(
        self,
        endpoint: pin::Pin<&mut endpoint::PooledSocket<'d, 'tls, ID, H>>,
        addr: net::SocketAddr,
        config: conn::config::Options,
        dcid: packet::ConnectionId,
    ) -> Result<conn::Handle, crate::errors::ConnectFailure> {
        endpoint.connect_with_config_id(addr, self, config, dcid)
    }
}

impl Authority for &conn::tls::ClientPool {}

impl<'tls> EndpointAuthority<'tls> for &'tls conn::tls::ClientPool {
    fn connect<'d, const ID: u8, H: mux::Handler<ID>>(
        self,
        endpoint: pin::Pin<&mut endpoint::PooledSocket<'d, 'tls, ID, H>>,
        addr: net::SocketAddr,
        config: conn::config::Options,
        dcid: packet::ConnectionId,
    ) -> Result<conn::Handle, crate::errors::ConnectFailure> {
        endpoint.connect_pooled_with_config_id(addr, self, config, dcid)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub endpoint: endpoint::Config,
    pub event_budget: usize,
    pub retry_budget: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathStats {
    pub srtt: Option<time::Duration>,
    pub min_rtt: Option<time::Duration>,
    pub cwnd: u64,
    pub bytes_in_flight: u64,
}

struct EndpointSlot<A> {
    addr: net::SocketAddr,
    authority: A,
    handle: Option<conn::Handle>,
    attempt: u32,
}

#[derive(Clone, Copy)]
struct Binding {
    handle: conn::Handle,
    slot: SlotId,
}

struct Bridge<P: Protocol> {
    protocol: P,
    handle_to_slot: Box<[Option<Binding>]>,
    pending_close: slot::Fifo<Binding>,
    pending_established: slot::Fifo<Binding>,
}

impl<P: Protocol> Bridge<P> {
    fn lookup_slot(&self, handle: conn::Handle) -> Option<SlotId> {
        self.handle_to_slot
            .get(handle.index() as usize)
            .copied()
            .flatten()
            .filter(|binding| binding.handle == handle)
            .map(|binding| binding.slot)
    }

    fn bind(&mut self, handle: conn::Handle, slot: SlotId) -> bool {
        let Some(binding) = self.handle_to_slot.get_mut(handle.index() as usize) else {
            return false;
        };
        if binding.is_some() {
            return false;
        }
        *binding = Some(Binding { handle, slot });
        true
    }

    fn unbind(&mut self, handle: conn::Handle) -> Option<SlotId> {
        let binding = self.handle_to_slot.get_mut(handle.index() as usize)?;
        if !binding.is_some_and(|binding| binding.handle == handle) {
            return None;
        }
        binding.take().map(|binding| binding.slot)
    }
}

impl<const DOMAIN: u8, P: Protocol> mux::Handler<DOMAIN> for Bridge<P> {
    type Connection = ();

    fn create_connection(
        &mut self,
        _conn: &mut session::Connection<DOMAIN>,
        _handle: conn::Handle,
    ) {
    }

    fn established(
        &mut self,
        _connection: &mut (),
        _conn: &mut session::Connection<DOMAIN>,
        handle: conn::Handle,
    ) {
        if let Some(slot) = self.lookup_slot(handle) {
            let binding = Binding { handle, slot };
            if let Some(entry) = self.pending_established.vacant_entry(slot.index() as usize) {
                entry.push_back(binding);
            }
        }
    }

    fn datagram(
        &mut self,
        _connection: &mut (),
        _conn: &mut session::Connection<DOMAIN>,
        handle: conn::Handle,
        data: Vec<u8>,
    ) {
        if let Some(slot) = self.lookup_slot(handle) {
            self.protocol.datagram(slot, data);
        }
    }

    fn close(&mut self, _connection: (), handle: conn::Handle) {
        if let Some(slot) = self.unbind(handle) {
            self.protocol.close(slot);
            let binding = Binding { handle, slot };
            if let Some(entry) = self.pending_close.vacant_entry(slot.index() as usize) {
                entry.push_back(binding);
            }
        }
    }
}

#[pin_project::pin_project]
pub struct Dialer<
    'd,
    'tls,
    const ID: u8,
    P: Protocol,
    B: BackoffPolicy,
    A: EndpointAuthority<'tls>,
    C: ConfigProvider = StaticConfig,
> {
    #[pin]
    inner: endpoint::PooledSocket<'d, 'tls, ID, Bridge<P>>,
    endpoints: Vec<EndpointSlot<A>>,
    retries: heap::Min<time::Instant>,
    backoff: B,
    config_provider: C,
    event_budget: usize,
    retry_budget: usize,
    dcid_seed: u64,
}

pub type Client<'d, const ID: u8, P, B, C = StaticConfig> =
    Dialer<'d, 'static, ID, P, B, [u8; 32], C>;

/// High-level client whose active TLS handshakes cannot outlive their pools.
///
/// ```compile_fail
/// use dope_quic::client::{BackoffPolicy, ConfigProvider, PooledDialer, Protocol};
///
/// fn erase_pool_lifetime<'d, 'tls, const ID: u8, P, B, C>(
///     client: PooledDialer<'d, 'tls, ID, P, B, C>,
/// ) -> PooledDialer<'d, 'static, ID, P, B, C>
/// where
///     P: Protocol,
///     B: BackoffPolicy,
///     C: ConfigProvider,
/// {
///     client
/// }
/// ```
pub type PooledDialer<'d, 'tls, const ID: u8, P, B, C = StaticConfig> =
    Dialer<'d, 'tls, ID, P, B, &'tls conn::tls::ClientPool, C>;

/// Lifecycle-preserving client operations for one application step.
pub struct ControlInner<'step, 'd, 'tls, const ID: u8, P, B, A, C = StaticConfig>
where
    'd: 'step,
    P: Protocol,
    B: BackoffPolicy,
    A: EndpointAuthority<'tls>,
    C: ConfigProvider,
{
    inner: pin::Pin<&'step mut Dialer<'d, 'tls, ID, P, B, A, C>>,
}

pub type Control<'step, 'd, const ID: u8, P, B, C = StaticConfig> =
    ControlInner<'step, 'd, 'static, ID, P, B, [u8; 32], C>;

pub type PooledControl<'step, 'd, 'tls, const ID: u8, P, B, C = StaticConfig> =
    ControlInner<'step, 'd, 'tls, ID, P, B, &'tls conn::tls::ClientPool, C>;

impl<'step, 'd, 'tls, const ID: u8, P, B, A, C> ControlInner<'step, 'd, 'tls, ID, P, B, A, C>
where
    'd: 'step,
    P: Protocol,
    B: BackoffPolicy,
    A: EndpointAuthority<'tls>,
    C: ConfigProvider,
{
    pub fn protocol(&self) -> &P {
        self.inner.as_ref().get_ref().protocol()
    }

    pub fn smoothed_rtt(&self, slot: SlotId) -> Option<time::Duration> {
        self.inner.as_ref().get_ref().smoothed_rtt(slot)
    }

    pub fn path_stats(&self, slot: SlotId) -> Option<PathStats> {
        self.inner.as_ref().get_ref().path_stats(slot)
    }

    pub fn try_send_datagram(
        &mut self,
        slot: SlotId,
        data: Vec<u8>,
    ) -> Result<(), crate::errors::SendFailure<Vec<u8>>> {
        self.inner.as_mut().try_send_datagram(slot, data)
    }
}

impl<'d, const ID: u8, P: Protocol, B: BackoffPolicy>
    Dialer<'d, 'static, ID, P, B, [u8; 32], StaticConfig>
{
    pub fn build(
        bind: net::SocketAddr,
        endpoints: Vec<EndpointSpec>,
        client_config: conn::config::Options,
        protocol: P,
        backoff: B,
        config: Config,
        driver: &mut driver::Context<'_, 'd>,
    ) -> io::Result<Self> {
        client_config
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        client_config
            .duplicate_connection()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Self::build_with_config_provider(
            bind,
            endpoints,
            StaticConfig(client_config),
            protocol,
            backoff,
            config,
            driver,
        )
    }
}

impl<'d, const ID: u8, P, B, C> Dialer<'d, 'static, ID, P, B, [u8; 32], C>
where
    P: Protocol,
    B: BackoffPolicy,
    C: ConfigProvider,
{
    pub fn build_with_config_provider(
        bind: net::SocketAddr,
        endpoints: Vec<EndpointSpec>,
        config_provider: C,
        protocol: P,
        backoff: B,
        config: Config,
        driver: &mut driver::Context<'_, 'd>,
    ) -> io::Result<Self> {
        let endpoints = endpoints
            .into_iter()
            .map(|endpoint| EndpointSlot {
                addr: endpoint.addr,
                authority: endpoint.pubkey,
                handle: None,
                attempt: 0,
            })
            .collect();
        Self::build_inner(
            bind,
            endpoints,
            config_provider,
            protocol,
            backoff,
            config,
            driver,
        )
    }
}

impl<'d, 'tls, const ID: u8, P: Protocol, B: BackoffPolicy>
    Dialer<'d, 'tls, ID, P, B, &'tls conn::tls::ClientPool, StaticConfig>
{
    pub fn build_pooled(
        bind: net::SocketAddr,
        endpoints: Vec<PooledEndpointSpec<'tls>>,
        client_config: conn::config::Options,
        protocol: P,
        backoff: B,
        config: Config,
        driver: &mut driver::Context<'_, 'd>,
    ) -> io::Result<Self> {
        client_config
            .validate_pooled_client()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        client_config
            .duplicate_connection()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Self::build_pooled_with_config_provider(
            bind,
            endpoints,
            StaticConfig(client_config),
            protocol,
            backoff,
            config,
            driver,
        )
    }
}

impl<'d, 'tls, const ID: u8, P, B, C> Dialer<'d, 'tls, ID, P, B, &'tls conn::tls::ClientPool, C>
where
    P: Protocol,
    B: BackoffPolicy,
    C: ConfigProvider,
{
    pub fn build_pooled_with_config_provider(
        bind: net::SocketAddr,
        endpoints: Vec<PooledEndpointSpec<'tls>>,
        config_provider: C,
        protocol: P,
        backoff: B,
        config: Config,
        driver: &mut driver::Context<'_, 'd>,
    ) -> io::Result<Self> {
        let endpoints = endpoints
            .into_iter()
            .map(|endpoint| EndpointSlot {
                addr: endpoint.addr,
                authority: endpoint.pool,
                handle: None,
                attempt: 0,
            })
            .collect();
        Self::build_inner(
            bind,
            endpoints,
            config_provider,
            protocol,
            backoff,
            config,
            driver,
        )
    }
}

impl<'d, 'tls, const ID: u8, P, B, A, C> Dialer<'d, 'tls, ID, P, B, A, C>
where
    P: Protocol,
    B: BackoffPolicy,
    A: EndpointAuthority<'tls>,
    C: ConfigProvider,
{
    fn build_inner(
        bind: net::SocketAddr,
        endpoints: Vec<EndpointSlot<A>>,
        config_provider: C,
        protocol: P,
        backoff: B,
        config: Config,
        driver: &mut driver::Context<'_, 'd>,
    ) -> io::Result<Self> {
        let endpoint_config = config.endpoint.validate()?;
        if config.event_budget == 0
            || config.event_budget > crate::mux::MAX_OUTGOING_CAPACITY
            || config.retry_budget == 0
            || config.retry_budget > crate::mux::MAX_OUTGOING_CAPACITY
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid QUIC client work budget",
            ));
        }
        let capacity = endpoints.len();
        if endpoint_config.max_conns != capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC endpoint capacity mismatch",
            ));
        }
        let mut seed = [0; 8];
        ring::rand::SystemRandom::new()
            .fill(&mut seed)
            .map_err(|_| io::Error::other("QUIC DCID entropy unavailable"))?;
        let bridge = Bridge {
            protocol,
            handle_to_slot: vec![None; capacity].into_boxed_slice(),
            pending_close: slot::Fifo::with_capacity(capacity),
            pending_established: slot::Fifo::with_capacity(capacity),
        };
        let inner =
            endpoint::PooledSocket::build_client_pooled(bind, bridge, endpoint_config, driver)?;
        let now = time::Instant::now();
        let mut retries = heap::Min::with_capacity(capacity);
        for index in 0..capacity {
            retries
                .insert(index, now)
                .map_err(|_| io::Error::other("QUIC retry scheduler capacity mismatch"))?;
        }
        Ok(Self {
            inner,
            endpoints,
            retries,
            backoff,
            config_provider,
            event_budget: config.event_budget,
            retry_budget: config.retry_budget,
            dcid_seed: u64::from_ne_bytes(seed),
        })
    }

    pub fn protocol(&self) -> &P {
        &self.inner.handler().protocol
    }

    pub(crate) fn protocol_mut(self: pin::Pin<&mut Self>) -> &mut P {
        &mut self.project().inner.handler_mut().protocol
    }

    pub fn local_addr(&self) -> net::SocketAddr {
        self.inner.local_addr()
    }

    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_connected(&self, slot: SlotId) -> bool {
        self.endpoints
            .get(slot.index() as usize)
            .map(|ep| ep.handle.is_some())
            .unwrap_or(false)
    }

    /// Smoothed RTT of the QUIC connection on `slot`, if connected.
    pub fn smoothed_rtt(&self, slot: SlotId) -> Option<time::Duration> {
        let handle = self.endpoints.get(slot.index() as usize)?.handle?;
        self.inner.conn(handle)?.status().smoothed_rtt()
    }

    /// Current path statistics for the QUIC connection on `slot`, if connected.
    pub fn path_stats(&self, slot: SlotId) -> Option<PathStats> {
        let handle = self.endpoints.get(slot.index() as usize)?.handle?;
        let conn = self.inner.conn(handle)?;
        Some(PathStats {
            srtt: conn.status().smoothed_rtt(),
            min_rtt: conn.status().min_rtt(),
            cwnd: conn.status().congestion_window(),
            bytes_in_flight: conn.status().bytes_in_flight(),
        })
    }

    pub fn try_send_datagram(
        self: pin::Pin<&mut Self>,
        slot: SlotId,
        data: Vec<u8>,
    ) -> Result<(), crate::errors::SendFailure<Vec<u8>>> {
        let mut this = self.project();
        let index = slot.index() as usize;
        let Some(ep) = this.endpoints.get_mut(index) else {
            return Err(crate::errors::SendFailure::Closed(data));
        };
        let Some(handle) = ep.handle else {
            return Err(crate::errors::SendFailure::Closed(data));
        };
        match this.inner.as_mut().try_send_datagram(handle, data) {
            Ok(()) => Ok(()),
            Err(crate::errors::SendFailure::Closed(data)) => {
                this.inner.as_mut().close(handle);
                this.inner.as_mut().handler_mut().unbind(handle);
                ep.handle = None;
                ep.attempt = ep.attempt.saturating_add(1);
                let retry_at = this.backoff.next_retry_at(ep.attempt, time::Instant::now());
                this.retries.remove(index);
                let _ = this.retries.insert(index, retry_at);
                Err(crate::errors::SendFailure::Closed(data))
            }
            Err(error) => Err(error),
        }
    }

    fn try_connect(self: pin::Pin<&mut Self>, slot: SlotId) -> bool {
        let mut this = self.project();
        let index = slot.index() as usize;
        let (addr, authority) = match this.endpoints.get(index) {
            Some(endpoint) if endpoint.handle.is_none() => (endpoint.addr, endpoint.authority),
            None => return false,
            Some(_) => return false,
        };
        *this.dcid_seed = this.dcid_seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let Ok(dcid) = packet::ConnectionId::try_from(this.dcid_seed.to_be_bytes()) else {
            return false;
        };
        let Some(config) = this.config_provider.config(slot) else {
            if let Some(endpoint) = this.endpoints.get_mut(index) {
                endpoint.attempt = endpoint.attempt.saturating_add(1);
                let retry_at = this
                    .backoff
                    .next_retry_at(endpoint.attempt, time::Instant::now());
                this.retries.remove(index);
                let _ = this.retries.insert(index, retry_at);
            }
            return false;
        };
        let connection = authority.connect(this.inner.as_mut(), addr, config, dcid);
        let Ok(handle) = connection else {
            if let Some(endpoint) = this.endpoints.get_mut(index) {
                endpoint.attempt = endpoint.attempt.saturating_add(1);
                let retry_at = this
                    .backoff
                    .next_retry_at(endpoint.attempt, time::Instant::now());
                this.retries.remove(index);
                let _ = this.retries.insert(index, retry_at);
            }
            return false;
        };
        if this.inner.as_mut().handler_mut().bind(handle, slot) {
            if let Some(endpoint) = this.endpoints.get_mut(index) {
                endpoint.handle = Some(handle);
            }
            return true;
        }
        this.inner.as_mut().close(handle);
        if let Some(endpoint) = this.endpoints.get_mut(index) {
            endpoint.attempt = endpoint.attempt.saturating_add(1);
            let retry_at = this
                .backoff
                .next_retry_at(endpoint.attempt, time::Instant::now());
            this.retries.remove(index);
            let _ = this.retries.insert(index, retry_at);
        }
        false
    }
}
