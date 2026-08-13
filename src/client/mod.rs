mod sealed;

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::{Duration, Instant};

use dope::core::driver::Context;
use o3::collections::{heap::Min, queue::slot::Fifo};
use pin_project::pin_project;
use ring::rand::{SecureRandom, SystemRandom};

use crate::TrySendError;
use crate::conn::session::Connection;
use crate::conn::{self, Handle};
use crate::endpoint::{self, PooledEndpoint};
use crate::mux::Handler;
use crate::packet::ConnectionId;
use std::io::Error;
use std::io::ErrorKind;

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
    fn next_retry_at(&self, attempt: u32, now: Instant) -> Instant;
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
    pub addr: SocketAddr,
    pub pubkey: [u8; 32],
}

#[derive(Clone, Copy)]
/// One remote endpoint backed by externally owned, exactly reserved TLS state.
pub struct PooledEndpointSpec<'tls> {
    pub addr: SocketAddr,
    pub pool: &'tls conn::tls::ClientPool,
}

#[doc(hidden)]
pub trait EndpointAuthority<'tls>: Copy + sealed::Authority {
    fn connect<'d, const ID: u8, H: Handler<ID>>(
        self,
        endpoint: Pin<&mut PooledEndpoint<'d, 'tls, ID, H>>,
        addr: SocketAddr,
        config: conn::config::Options,
        dcid: ConnectionId,
    ) -> Result<Handle, crate::ConnectError>;
}

impl sealed::Authority for [u8; 32] {}

impl<'tls> EndpointAuthority<'tls> for [u8; 32] {
    #[inline]
    fn connect<'d, const ID: u8, H: Handler<ID>>(
        self,
        endpoint: Pin<&mut PooledEndpoint<'d, 'tls, ID, H>>,
        addr: SocketAddr,
        config: conn::config::Options,
        dcid: ConnectionId,
    ) -> Result<Handle, crate::ConnectError> {
        endpoint.connect_with_config_id(addr, self, config, dcid)
    }
}

impl sealed::Authority for &conn::tls::ClientPool {}

impl<'tls> EndpointAuthority<'tls> for &'tls conn::tls::ClientPool {
    #[inline]
    fn connect<'d, const ID: u8, H: Handler<ID>>(
        self,
        endpoint: Pin<&mut PooledEndpoint<'d, 'tls, ID, H>>,
        addr: SocketAddr,
        config: conn::config::Options,
        dcid: ConnectionId,
    ) -> Result<Handle, crate::ConnectError> {
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
    pub srtt: Option<Duration>,
    pub min_rtt: Option<Duration>,
    pub cwnd: u64,
    pub bytes_in_flight: u64,
}

struct EndpointSlot<A> {
    addr: SocketAddr,
    authority: A,
    handle: Option<Handle>,
    attempt: u32,
}

#[derive(Clone, Copy)]
struct Binding {
    handle: Handle,
    slot: SlotId,
}

struct Bridge<P: Protocol> {
    protocol: P,
    handle_to_slot: Box<[Option<Binding>]>,
    pending_close: Fifo<Binding>,
    pending_established: Fifo<Binding>,
}

impl<P: Protocol> Bridge<P> {
    fn lookup_slot(&self, handle: Handle) -> Option<SlotId> {
        self.handle_to_slot
            .get(handle.index() as usize)
            .copied()
            .flatten()
            .filter(|binding| binding.handle == handle)
            .map(|binding| binding.slot)
    }

    fn bind(&mut self, handle: Handle, slot: SlotId) -> bool {
        let Some(binding) = self.handle_to_slot.get_mut(handle.index() as usize) else {
            return false;
        };
        if binding.is_some() {
            return false;
        }
        *binding = Some(Binding { handle, slot });
        true
    }

    fn unbind(&mut self, handle: Handle) -> Option<SlotId> {
        let binding = self.handle_to_slot.get_mut(handle.index() as usize)?;
        if !binding.is_some_and(|binding| binding.handle == handle) {
            return None;
        }
        binding.take().map(|binding| binding.slot)
    }
}

impl<const DOMAIN: u8, P: Protocol> Handler<DOMAIN> for Bridge<P> {
    type Connection = ();

    fn create_connection(&mut self, _conn: &mut Connection<DOMAIN>, _handle: Handle) {}

    fn established(
        &mut self,
        _connection: &mut (),
        _conn: &mut Connection<DOMAIN>,
        handle: Handle,
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
        _conn: &mut Connection<DOMAIN>,
        handle: Handle,
        data: Vec<u8>,
    ) {
        if let Some(slot) = self.lookup_slot(handle) {
            self.protocol.datagram(slot, data);
        }
    }

    fn close(&mut self, _connection: (), handle: Handle) {
        if let Some(slot) = self.unbind(handle) {
            self.protocol.close(slot);
            let binding = Binding { handle, slot };
            if let Some(entry) = self.pending_close.vacant_entry(slot.index() as usize) {
                entry.push_back(binding);
            }
        }
    }
}

#[pin_project]
pub struct ClientInner<
    'd,
    'tls,
    const ID: u8,
    P: Protocol,
    B: BackoffPolicy,
    A: EndpointAuthority<'tls>,
    C: ConfigProvider = StaticConfig,
> {
    #[pin]
    inner: PooledEndpoint<'d, 'tls, ID, Bridge<P>>,
    endpoints: Vec<EndpointSlot<A>>,
    retries: Min<Instant>,
    backoff: B,
    config_provider: C,
    event_budget: usize,
    retry_budget: usize,
    dcid_seed: u64,
}

pub type Client<'d, const ID: u8, P, B, C = StaticConfig> =
    ClientInner<'d, 'static, ID, P, B, [u8; 32], C>;

/// High-level client whose active TLS handshakes cannot outlive their pools.
///
/// ```compile_fail
/// use dope_quic::client::{BackoffPolicy, ConfigProvider, PooledClient, Protocol};
///
/// fn erase_pool_lifetime<'d, 'tls, const ID: u8, P, B, C>(
///     client: PooledClient<'d, 'tls, ID, P, B, C>,
/// ) -> PooledClient<'d, 'static, ID, P, B, C>
/// where
///     P: Protocol,
///     B: BackoffPolicy,
///     C: ConfigProvider,
/// {
///     client
/// }
/// ```
pub type PooledClient<'d, 'tls, const ID: u8, P, B, C = StaticConfig> =
    ClientInner<'d, 'tls, ID, P, B, &'tls conn::tls::ClientPool, C>;

/// Lifecycle-preserving client operations for one application step.
pub struct ControlInner<'step, 'd, 'tls, const ID: u8, P, B, A, C = StaticConfig>
where
    'd: 'step,
    P: Protocol,
    B: BackoffPolicy,
    A: EndpointAuthority<'tls>,
    C: ConfigProvider,
{
    inner: Pin<&'step mut ClientInner<'d, 'tls, ID, P, B, A, C>>,
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

    pub fn protocol_control(&mut self) -> <P as ControlProtocol>::Control<'_>
    where
        P: ControlProtocol,
    {
        let protocol = self.inner.as_mut().protocol_mut();
        // SAFETY: this is the exact protocol installed beneath the client and
        // the returned control cannot outlive this exclusive step borrow.
        unsafe { P::control(protocol) }
    }

    pub fn smoothed_rtt(&self, slot: SlotId) -> Option<Duration> {
        self.inner.as_ref().get_ref().smoothed_rtt(slot)
    }

    pub fn path_stats(&self, slot: SlotId) -> Option<PathStats> {
        self.inner.as_ref().get_ref().path_stats(slot)
    }

    pub fn try_send_datagram(
        &mut self,
        slot: SlotId,
        data: Vec<u8>,
    ) -> Result<(), TrySendError<Vec<u8>>> {
        self.inner.as_mut().try_send_datagram(slot, data)
    }
}

/// Restricted coordinate view supplied by a client protocol.
///
/// # Safety
/// `Control` must not expose an operation that moves, replaces, or drops
/// driver-branded retained storage owned by the protocol.
pub unsafe trait ControlProtocol: Protocol {
    type Control<'step>
    where
        Self: 'step;

    /// # Safety
    /// `protocol` must be the protocol installed beneath its live client and
    /// no client lifecycle phase may overlap the returned control.
    unsafe fn control<'step>(protocol: &'step mut Self) -> Self::Control<'step>;
}

impl<'d, const ID: u8, P: Protocol, B: BackoffPolicy>
    ClientInner<'d, 'static, ID, P, B, [u8; 32], StaticConfig>
{
    pub fn build(
        bind: SocketAddr,
        endpoints: Vec<EndpointSpec>,
        client_config: conn::config::Options,
        protocol: P,
        backoff: B,
        config: Config,
        driver: &mut Context<'_, 'd>,
    ) -> io::Result<Self> {
        client_config
            .validate()
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
        client_config
            .duplicate_connection()
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
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

impl<'d, const ID: u8, P, B, C> ClientInner<'d, 'static, ID, P, B, [u8; 32], C>
where
    P: Protocol,
    B: BackoffPolicy,
    C: ConfigProvider,
{
    pub fn build_with_config_provider(
        bind: SocketAddr,
        endpoints: Vec<EndpointSpec>,
        config_provider: C,
        protocol: P,
        backoff: B,
        config: Config,
        driver: &mut Context<'_, 'd>,
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
    ClientInner<'d, 'tls, ID, P, B, &'tls conn::tls::ClientPool, StaticConfig>
{
    pub fn build_pooled(
        bind: SocketAddr,
        endpoints: Vec<PooledEndpointSpec<'tls>>,
        client_config: conn::config::Options,
        protocol: P,
        backoff: B,
        config: Config,
        driver: &mut Context<'_, 'd>,
    ) -> io::Result<Self> {
        client_config
            .validate_pooled_client()
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
        client_config
            .duplicate_connection()
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
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

impl<'d, 'tls, const ID: u8, P, B, C>
    ClientInner<'d, 'tls, ID, P, B, &'tls conn::tls::ClientPool, C>
where
    P: Protocol,
    B: BackoffPolicy,
    C: ConfigProvider,
{
    pub fn build_pooled_with_config_provider(
        bind: SocketAddr,
        endpoints: Vec<PooledEndpointSpec<'tls>>,
        config_provider: C,
        protocol: P,
        backoff: B,
        config: Config,
        driver: &mut Context<'_, 'd>,
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

impl<'d, 'tls, const ID: u8, P, B, A, C> ClientInner<'d, 'tls, ID, P, B, A, C>
where
    P: Protocol,
    B: BackoffPolicy,
    A: EndpointAuthority<'tls>,
    C: ConfigProvider,
{
    fn build_inner(
        bind: SocketAddr,
        endpoints: Vec<EndpointSlot<A>>,
        config_provider: C,
        protocol: P,
        backoff: B,
        config: Config,
        driver: &mut Context<'_, 'd>,
    ) -> io::Result<Self> {
        let endpoint_config = config.endpoint.validate()?;
        if config.event_budget == 0
            || config.event_budget > crate::mux::MAX_OUTGOING_CAPACITY
            || config.retry_budget == 0
            || config.retry_budget > crate::mux::MAX_OUTGOING_CAPACITY
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid QUIC client work budget",
            ));
        }
        let capacity = endpoints.len();
        if endpoint_config.max_conns != capacity {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "QUIC endpoint capacity mismatch",
            ));
        }
        let mut seed = [0; 8];
        SystemRandom::new()
            .fill(&mut seed)
            .map_err(|_| Error::other("QUIC DCID entropy unavailable"))?;
        let bridge = Bridge {
            protocol,
            handle_to_slot: vec![None; capacity].into_boxed_slice(),
            pending_close: Fifo::with_capacity(capacity),
            pending_established: Fifo::with_capacity(capacity),
        };
        let inner = PooledEndpoint::build_client_pooled(bind, bridge, endpoint_config, driver)?;
        let now = Instant::now();
        let mut retries = Min::with_capacity(capacity);
        for index in 0..capacity {
            retries
                .insert(index, now)
                .map_err(|_| Error::other("QUIC retry scheduler capacity mismatch"))?;
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

    pub(crate) fn protocol_mut(self: Pin<&mut Self>) -> &mut P {
        &mut self.project().inner.handler_mut().protocol
    }

    pub fn local_addr(&self) -> SocketAddr {
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
    pub fn smoothed_rtt(&self, slot: SlotId) -> Option<Duration> {
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
        self: Pin<&mut Self>,
        slot: SlotId,
        data: Vec<u8>,
    ) -> Result<(), TrySendError<Vec<u8>>> {
        let mut this = self.project();
        let index = slot.index() as usize;
        let Some(ep) = this.endpoints.get_mut(index) else {
            return Err(TrySendError::Closed(data));
        };
        let Some(handle) = ep.handle else {
            return Err(TrySendError::Closed(data));
        };
        match this.inner.as_mut().try_send_datagram(handle, data) {
            Ok(()) => Ok(()),
            Err(TrySendError::Closed(data)) => {
                this.inner.as_mut().close(handle);
                this.inner.as_mut().handler_mut().unbind(handle);
                ep.handle = None;
                ep.attempt = ep.attempt.saturating_add(1);
                let retry_at = this.backoff.next_retry_at(ep.attempt, Instant::now());
                this.retries.remove(index);
                let _ = this.retries.insert(index, retry_at);
                Err(TrySendError::Closed(data))
            }
            Err(error) => Err(error),
        }
    }

    fn try_connect(self: Pin<&mut Self>, slot: SlotId) -> bool {
        let mut this = self.project();
        let index = slot.index() as usize;
        let (addr, authority) = match this.endpoints.get(index) {
            Some(endpoint) if endpoint.handle.is_none() => (endpoint.addr, endpoint.authority),
            None => return false,
            Some(_) => return false,
        };
        *this.dcid_seed = this.dcid_seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let Ok(dcid) = ConnectionId::try_from(this.dcid_seed.to_be_bytes()) else {
            return false;
        };
        let Some(config) = this.config_provider.config(slot) else {
            if let Some(endpoint) = this.endpoints.get_mut(index) {
                endpoint.attempt = endpoint.attempt.saturating_add(1);
                let retry_at = this.backoff.next_retry_at(endpoint.attempt, Instant::now());
                this.retries.remove(index);
                let _ = this.retries.insert(index, retry_at);
            }
            return false;
        };
        let connection = authority.connect(this.inner.as_mut(), addr, config, dcid);
        let Ok(handle) = connection else {
            if let Some(endpoint) = this.endpoints.get_mut(index) {
                endpoint.attempt = endpoint.attempt.saturating_add(1);
                let retry_at = this.backoff.next_retry_at(endpoint.attempt, Instant::now());
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
            let retry_at = this.backoff.next_retry_at(endpoint.attempt, Instant::now());
            this.retries.remove(index);
            let _ = this.retries.insert(index, retry_at);
        }
        false
    }
}
