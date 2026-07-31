use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::{Duration, Instant};

use dope::DriverContext;
use dope::manifold::Manifold;
use o3::collections::IndexedMinHeap;
use o3::collections::SlotQueue;
use pin_project::pin_project;
use ring::rand::{SecureRandom, SystemRandom};

use crate::TrySendError;
use crate::conn::{self, Conn, ConnHandle};
use crate::endpoint::{self, Endpoint};
use crate::mux::Handler;
use dope::runtime::dispatcher::Idle;
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

pub trait ClientConfigProvider: 'static {
    fn config(&mut self, slot: SlotId) -> Option<conn::Config>;
}

pub struct StaticClientConfig(conn::Config);

impl ClientConfigProvider for StaticClientConfig {
    fn config(&mut self, _slot: SlotId) -> Option<conn::Config> {
        self.0.duplicate_connection().ok()
    }
}

#[derive(Clone)]
pub struct EndpointSpec {
    pub addr: SocketAddr,
    pub pubkey: [u8; 32],
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

struct EndpointSlot {
    addr: SocketAddr,
    pubkey: [u8; 32],
    handle: Option<ConnHandle>,
    attempt: u32,
}

#[derive(Clone, Copy)]
struct Binding {
    handle: ConnHandle,
    slot: SlotId,
}

struct Bridge<P: Protocol> {
    protocol: P,
    handle_to_slot: Box<[Option<Binding>]>,
    pending_close: SlotQueue<Binding>,
    pending_established: SlotQueue<Binding>,
}

impl<P: Protocol> Bridge<P> {
    fn lookup_slot(&self, handle: ConnHandle) -> Option<SlotId> {
        self.handle_to_slot
            .get(handle.index() as usize)
            .copied()
            .flatten()
            .filter(|binding| binding.handle == handle)
            .map(|binding| binding.slot)
    }

    fn bind(&mut self, handle: ConnHandle, slot: SlotId) -> bool {
        let Some(binding) = self.handle_to_slot.get_mut(handle.index() as usize) else {
            return false;
        };
        if binding.is_some() {
            return false;
        }
        *binding = Some(Binding { handle, slot });
        true
    }

    fn unbind(&mut self, handle: ConnHandle) -> Option<SlotId> {
        let binding = self.handle_to_slot.get_mut(handle.index() as usize)?;
        if !binding.is_some_and(|binding| binding.handle == handle) {
            return None;
        }
        binding.take().map(|binding| binding.slot)
    }
}

impl<P: Protocol> Handler for Bridge<P> {
    fn established(&mut self, _conn: &mut Conn, handle: ConnHandle) {
        if let Some(slot) = self.lookup_slot(handle) {
            let binding = Binding { handle, slot };
            if let Some(entry) = self.pending_established.vacant_entry(slot.index() as usize) {
                entry.push_back(binding);
            }
            self.protocol.connect(slot);
        }
    }

    fn datagram(&mut self, _conn: &mut Conn, handle: ConnHandle, data: Vec<u8>) {
        if let Some(slot) = self.lookup_slot(handle) {
            self.protocol.datagram(slot, data);
        }
    }

    fn close(&mut self, handle: ConnHandle) {
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
pub struct Client<
    'd,
    const ID: u8,
    P: Protocol,
    B: BackoffPolicy,
    C: ClientConfigProvider = StaticClientConfig,
> {
    #[pin]
    inner: Endpoint<'d, ID, Bridge<P>>,
    endpoints: Vec<EndpointSlot>,
    retries: IndexedMinHeap<Instant>,
    backoff: B,
    config_provider: C,
    event_budget: usize,
    retry_budget: usize,
    dcid_seed: u64,
}

impl<'d, const ID: u8, P: Protocol, B: BackoffPolicy> Client<'d, ID, P, B, StaticClientConfig> {
    pub fn build(
        bind: SocketAddr,
        endpoints: Vec<EndpointSpec>,
        client_config: conn::Config,
        protocol: P,
        backoff: B,
        config: Config,
        driver: &mut DriverContext<'_, 'd>,
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
            StaticClientConfig(client_config),
            protocol,
            backoff,
            config,
            driver,
        )
    }
}

impl<'d, const ID: u8, P, B, C> Client<'d, ID, P, B, C>
where
    P: Protocol,
    B: BackoffPolicy,
    C: ClientConfigProvider,
{
    pub fn build_with_config_provider(
        bind: SocketAddr,
        endpoints: Vec<EndpointSpec>,
        config_provider: C,
        protocol: P,
        backoff: B,
        config: Config,
        driver: &mut DriverContext<'_, 'd>,
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
            pending_close: SlotQueue::with_capacity(capacity),
            pending_established: SlotQueue::with_capacity(capacity),
        };
        let inner = Endpoint::build_client(bind, bridge, endpoint_config, driver)?;
        let now = Instant::now();
        let mut retries = IndexedMinHeap::with_capacity(capacity);
        for index in 0..capacity {
            retries
                .insert(index, now)
                .map_err(|_| Error::other("QUIC retry scheduler capacity mismatch"))?;
        }
        let endpoints = endpoints
            .into_iter()
            .map(|e| EndpointSlot {
                addr: e.addr,
                pubkey: e.pubkey,
                handle: None,
                attempt: 0,
            })
            .collect();
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

    pub fn protocol_mut(self: Pin<&mut Self>) -> &mut P {
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
        self.inner.conn(handle)?.smoothed_rtt()
    }

    /// Current path statistics for the QUIC connection on `slot`, if connected.
    pub fn path_stats(&self, slot: SlotId) -> Option<PathStats> {
        let handle = self.endpoints.get(slot.index() as usize)?.handle?;
        let conn = self.inner.conn(handle)?;
        Some(PathStats {
            srtt: conn.smoothed_rtt(),
            min_rtt: conn.min_rtt(),
            cwnd: conn.cwnd(),
            bytes_in_flight: conn.bytes_in_flight(),
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
        let (addr, pubkey) = match this.endpoints.get(index) {
            Some(endpoint) if endpoint.handle.is_none() => (endpoint.addr, endpoint.pubkey),
            None => return false,
            Some(_) => return false,
        };
        *this.dcid_seed = this.dcid_seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let dcid = this.dcid_seed.to_be_bytes().to_vec();
        let Some(config) = this.config_provider.config(slot) else {
            if let Some(endpoint) = this.endpoints.get_mut(index) {
                endpoint.attempt = endpoint.attempt.saturating_add(1);
                let retry_at = this.backoff.next_retry_at(endpoint.attempt, Instant::now());
                this.retries.remove(index);
                let _ = this.retries.insert(index, retry_at);
            }
            return false;
        };
        let Ok(handle) = this
            .inner
            .as_mut()
            .connect_with_config(addr, pubkey, config, dcid)
        else {
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

impl<'d, const ID: u8, P, B, C> Manifold<'d> for Client<'d, ID, P, B, C>
where
    P: Protocol,
    B: BackoffPolicy,
    C: ClientConfigProvider,
{
    const ID: u8 = ID;

    fn dispatch(mut self: Pin<&mut Self>, ev: dope::Event<'d>, driver: &mut DriverContext<'_, 'd>) {
        self.as_mut().project().inner.dispatch(ev, driver);
    }

    fn pre_park(mut self: Pin<&mut Self>, driver: &mut DriverContext<'_, 'd>) {
        let mut this_client = self.as_mut();
        this_client.as_mut().project().inner.flush_pending(driver);
        let now = Instant::now();
        {
            let mut this = this_client.as_mut().project();
            let mut remaining = *this.event_budget;
            while remaining != 0 {
                let Some(binding) = this.inner.as_mut().handler_mut().pending_close.pop_front()
                else {
                    break;
                };
                remaining -= 1;
                let index = binding.slot.index() as usize;
                if let Some(endpoint) = this.endpoints.get_mut(index)
                    && endpoint.handle == Some(binding.handle)
                {
                    endpoint.handle = None;
                    endpoint.attempt = endpoint.attempt.saturating_add(1);
                    let retry_at = this.backoff.next_retry_at(endpoint.attempt, now);
                    this.retries.remove(index);
                    let _ = this.retries.insert(index, retry_at);
                }
            }
            while remaining != 0 {
                let Some(binding) = this
                    .inner
                    .as_mut()
                    .handler_mut()
                    .pending_established
                    .pop_front()
                else {
                    break;
                };
                remaining -= 1;
                if let Some(endpoint) = this.endpoints.get_mut(binding.slot.index() as usize)
                    && endpoint.handle == Some(binding.handle)
                {
                    endpoint.attempt = 0;
                }
            }
        }
        let mut connected = false;
        let mut remaining = *this_client.as_ref().project_ref().retry_budget;
        while remaining != 0 {
            let due = {
                let this = this_client.as_mut().project();
                match this.retries.peek() {
                    Some((_, retry_at)) if *retry_at <= now => this.retries.pop().map(|(i, _)| i),
                    _ => None,
                }
            };
            let Some(index) = due else { break };
            remaining -= 1;
            connected |= this_client
                .as_mut()
                .try_connect(SlotId::from_index(index as u32));
        }
        if connected {
            this_client.project().inner.flush_pending(driver);
        }
    }

    fn idle(self: Pin<&Self>) -> Idle {
        let client = self.as_ref();
        let this = client.project_ref();
        if !this.inner.handler().pending_close.is_empty()
            || !this.inner.handler().pending_established.is_empty()
        {
            return Idle::Busy;
        }
        match this.inner.get_ref().idle() {
            Idle::Busy => Idle::Busy,
            Idle::Park(deadline) => {
                let retry = this.retries.peek().map(|(_, retry)| *retry);
                Idle::Park(match (deadline, retry) {
                    (Some(left), Some(right)) => Some(left.min(right)),
                    (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
                    (None, None) => None,
                })
            }
        }
    }
}
