use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Instant;

use dope::Driver;
use dope::manifold::Manifold;
use pin_project::pin_project;

use crate::conn::{Conn, ConnConfig, ConnHandle, DatagramError};
use crate::endpoint::Endpoint;
use crate::mux::Handler;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SlotId(u32);

impl SlotId {
    pub fn from_idx(idx: u32) -> Self {
        Self(idx)
    }

    pub fn idx(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    NotConnected,
    QueueFull,
    TooLarge,
    Unsupported,
}

pub trait BackoffPolicy: 'static {
    fn next_retry_at(&self, attempt: u32, now: Instant) -> Instant;
}

pub trait Protocol: 'static {
    fn on_connect(&mut self, slot: SlotId);
    fn on_datagram(&mut self, slot: SlotId, data: Vec<u8>);
    fn on_close(&mut self, slot: SlotId);
}

#[derive(Clone)]
pub struct EndpointSpec {
    pub addr: SocketAddr,
    pub pubkey: [u8; 32],
}

struct EndpointSlot {
    addr: SocketAddr,
    pubkey: [u8; 32],
    handle: Option<ConnHandle>,
    attempt: u32,
    next_retry_at: Option<Instant>,
}

struct Bridge<P: Protocol> {
    protocol: P,
    handle_to_slot: Vec<(ConnHandle, SlotId)>,
    pending_close: Vec<SlotId>,
    pending_established: Vec<SlotId>,
}

impl<P: Protocol> Bridge<P> {
    fn lookup_slot(&self, handle: ConnHandle) -> Option<SlotId> {
        self.handle_to_slot
            .iter()
            .find(|(h, _)| *h == handle)
            .map(|(_, s)| *s)
    }
}

impl<P: Protocol> Handler for Bridge<P> {
    fn on_established(&mut self, _conn: &mut Conn, handle: ConnHandle) {
        if let Some(slot) = self.lookup_slot(handle) {
            self.pending_established.push(slot);
            self.protocol.on_connect(slot);
        }
    }

    fn on_datagram(&mut self, _conn: &mut Conn, handle: ConnHandle, data: Vec<u8>) {
        if let Some(slot) = self.lookup_slot(handle) {
            self.protocol.on_datagram(slot, data);
        }
    }

    fn on_close(&mut self, handle: ConnHandle) {
        if let Some(slot) = self.lookup_slot(handle) {
            self.protocol.on_close(slot);
            self.pending_close.push(slot);
            self.handle_to_slot.retain(|(h, _)| *h != handle);
        }
    }
}

#[pin_project]
pub struct Client<const ID: u8, P: Protocol, B: BackoffPolicy> {
    #[pin]
    inner: Endpoint<0, Bridge<P>>,
    endpoints: Vec<EndpointSlot>,
    backoff: B,
    client_config: ConnConfig,
    dcid_seed: u64,
}

impl<const ID: u8, P: Protocol, B: BackoffPolicy> Client<ID, P, B> {
    pub fn build(
        bind: SocketAddr,
        endpoints: Vec<EndpointSpec>,
        client_config: ConnConfig,
        protocol: P,
        backoff: B,
        dcid_seed_initial: u64,
        driver: &mut Driver,
    ) -> io::Result<Self> {
        let bridge = Bridge {
            protocol,
            handle_to_slot: Vec::with_capacity(endpoints.len()),
            pending_close: Vec::new(),
            pending_established: Vec::new(),
        };
        let inner = Endpoint::build_client(bind, bridge, driver)?;
        let endpoints = endpoints
            .into_iter()
            .map(|e| EndpointSlot {
                addr: e.addr,
                pubkey: e.pubkey,
                handle: None,
                attempt: 0,
                next_retry_at: Some(Instant::now()),
            })
            .collect();
        Ok(Self {
            inner,
            endpoints,
            backoff,
            client_config,
            dcid_seed: dcid_seed_initial,
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
            .get(slot.0 as usize)
            .map(|ep| ep.handle.is_some())
            .unwrap_or(false)
    }

    pub fn send_datagram(
        self: Pin<&mut Self>,
        slot: SlotId,
        data: Vec<u8>,
    ) -> Result<(), SendError> {
        let mut this = self.project();
        let ep = this
            .endpoints
            .get_mut(slot.0 as usize)
            .ok_or(SendError::NotConnected)?;
        let handle = ep.handle.ok_or(SendError::NotConnected)?;
        let send = this.inner.as_mut().send_datagram(handle, data);
        match send {
            Ok(()) => Ok(()),
            Err(DatagramError::Closed) => {
                ep.handle = None;
                ep.attempt = ep.attempt.saturating_add(1);
                ep.next_retry_at = Some(this.backoff.next_retry_at(ep.attempt, Instant::now()));
                this.inner
                    .handler_mut()
                    .handle_to_slot
                    .retain(|(h, _)| *h != handle);
                Err(SendError::NotConnected)
            }
            Err(DatagramError::QueueFull) => Err(SendError::QueueFull),
            Err(DatagramError::TooLarge) => Err(SendError::TooLarge),
            Err(DatagramError::PeerDoesNotSupport) => Err(SendError::Unsupported),
        }
    }

    fn try_connect(self: Pin<&mut Self>, slot: SlotId) {
        let mut this = self.project();
        let idx = slot.0 as usize;
        let (addr, pubkey) = match this.endpoints.get(idx) {
            Some(e) => (e.addr, e.pubkey),
            None => return,
        };
        *this.dcid_seed = this.dcid_seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let dcid = this.dcid_seed.to_be_bytes().to_vec();
        let config = this.client_config.clone();
        let handle = this
            .inner
            .as_mut()
            .connect_with_config(addr, pubkey, config, dcid);
        if let Some(ep) = this.endpoints.get_mut(idx) {
            ep.handle = Some(handle);
            ep.next_retry_at = None;
        }
        this.inner.handler_mut().handle_to_slot.push((handle, slot));
    }
}

impl<const ID: u8, P: Protocol, B: BackoffPolicy> Manifold for Client<ID, P, B> {
    const ID: u8 = ID;

    fn dispatch(self: Pin<&mut Self>, ev: dope::Event, driver: &mut Driver) {
        self.project().inner.dispatch(ev, driver);
    }

    fn pre_park(mut self: Pin<&mut Self>, driver: &mut Driver) {
        let now = Instant::now();
        let due: Vec<usize> = {
            let mut this = self.as_mut().project();

            let established =
                std::mem::take(&mut this.inner.as_mut().handler_mut().pending_established);
            for slot in established {
                if let Some(ep) = this.endpoints.get_mut(slot.0 as usize) {
                    ep.attempt = 0;
                }
            }

            let closed = std::mem::take(&mut this.inner.as_mut().handler_mut().pending_close);
            for slot in closed {
                if let Some(ep) = this.endpoints.get_mut(slot.0 as usize) {
                    ep.handle = None;
                    ep.attempt = ep.attempt.saturating_add(1);
                    ep.next_retry_at = Some(this.backoff.next_retry_at(ep.attempt, now));
                }
            }

            this.endpoints
                .iter()
                .enumerate()
                .filter_map(|(idx, ep)| match (ep.handle, ep.next_retry_at) {
                    (None, Some(t)) if t <= now => Some(idx),
                    _ => None,
                })
                .collect()
        };
        for idx in due {
            self.as_mut().try_connect(SlotId(idx as u32));
        }
        self.project().inner.pre_park(driver);
    }

    fn idle(self: Pin<&Self>) -> dope::Idle {
        let this = self.project_ref();
        if !this.inner.handler().pending_close.is_empty()
            || !this.inner.handler().pending_established.is_empty()
        {
            return dope::Idle::Busy;
        }
        this.inner.idle()
    }
}
