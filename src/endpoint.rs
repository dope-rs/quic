use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Instant;

use dope::manifold::Manifold;
use dope::manifold::datagram::Socket;
use dope::{Completion as _, Cqe, DriverContext};
use pin_project::pin_project;
use shin::sig::SigningKey;

use crate::ConnectError;
use crate::TrySendError;
use crate::conn::{self, Conn, ConnHandle};
use crate::early_data::SharedEarlyDataReplayCache;
use crate::mux::{self, Mux};
use crate::mux::{MAX_CONNECTIONS, MAX_OUTGOING_BYTES, MAX_OUTGOING_CAPACITY, Outgoing};
use crate::transport_params;
use dope::Event;
use dope::runtime::Idle;
use std::io::Error;
use std::io::ErrorKind;

#[pin_project]
pub struct Endpoint<'d, const ID: u8, H: mux::Handler> {
    #[pin]
    udp: Socket<'d, ID>,
    mux: Mux<H>,
    packet_buffer_bytes: u32,
    completion_budget: usize,
    flush_budget: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub max_conns: usize,
    pub outgoing_capacity: usize,
    pub outgoing_bytes_capacity: usize,
    pub packet_buffer_slots: u32,
    pub packet_buffer_bytes: u32,
    pub completion_budget: usize,
    pub flush_budget: usize,
}

struct DriverCompletion(Cqe);

impl DriverCompletion {
    /// Decodes one completion yielded by its paired driver.
    fn decode(self) -> Option<Event> {
        unsafe { Event::from_cqe(self.0) }.ok()
    }
}

impl Config {
    pub(crate) fn validate(self) -> io::Result<Self> {
        if self.max_conns == 0
            || self.outgoing_capacity == 0
            || self.outgoing_bytes_capacity < 1200
            || self.packet_buffer_slots == 0
            || self.packet_buffer_bytes < 1200
            || self.completion_budget == 0
            || self.flush_budget == 0
            || self.max_conns > MAX_CONNECTIONS
            || self.outgoing_capacity > MAX_OUTGOING_CAPACITY
            || self.outgoing_bytes_capacity > MAX_OUTGOING_BYTES
            || self.packet_buffer_slots as usize > MAX_OUTGOING_CAPACITY
            || self.packet_buffer_bytes > u32::from(u16::MAX)
            || self.completion_budget > MAX_OUTGOING_CAPACITY
            || self.flush_budget > MAX_OUTGOING_CAPACITY
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid endpoint capacity",
            ));
        }
        Ok(self)
    }
}

impl<'d, const ID: u8, H: mux::Handler> Endpoint<'d, ID, H> {
    pub fn build_server(
        bind: SocketAddr,
        signing_key: SigningKey,
        server_tp: transport_params::Params,
        handler: H,
        config: Config,
        driver: &mut DriverContext<'_, 'd>,
    ) -> io::Result<Self> {
        Self::build_server_with_config(bind, signing_key, server_tp.into(), handler, config, driver)
    }

    pub fn build_server_with_config(
        bind: SocketAddr,
        signing_key: SigningKey,
        mut server_config: conn::Config,
        handler: H,
        config: Config,
        driver: &mut DriverContext<'_, 'd>,
    ) -> io::Result<Self> {
        let config = config.validate()?;
        server_config
            .validate()
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
        server_config.max_pmtu = server_config
            .max_pmtu
            .min(u64::from(config.packet_buffer_bytes));
        let udp = Socket::bind(bind, driver)?;
        if server_config.accept_early_data && server_config.early_data_replay_cache.is_none() {
            server_config.early_data_replay_cache = Some(SharedEarlyDataReplayCache::new());
        }
        let mux = Mux::server_with_limits(
            handler,
            signing_key,
            server_config,
            config.max_conns,
            config.outgoing_capacity,
            config.outgoing_bytes_capacity,
        )
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
        Ok(Self {
            udp,
            mux,
            packet_buffer_bytes: config.packet_buffer_bytes,
            completion_budget: config.completion_budget,
            flush_budget: config.flush_budget,
        })
    }

    pub fn build_client(
        bind: SocketAddr,
        handler: H,
        config: Config,
        driver: &mut DriverContext<'_, 'd>,
    ) -> io::Result<Self> {
        let config = config.validate()?;
        let udp = Socket::bind(bind, driver)?;
        let mux = Mux::client_with_limits(
            handler,
            config.max_conns,
            config.outgoing_capacity,
            config.outgoing_bytes_capacity,
        )
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
        Ok(Self {
            udp,
            mux,
            packet_buffer_bytes: config.packet_buffer_bytes,
            completion_budget: config.completion_budget,
            flush_budget: config.flush_budget,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.udp.local_addr()
    }

    pub fn set_gso(self: Pin<&mut Self>, on: bool) {
        self.project().mux.set_gso(on);
    }

    pub fn handler(&self) -> &H {
        self.mux.handler()
    }

    pub fn handler_mut(self: Pin<&mut Self>) -> &mut H {
        self.project().mux.handler_mut()
    }

    pub fn connect(
        self: Pin<&mut Self>,
        peer_addr: SocketAddr,
        server_pubkey: [u8; 32],
        client_tp: transport_params::Params,
        initial_dcid: Vec<u8>,
    ) -> Result<ConnHandle, ConnectError> {
        self.connect_with_config(peer_addr, server_pubkey, client_tp.into(), initial_dcid)
    }

    pub fn connect_with_config(
        self: Pin<&mut Self>,
        peer_addr: SocketAddr,
        server_pubkey: [u8; 32],
        mut client_config: conn::Config,
        initial_dcid: Vec<u8>,
    ) -> Result<ConnHandle, ConnectError> {
        let now = Instant::now();
        client_config.max_pmtu = client_config
            .max_pmtu
            .min(u64::from(self.packet_buffer_bytes))
            .min(crate::pmtud::MAX_PMTU);
        self.project()
            .mux
            .connect(peer_addr, server_pubkey, client_config, initial_dcid, now)
    }

    pub fn conn_mut(self: Pin<&mut Self>, handle: ConnHandle) -> Option<&mut Conn> {
        self.project().mux.conn_mut(handle)
    }

    pub fn try_send_datagram(
        self: Pin<&mut Self>,
        handle: ConnHandle,
        data: Vec<u8>,
    ) -> Result<(), TrySendError<Vec<u8>>> {
        let now = Instant::now();
        self.project().mux.try_send_datagram(handle, data, now)
    }

    pub fn close(self: Pin<&mut Self>, handle: ConnHandle) {
        self.project().mux.close(handle);
    }

    pub fn drive(mut self: Pin<&mut Self>, driver: &mut DriverContext<'_, 'd>) {
        let mut buf = [Cqe::ZERO; 64];
        let mut remaining = self.completion_budget;
        while remaining != 0 {
            let limit = remaining.min(buf.len());
            let n = driver.drain(&mut buf[..limit]);
            if n == 0 {
                break;
            }
            remaining -= n;
            for cqe in &buf[..n] {
                let Some(ev) = DriverCompletion(*cqe).decode() else {
                    continue;
                };
                self.as_mut().dispatch(ev, driver);
            }
        }
        self.flush_pending(driver);
    }

    pub(crate) fn dispatch(
        self: Pin<&mut Self>,
        ev: dope::Event,
        driver: &mut DriverContext<'_, 'd>,
    ) {
        use dope::EventRef;
        let this = self.project();
        match ev.as_ref() {
            EventRef::Recv(token, more, e) => {
                this.udp.dispatch_recv(token, more, *e, this.mux, driver);
            }
            EventRef::Send(token, e) => {
                this.udp.dispatch_send(token, *e, this.mux, driver);
            }
            _ => {}
        }
    }

    pub(crate) fn flush_pending(self: Pin<&mut Self>, driver: &mut DriverContext<'_, 'd>) {
        let mut this = self.project();
        let flushed = flush(this.udp.as_mut(), this.mux, *this.flush_budget);
        let now = Instant::now();
        this.mux.reap_closed(now);
        flush(
            this.udp.as_mut(),
            this.mux,
            this.flush_budget.saturating_sub(flushed),
        );
        this.udp.tick(driver);
    }

    pub(crate) fn idle(&self) -> Idle {
        if self.udp.needs_flush() || self.mux.has_buffered_outgoing() {
            Idle::Busy
        } else {
            Idle::Park(self.mux.next_deadline(Instant::now()))
        }
    }
}

impl<'d, const ID: u8, H: mux::Handler> Manifold<'d> for Endpoint<'d, ID, H> {
    const ID: u8 = ID;

    fn dispatch(mut self: Pin<&mut Self>, ev: dope::Event, driver: &mut DriverContext<'_, 'd>) {
        self.as_mut().dispatch(ev, driver);
    }

    fn pre_park(mut self: Pin<&mut Self>, driver: &mut DriverContext<'_, 'd>) {
        self.as_mut().flush_pending(driver);
    }

    fn idle(self: Pin<&Self>) -> Idle {
        self.as_ref().get_ref().idle()
    }
}

fn flush<'d, const ID: u8, H: mux::Handler>(
    mut sock: Pin<&mut Socket<'d, ID>>,
    mux: &mut Mux<H>,
    budget: usize,
) -> usize {
    let now = Instant::now();
    let mut flushed = 0usize;
    while flushed != budget {
        let Some(item) = mux.pop_outgoing() else {
            break;
        };
        match item {
            Outgoing::Plain(addr, payload) => {
                if let Err(payload) = sock.as_mut().queue_to(payload, addr) {
                    let _ = mux.push_outgoing_front(Outgoing::Plain(addr, payload));
                    break;
                }
            }
            Outgoing::Batch(addr, payload, segments) => {
                if let Err(payload) =
                    sock.as_mut()
                        .queue_segments(payload, segments.as_slice(), addr)
                {
                    let _ = mux.push_outgoing_front(Outgoing::Batch(addr, payload, segments));
                    break;
                }
            }
        }
        flushed += 1;
        mux.refill_outgoing(now);
    }
    flushed
}
