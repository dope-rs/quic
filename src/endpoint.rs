use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Instant;

use dope::manifold::Manifold;
use dope::manifold::datagram::Socket;
use dope::{Completion, DriverContext, Event};
use o3::cell::RegionToken;
use pin_project::pin_project;
use shin::crypto::sig::SigningKey;
use shin::crypto::ticket::TicketKeys;
use shin::server::{config::ClientCertVerifier, config::EarlyDataGuard, config::NoGuard};

use crate::ConnectError;
use crate::TrySendError;
use crate::conn::{self, Connection, Handle, ValidatedConfig};
use crate::mux::{self, Mux};
use crate::mux::{MAX_CONNECTIONS, MAX_OUTGOING_BYTES, MAX_OUTGOING_CAPACITY, Outgoing};
use crate::transport_params;
use dope::runtime::dispatcher::Idle;
use std::io::Error;
use std::io::ErrorKind;

#[pin_project]
pub struct Endpoint<
    'd,
    const ID: u8,
    H: mux::Handler,
    P: conn::server::Policy = conn::server::Standard,
> {
    #[pin]
    udp: Socket<'d, ID>,
    mux: Mux<H, P>,
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

impl<'d, const ID: u8, H: mux::Handler> Endpoint<'d, ID, H, conn::server::Standard> {
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
        server_config: conn::Config,
        handler: H,
        config: Config,
        driver: &mut DriverContext<'_, 'd>,
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
}

impl<'d, const ID: u8, H, G> Endpoint<'d, ID, H, conn::server::Standard<G>>
where
    H: mux::Handler,
    G: EarlyDataGuard + 'static,
{
    pub fn build_server_with_early_data_guard(
        bind: SocketAddr,
        signing_key: SigningKey,
        server_tp: transport_params::Params,
        guard: G,
        handler: H,
        config: Config,
        driver: &mut DriverContext<'_, 'd>,
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
        server_config: conn::Config,
        guard: G,
        handler: H,
        config: Config,
        driver: &mut DriverContext<'_, 'd>,
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

impl<'d, const ID: u8, H, V> Endpoint<'d, ID, H, conn::server::Mutual<NoGuard, V>>
where
    H: mux::Handler,
    V: ClientCertVerifier + 'static,
{
    pub fn build_server_mutual(
        bind: SocketAddr,
        signing_key: SigningKey,
        server_config: conn::Config,
        authentication: conn::server::Authentication<V>,
        handler: H,
        config: Config,
        driver: &mut DriverContext<'_, 'd>,
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

impl<'d, const ID: u8, H, G, V> Endpoint<'d, ID, H, conn::server::Mutual<G, V>>
where
    H: mux::Handler,
    G: EarlyDataGuard + 'static,
    V: ClientCertVerifier + 'static,
{
    pub fn build_server_mutual_with_early_data_guard(
        bind: SocketAddr,
        signing_key: SigningKey,
        server_config: conn::Config,
        authentication: conn::server::Authentication<V, G>,
        handler: H,
        config: Config,
        driver: &mut DriverContext<'_, 'd>,
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

impl<'d, const ID: u8, H, P> Endpoint<'d, ID, H, P>
where
    H: mux::Handler,
    P: conn::server::Policy,
{
    pub fn build_server_with_policy(
        bind: SocketAddr,
        signing_key: SigningKey,
        server_config: conn::Config,
        setup: P::Setup,
        handler: H,
        config: Config,
        driver: &mut DriverContext<'_, 'd>,
    ) -> io::Result<Self> {
        let config = config.validate()?;
        let mut server_config = ValidatedConfig::new(server_config)
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
        server_config
            .cap_max_pmtu(u64::from(config.packet_buffer_bytes))
            .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
        let udp = Socket::bind(bind, driver)?;
        let mux = Mux::server_with_validated_policy_and_limits(
            handler,
            signing_key,
            server_config,
            setup,
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
    ) -> Result<Handle, ConnectError> {
        self.connect_with_config(peer_addr, server_pubkey, client_tp.into(), initial_dcid)
    }

    pub fn connect_with_config(
        self: Pin<&mut Self>,
        peer_addr: SocketAddr,
        server_pubkey: [u8; 32],
        mut client_config: conn::Config,
        initial_dcid: Vec<u8>,
    ) -> Result<Handle, ConnectError> {
        let now = Instant::now();
        client_config.max_pmtu = client_config
            .max_pmtu
            .min(u64::from(self.packet_buffer_bytes))
            .min(crate::pmtud::MAX_PMTU);
        self.project()
            .mux
            .connect(peer_addr, server_pubkey, client_config, initial_dcid, now)
    }

    pub fn conn(&self, handle: Handle) -> Option<&Connection> {
        self.mux.conn(handle)
    }

    pub fn conn_mut(self: Pin<&mut Self>, handle: Handle) -> Option<&mut Connection> {
        self.project().mux.conn_mut(handle)
    }

    pub fn try_send_datagram(
        self: Pin<&mut Self>,
        handle: Handle,
        data: Vec<u8>,
    ) -> Result<(), TrySendError<Vec<u8>>> {
        let now = Instant::now();
        self.project().mux.try_send_datagram(handle, data, now)
    }

    pub fn close(self: Pin<&mut Self>, handle: Handle) {
        self.project().mux.close(handle);
    }

    pub fn replace_ticket_keys(self: Pin<&mut Self>, keys: Option<TicketKeys>) -> bool {
        self.project().mux.replace_ticket_keys(keys)
    }

    pub fn drive(mut self: Pin<&mut Self>, driver: &mut DriverContext<'_, 'd>) {
        let mut buf = [const { None }; 64];
        let mut remaining = self.completion_budget;
        while remaining != 0 {
            let limit = remaining.min(buf.len());
            let n = driver.drain(&mut buf[..limit]);
            if n == 0 {
                break;
            }
            remaining -= n;
            for event in &mut buf[..n] {
                let Some(event) = event.take() else {
                    continue;
                };
                self.as_mut().dispatch(event, driver);
            }
        }
        self.flush_pending(driver);
    }

    pub(crate) fn dispatch(
        self: Pin<&mut Self>,
        event: Event<'d>,
        driver: &mut DriverContext<'_, 'd>,
    ) {
        let this = self.project();
        match event {
            Event::Recv(token, more, event) => {
                this.udp.dispatch_recv(token, more, event, this.mux, driver);
            }
            Event::Send(token, event) => {
                this.udp.dispatch_send(token, event, this.mux, driver);
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

impl<'d, const ID: u8, H, P> Manifold<'d> for Endpoint<'d, ID, H, P>
where
    H: mux::Handler,
    P: conn::server::Policy,
{
    const ID: u8 = ID;

    fn dispatch(mut self: Pin<&mut Self>, event: Event<'d>, driver: &mut DriverContext<'_, 'd>) {
        self.as_mut().dispatch(event, driver);
    }

    fn pre_park(mut self: Pin<&mut Self>, driver: &mut DriverContext<'_, 'd>) {
        self.as_mut().flush_pending(driver);
    }

    fn idle(self: Pin<&Self>, _region: &RegionToken<'d>) -> Idle {
        self.as_ref().get_ref().idle()
    }
}

fn flush<'d, const ID: u8, H, P>(
    mut sock: Pin<&mut Socket<'d, ID>>,
    mux: &mut Mux<H, P>,
    budget: usize,
) -> usize
where
    H: mux::Handler,
    P: conn::server::Policy,
{
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
            Outgoing::Batch(addr, payload, segment_size) => {
                if let Err(payload) = sock.as_mut().queue_gso(payload, segment_size, addr) {
                    let _ = mux.push_outgoing_front(Outgoing::Batch(addr, payload, segment_size));
                    break;
                }
            }
        }
        flushed += 1;
        mux.refill_outgoing(now);
    }
    flushed
}
