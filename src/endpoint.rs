use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Instant;

use dope::manifold::Manifold;
use dope::manifold::datagram::{Handler, Socket};
use dope::{Cqe, Drive, Driver};
use pin_project::pin_project;
use shin::sig::SigningKey;

use crate::conn::{Conn, ConnConfig, ConnHandle, DatagramError};
use crate::mux::{self, Mux};
use crate::transport_params;

#[pin_project]
pub struct Endpoint<const ID: u8, H: mux::Handler> {
    #[pin]
    udp: Socket<0>,
    mux: Mux<H>,
}

impl<const ID: u8, H: mux::Handler> Endpoint<ID, H> {
    pub fn build_server(
        bind: SocketAddr,
        signing_key: SigningKey,
        server_tp: transport_params::Params,
        handler: H,
        driver: &mut Driver,
    ) -> io::Result<Self> {
        Self::build_server_with_config(bind, signing_key, server_tp.into(), handler, driver)
    }

    pub fn build_server_with_config(
        bind: SocketAddr,
        signing_key: SigningKey,
        server_config: ConnConfig,
        handler: H,
        driver: &mut Driver,
    ) -> io::Result<Self> {
        let udp = Socket::bind(bind, driver)?;
        let mux = Mux::server(handler, signing_key, server_config);
        Ok(Self { udp, mux })
    }

    pub fn build_client(bind: SocketAddr, handler: H, driver: &mut Driver) -> io::Result<Self> {
        let udp = Socket::bind(bind, driver)?;
        let mux = Mux::client(handler);
        Ok(Self { udp, mux })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.udp.local_addr()
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
    ) -> ConnHandle {
        self.connect_with_config(peer_addr, server_pubkey, client_tp.into(), initial_dcid)
    }

    pub fn connect_with_config(
        self: Pin<&mut Self>,
        peer_addr: SocketAddr,
        server_pubkey: [u8; 32],
        client_config: ConnConfig,
        initial_dcid: Vec<u8>,
    ) -> ConnHandle {
        let now = Instant::now();
        self.project()
            .mux
            .connect(peer_addr, server_pubkey, client_config, initial_dcid, now)
    }

    pub fn conn_mut(self: Pin<&mut Self>, handle: ConnHandle) -> Option<&mut Conn> {
        self.project().mux.conn_mut(handle)
    }

    pub fn send_datagram(
        self: Pin<&mut Self>,
        handle: ConnHandle,
        data: Vec<u8>,
    ) -> Result<(), DatagramError> {
        let now = Instant::now();
        self.project().mux.send_datagram(handle, data, now)
    }

    pub fn close(self: Pin<&mut Self>, handle: ConnHandle) {
        self.project().mux.close(handle);
    }

    pub fn drive(mut self: Pin<&mut Self>, driver: &mut Driver) {
        let mut buf = [Cqe::ZERO; 64];
        loop {
            let n = driver.drain(&mut buf);
            if n == 0 {
                break;
            }
            for cqe in &buf[..n] {
                let Ok(ev) = dope::Event::try_from(*cqe) else {
                    continue;
                };
                self.as_mut().dispatch(ev, driver);
            }
        }
        self.pre_park(driver);
    }
}

impl<const ID: u8, H: mux::Handler> Manifold for Endpoint<ID, H> {
    const ID: u8 = ID;

    fn dispatch(self: Pin<&mut Self>, ev: dope::Event, driver: &mut Driver) {
        use dope::Event;
        let this = self.project();
        match ev {
            Event::Recv(token, more, e) => {
                this.udp.dispatch_recv(token, more, e, driver, this.mux);
            }
            Event::Send(token, e) => {
                this.udp.dispatch_send(token, e, this.mux);
            }
            _ => {}
        }
    }

    fn pre_park(self: Pin<&mut Self>, driver: &mut Driver) {
        let mut this = self.project();
        let now = Instant::now();
        this.mux.reap_closed(now);
        for (addr, payload) in this.mux.pull_outgoing() {
            this.udp.as_mut().queue_to(payload, addr);
        }
        this.udp.tick(driver);
    }

    fn idle(self: Pin<&Self>) -> dope::Idle {
        if self.get_ref().udp.has_pending() {
            dope::Idle::Busy
        } else {
            dope::Idle::Park(None)
        }
    }
}

impl<H: mux::Handler> Handler<0> for Mux<H> {
    fn on_packet(&mut self, addr: SocketAddr, data: &[u8], mut sock: Pin<&mut Socket<0>>) {
        let now = Instant::now();
        let _ = self.on_udp_packet(addr, data, now);
        for (dst, payload) in self.pull_outgoing() {
            sock.as_mut().queue_to(payload, dst);
        }
    }
}
