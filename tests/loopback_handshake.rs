pub mod support;

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

use dope::runtime::Executor;
use dope::{Completion as _, DriverContext, driver};
use dope_quic::{Conn, ConnHandle, Endpoint, Handler, endpoint, transport_params};

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];
const MAX_TICKS: usize = 100;
const TICK_PARK: Duration = Duration::from_millis(5);

const ENDPOINT: endpoint::Config = endpoint::Config {
    max_conns: 1,
    outgoing_capacity: 64,
    outgoing_bytes_capacity: 1 << 20,
    packet_buffer_slots: 64,
    packet_buffer_bytes: u16::MAX as u32,
    completion_budget: 64,
    flush_budget: 64,
};

#[derive(Default)]
struct Events {
    established: Vec<ConnHandle>,
    datagrams: Vec<(ConnHandle, Vec<u8>)>,
}

#[derive(Clone, Default)]
struct CapturingHandler {
    events: Rc<RefCell<Events>>,
}

impl Handler for CapturingHandler {
    fn established(&mut self, _conn: &mut Conn, h: ConnHandle) {
        self.events.borrow_mut().established.push(h);
    }
    fn datagram(&mut self, _conn: &mut Conn, h: ConnHandle, data: Vec<u8>) {
        self.events.borrow_mut().datagrams.push((h, data.to_vec()));
    }
}

fn drive_both<'c, 's>(
    mut client: std::pin::Pin<&mut Endpoint<'c, 0, CapturingHandler>>,
    client_drv: &mut DriverContext<'_, 'c>,
    mut server: std::pin::Pin<&mut Endpoint<'s, 0, CapturingHandler>>,
    server_drv: &mut DriverContext<'_, 's>,
    until: impl Fn() -> bool,
) -> bool {
    for _ in 0..MAX_TICKS {
        client.as_mut().drive(client_drv);
        let _ = client_drv.wait(Some(TICK_PARK));
        server.as_mut().drive(server_drv);
        let _ = server_drv.wait(Some(TICK_PARK));

        if until() {
            return true;
        }
    }
    false
}

#[test]
fn quic_datagram_handshake_completes_on_loopback() {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();

    let user_tp = transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(65535),
        ..transport_params::Params::default()
    };

    let server_exec = Executor::new(driver::Config::for_quic_udp(64, 2048)).unwrap();
    let client_exec = Executor::new(driver::Config::for_quic_udp(64, 2048)).unwrap();
    server_exec.enter(|mut server_sess| {
        client_exec.enter(|mut client_sess| {
            let mut server_drv = server_sess.driver_access();
            let mut client_drv = client_sess.driver_access();

            let server_handler = CapturingHandler::default();
            let server_events = server_handler.events.clone();
            let mut server = std::pin::pin!(
                Endpoint::build_server(
                    "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                    signing,
                    user_tp.clone(),
                    server_handler,
                    ENDPOINT,
                    &mut server_drv,
                )
                .unwrap()
            );
            let server_addr = server.local_addr();

            let client_handler = CapturingHandler::default();
            let client_events = client_handler.events.clone();
            let mut client = std::pin::pin!(
                Endpoint::build_client(
                    "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                    client_handler,
                    ENDPOINT,
                    &mut client_drv,
                )
                .unwrap()
            );

            let _client_handle = client
                .as_mut()
                .connect(server_addr, server_pubkey, user_tp, CID.to_vec())
                .unwrap();

            let done = drive_both(
                client.as_mut(),
                &mut client_drv,
                server.as_mut(),
                &mut server_drv,
                || {
                    !client_events.borrow().established.is_empty()
                        && !server_events.borrow().established.is_empty()
                },
            );

            assert!(done, "handshake did not complete within budget");
        });
    });
}
