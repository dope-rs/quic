use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

use dope::{Drive, Driver, DriverCfg, DriverConfig};
use dope_quic::{Conn, ConnHandle, Endpoint, Handler, transport_params};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];
const MAX_TICKS: usize = 100;
const TICK_PARK: Duration = Duration::from_millis(5);

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
    fn on_established(&mut self, _conn: &mut Conn, h: ConnHandle) {
        self.events.borrow_mut().established.push(h);
    }
    fn on_datagram(&mut self, _conn: &mut Conn, h: ConnHandle, data: Vec<u8>) {
        self.events.borrow_mut().datagrams.push((h, data.to_vec()));
    }
}

fn drive_both(
    mut client: std::pin::Pin<&mut Endpoint<0, CapturingHandler>>,
    client_drv: &mut Driver,
    mut server: std::pin::Pin<&mut Endpoint<0, CapturingHandler>>,
    server_drv: &mut Driver,
    until: impl Fn() -> bool,
) -> bool {
    for _ in 0..MAX_TICKS {
        client.as_mut().drive(client_drv);
        let _ = client_drv.park(TICK_PARK);
        server.as_mut().drive(server_drv);
        let _ = server_drv.park(TICK_PARK);

        if until() {
            return true;
        }
    }
    false
}

#[test]
fn quic_datagram_handshake_completes_on_loopback() {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();

    let user_tp = transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(65535),
        ..transport_params::Params::default()
    };

    let mut server_drv = Driver::new(DriverCfg::for_quic_udp(64, 2048)).unwrap();
    let server_handler = CapturingHandler::default();
    let server_events = server_handler.events.clone();
    let mut server = std::pin::pin!(
        Endpoint::build_server(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            signing,
            user_tp.clone(),
            server_handler,
            &mut server_drv,
        )
        .unwrap()
    );
    let server_addr = server.local_addr();

    let mut client_drv = Driver::new(DriverCfg::for_quic_udp(64, 2048)).unwrap();
    let client_handler = CapturingHandler::default();
    let client_events = client_handler.events.clone();
    let mut client = std::pin::pin!(
        Endpoint::build_client(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            client_handler,
            &mut client_drv,
        )
        .unwrap()
    );

    let _client_handle = client
        .as_mut()
        .connect(server_addr, server_pubkey, user_tp, CID.to_vec());

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
}
