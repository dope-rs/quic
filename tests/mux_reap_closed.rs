use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dope_quic::{Conn, ConnHandle, Handler, Mux, transport_params};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];

#[derive(Default)]
struct Events {
    established: Vec<ConnHandle>,
    datagrams: Vec<(ConnHandle, Vec<u8>)>,
    closed: Vec<ConnHandle>,
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
    fn on_close(&mut self, h: ConnHandle) {
        self.events.borrow_mut().closed.push(h);
    }
}

fn relay_once(
    src: &mut Mux<CapturingHandler>,
    dst: &mut Mux<CapturingHandler>,
    src_addr: SocketAddr,
    now: Instant,
) -> usize {
    let pkts = src.pull_outgoing();
    let n = pkts.len();
    for out in pkts {
        dst.on_udp_packet(src_addr, out.payload(), now).expect("recv");
    }
    n
}

#[allow(clippy::type_complexity)]
fn build_pair(
    idle_ms: u64,
) -> (
    Mux<CapturingHandler>,
    Rc<RefCell<Events>>,
    Mux<CapturingHandler>,
    Rc<RefCell<Events>>,
    [u8; 32],
    transport_params::Params,
) {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();

    let tp = transport_params::Params {
        max_idle_timeout_ms: idle_ms,
        max_datagram_frame_size: Some(65535),
        ..transport_params::Params::default()
    };

    let server_h = CapturingHandler::default();
    let server_events = server_h.events.clone();
    let server = Mux::server(server_h, signing, tp.clone().into());

    let client_h = CapturingHandler::default();
    let client_events = client_h.events.clone();
    let client = Mux::client(client_h);

    (
        server,
        server_events,
        client,
        client_events,
        server_pubkey,
        tp,
    )
}

fn complete_handshake(
    server: &mut Mux<CapturingHandler>,
    client: &mut Mux<CapturingHandler>,
    server_pubkey: [u8; 32],
    tp: transport_params::Params,
    server_addr: SocketAddr,
    client_addr: SocketAddr,
    now: Instant,
) -> ConnHandle {
    let client_handle = client.connect(server_addr, server_pubkey, tp.into(), CID.to_vec(), now);
    relay_once(client, server, client_addr, now);
    relay_once(server, client, server_addr, now);
    relay_once(client, server, client_addr, now);
    client_handle
}

#[test]
fn idle_timeout_fires_on_close_via_reap() {
    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();
    let (mut server, server_events, mut client, client_events, server_pubkey, tp) = build_pair(50);

    let t0 = Instant::now();
    let _ = complete_handshake(
        &mut server,
        &mut client,
        server_pubkey,
        tp,
        server_addr,
        client_addr,
        t0,
    );
    assert_eq!(server_events.borrow().established.len(), 1);
    assert_eq!(client_events.borrow().established.len(), 1);

    let t_past = t0 + Duration::from_millis(150);
    server.reap_closed(t_past);
    client.reap_closed(t_past);

    assert_eq!(
        server_events.borrow().closed.len(),
        1,
        "server must fire on_close exactly once",
    );
    assert_eq!(
        client_events.borrow().closed.len(),
        1,
        "client must fire on_close exactly once",
    );
}

#[test]
fn reap_is_idempotent() {
    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();
    let (mut server, server_events, mut client, _client_events, server_pubkey, tp) = build_pair(50);

    let t0 = Instant::now();
    let _ = complete_handshake(
        &mut server,
        &mut client,
        server_pubkey,
        tp,
        server_addr,
        client_addr,
        t0,
    );

    let t_past = t0 + Duration::from_millis(200);
    server.reap_closed(t_past);
    server.reap_closed(t_past);
    server.reap_closed(t_past + Duration::from_millis(100));

    assert_eq!(
        server_events.borrow().closed.len(),
        1,
        "subsequent reaps must not double-fire on_close",
    );
}

#[test]
fn active_conn_is_not_reaped() {
    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();
    let (mut server, server_events, mut client, _client_events, server_pubkey, tp) =
        build_pair(100);

    let t0 = Instant::now();
    let client_handle = complete_handshake(
        &mut server,
        &mut client,
        server_pubkey,
        tp,
        server_addr,
        client_addr,
        t0,
    );

    let t1 = t0 + Duration::from_millis(80);
    client
        .send_datagram(client_handle, b"keepalive".to_vec(), t1)
        .unwrap();
    relay_once(&mut client, &mut server, client_addr, t1);

    let t2 = t1 + Duration::from_millis(50);
    server.reap_closed(t2);
    client.reap_closed(t2);

    assert!(
        server_events.borrow().closed.is_empty(),
        "active server conn must not be reaped",
    );
}

#[test]
fn explicit_close_then_reap_does_not_double_fire() {
    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();
    let (mut server, _server_events, mut client, client_events, server_pubkey, tp) =
        build_pair(30_000);

    let t0 = Instant::now();
    let client_handle = complete_handshake(
        &mut server,
        &mut client,
        server_pubkey,
        tp,
        server_addr,
        client_addr,
        t0,
    );

    client.close(client_handle);
    assert_eq!(client_events.borrow().closed.len(), 1);

    client.reap_closed(t0);
    assert_eq!(
        client_events.borrow().closed.len(),
        1,
        "reap after explicit close must be a no-op",
    );
}

#[test]
fn peer_connection_close_makes_reap_fire_on_close() {
    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();
    let (mut server, server_events, mut client, _client_events, server_pubkey, tp) =
        build_pair(30_000);

    let t0 = Instant::now();
    let _ = complete_handshake(
        &mut server,
        &mut client,
        server_pubkey,
        tp,
        server_addr,
        client_addr,
        t0,
    );

    let h0 = ConnHandle(0);
    if let Some(conn) = client.conn_mut(h0) {
        conn.close(0, b"client-side close".to_vec());
    }

    client.reap_closed(t0);
    assert_eq!(
        _client_events.borrow().closed.len(),
        1,
        "client must surface its own close exactly once",
    );

    relay_once(&mut client, &mut server, client_addr, t0);

    server.reap_closed(t0);
    assert_eq!(
        server_events.borrow().closed.len(),
        1,
        "peer CONNECTION_CLOSE → reap fires on_close on server",
    );
}

#[test]
fn reap_clears_routing_so_handle_index_recycles() {
    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();
    let (mut server, _server_events, mut client, _client_events, server_pubkey, tp) =
        build_pair(50);

    let t0 = Instant::now();
    let h0 = complete_handshake(
        &mut server,
        &mut client,
        server_pubkey,
        tp.clone(),
        server_addr,
        client_addr,
        t0,
    );

    let t_past = t0 + Duration::from_millis(200);
    client.reap_closed(t_past);

    let mut alt_cid = CID;
    alt_cid[0] = 0x99;
    let h1 = client.connect(
        server_addr,
        server_pubkey,
        tp.into(),
        alt_cid.to_vec(),
        t_past,
    );
    assert_eq!(
        h0, h1,
        "freed slot index must be reused by next connect (free list pop)",
    );
}
