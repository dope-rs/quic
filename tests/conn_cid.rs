use std::net::SocketAddr;
use std::time::Instant;

use dope_quic::{Conn, ConnHandle, Handler, Mux, transport_params};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

const CID: [u8; 8] = [0x42; 8];

#[derive(Default)]
struct CountHandler {
    established: usize,
    datagrams: usize,
}
impl Handler for CountHandler {
    fn on_established(&mut self, _conn: &mut Conn, _h: ConnHandle) {
        self.established += 1;
    }
    fn on_datagram(&mut self, _conn: &mut Conn, _h: ConnHandle, _d: Vec<u8>) {
        self.datagrams += 1;
    }
}

fn user_tp() -> dope_quic::ConnConfig {
    transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(65535),
        active_connection_id_limit: 4,
        ..transport_params::Params::default()
    }
    .into()
}

fn signed_keys() -> ([u8; 32], SigningKey) {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let pk = *signing.pubkey();
    (pk, signing)
}

fn relay(src: &mut Mux<CountHandler>, dst: &mut Mux<CountHandler>, src_addr: SocketAddr) {
    let now = Instant::now();
    for (_, payload) in src.pull_outgoing() {
        dst.on_udp_packet(src_addr, &payload, now).expect("recv");
    }
}

#[test]
fn handshake_completes_with_dcid_routing() {
    let (server_pubkey, signing) = signed_keys();
    let mut server = Mux::server(CountHandler::default(), signing, user_tp());
    let mut client = Mux::client(CountHandler::default());
    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();

    let _h = client.connect(
        server_addr,
        server_pubkey,
        user_tp(),
        CID.to_vec(),
        Instant::now(),
    );

    relay(&mut client, &mut server, client_addr);
    relay(&mut server, &mut client, server_addr);
    relay(&mut client, &mut server, client_addr);
    relay(&mut server, &mut client, server_addr);

    assert_eq!(server.handler().established, 1);
    assert_eq!(client.handler().established, 1);
}

#[test]
fn server_demultiplexes_two_clients_at_same_addr_via_dcid() {
    let (server_pubkey, signing) = signed_keys();
    let mut server = Mux::server(CountHandler::default(), signing, user_tp());

    let mut client_a = Mux::client(CountHandler::default());
    let mut client_b = Mux::client(CountHandler::default());

    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let shared_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();

    let _ha = client_a.connect(
        server_addr,
        server_pubkey,
        user_tp(),
        vec![0xAA; 8],
        Instant::now(),
    );
    let _hb = client_b.connect(
        server_addr,
        server_pubkey,
        user_tp(),
        vec![0xBB; 8],
        Instant::now(),
    );

    relay(&mut client_a, &mut server, shared_addr);
    relay(&mut client_b, &mut server, shared_addr);

    let mut conn_count = 0;
    for h in 0..16u32 {
        if server.conn_mut(ConnHandle(h)).is_some() {
            conn_count += 1;
        }
    }
    assert_eq!(conn_count, 2, "server has 2 conns from same addr");
}
