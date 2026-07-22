pub mod support;

use std::net::SocketAddr;
use std::time::Instant;

use dope_quic::{Conn, Handler, Mux, conn, transport_params};

const CID: [u8; 8] = [0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55];

fn drain(from: &mut Conn, into: &mut Conn) {
    let now = Instant::now();
    for pkt in from.send_packets(now) {
        into.recv_packet(&pkt, now).expect("recv");
    }
}

fn cfg(secret: Option<[u8; 32]>) -> conn::Config {
    conn::Config {
        transport_params: transport_params::Params {
            max_idle_timeout_ms: 30_000,
            max_datagram_frame_size: Some(65535),
            active_connection_id_limit: 8,
            ..transport_params::Params::default()
        },
        stateless_reset_secret: secret,
        ..Default::default()
    }
}

fn handshake(server_cfg: conn::Config, client_cfg: conn::Config) -> (Conn, Conn) {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();

    let mut server = Conn::new_server(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        server_cfg,
    )
    .unwrap();
    let mut client =
        Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, client_cfg).unwrap();

    drain(&mut client, &mut server);
    drain(&mut server, &mut client);
    drain(&mut client, &mut server);
    drain(&mut server, &mut client);
    drain(&mut client, &mut server);
    assert!(client.is_established() && server.is_established());
    (server, client)
}

fn peer_cid(conn: &mut Conn) -> Vec<u8> {
    conn.try_send_datagram(vec![0]).unwrap();
    let packet = conn
        .send_packets(Instant::now())
        .into_iter()
        .next()
        .expect("application packet");
    packet[1..1 + CID.len()].to_vec()
}

#[test]
fn server_with_secret_advertises_initial_srt_in_tp() {
    let secret = [0xA5u8; 32];
    let (_server, client) = handshake(cfg(Some(secret)), cfg(None));

    let peer_tp = client
        .peer_transport_params()
        .expect("peer TP after handshake");
    let token = peer_tp
        .stateless_reset_token
        .expect("server should advertise stateless_reset_token");
    assert_ne!(token, [0u8; 16], "token must not be all zeros");
}

#[test]
fn server_without_secret_does_not_advertise_srt() {
    let (_server, client) = handshake(cfg(None), cfg(None));
    let peer_tp = client.peer_transport_params().expect("peer TP");
    assert!(
        peer_tp.stateless_reset_token.is_none(),
        "no secret ⇒ no advertised SRT",
    );
}

#[test]
fn srt_is_stable_across_server_restarts_with_same_secret() {
    let secret = [0xBBu8; 32];
    let (_, client_a) = handshake(cfg(Some(secret)), cfg(None));
    let (_, client_b) = handshake(cfg(Some(secret)), cfg(None));

    let token_a = client_a
        .peer_transport_params()
        .unwrap()
        .stateless_reset_token
        .unwrap();
    let token_b = client_b
        .peer_transport_params()
        .unwrap()
        .stateless_reset_token
        .unwrap();
    assert_eq!(token_a, token_b, "deterministic SRT must survive restart");
}

fn craft_stateless_reset(token: [u8; 16]) -> Vec<u8> {
    let mut wire = vec![0x40u8; 30];
    let tail = wire.len() - 16;
    wire[tail..].copy_from_slice(&token);
    wire
}

#[test]
fn matching_srt_in_tail_closes_conn_and_surfaces_flag() {
    let secret = [0xC1u8; 32];
    let (_server, mut client) = handshake(cfg(Some(secret)), cfg(None));

    let token = client
        .peer_transport_params()
        .and_then(|params| params.stateless_reset_token)
        .expect("peer stateless reset token");

    let reset = craft_stateless_reset(token);
    let now = Instant::now();

    client
        .recv_packet(&reset, now)
        .expect("reset must not surface as ConnError");
    assert!(
        client.was_stateless_reset(),
        "client should mark stateless_reset_received",
    );
    assert!(client.is_closed());
}

#[test]
fn unrecognised_tail_does_not_trigger_reset() {
    let secret = [0xC2u8; 32];
    let (_server, mut client) = handshake(cfg(Some(secret)), cfg(None));

    let mut bogus = [0u8; 16];
    for (i, b) in bogus.iter_mut().enumerate() {
        *b = (i as u8) ^ 0xAA;
    }
    let reset = craft_stateless_reset(bogus);
    let now = Instant::now();

    let _ = client.recv_packet(&reset, now);
    assert!(
        !client.was_stateless_reset(),
        "random tail must not trigger reset",
    );
    assert!(client.is_established(), "conn stays open");
}

#[test]
fn pre_handshake_reset_is_ignored() {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();

    let mut client =
        Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, cfg(None)).unwrap();
    let reset = craft_stateless_reset([0xFFu8; 16]);
    let _ = client.recv_packet(&reset, Instant::now());
    assert!(!client.was_stateless_reset());
}

struct NoopHandler;
impl Handler for NoopHandler {
    fn established(&mut self, _conn: &mut Conn, _h: dope_quic::ConnHandle) {}
    fn datagram(&mut self, _conn: &mut Conn, _h: dope_quic::ConnHandle, _data: Vec<u8>) {}
    fn close(&mut self, _h: dope_quic::ConnHandle) {}
}

fn server_mux(secret: [u8; 32]) -> Mux<NoopHandler> {
    let signing = support::signing_key(0x39);
    let cfg = conn::Config {
        stateless_reset_secret: Some(secret),
        ..Default::default()
    };
    Mux::server(NoopHandler, signing, cfg).unwrap()
}

#[test]
fn server_emits_reset_for_unknown_dcid() {
    let secret = [0xD1u8; 32];
    let mut mux = server_mux(secret);

    let dcid = [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89];
    let mut wire = vec![0x40u8; 30];
    wire[1..9].copy_from_slice(&dcid);

    let from: SocketAddr = "127.0.0.1:55555".parse().unwrap();
    mux.recv(from, &wire, Instant::now()).unwrap();

    let outgoing: Vec<_> = mux.drain_outgoing().collect();
    assert_eq!(outgoing.len(), 1, "exactly one reset should be emitted");
    let (dst, reset) = (outgoing[0].addr(), outgoing[0].payload());
    assert_eq!(dst, from, "reset goes back to triggering address");
    assert!(
        reset.len() >= 22 && reset.len() < wire.len(),
        "reset must be 22..{} bytes, got {}",
        wire.len(),
        reset.len()
    );

    assert_eq!(reset[0] & 0xC0, 0x40);

    let expected = {
        let signing = support::signing_key(0x39);
        let server = Conn::new_server(
            CID.to_vec(),
            dcid.to_vec(),
            CID.to_vec(),
            signing,
            conn::Config {
                stateless_reset_secret: Some(secret),
                ..Default::default()
            },
        )
        .unwrap();
        let _ = server;
        None::<[u8; 16]>
    };
    let mut tail = [0u8; 16];
    tail.copy_from_slice(&reset[reset.len() - 16..]);
    assert_ne!(tail, [0u8; 16], "tail must be non-zero (real SRT)");
    let _ = expected;

    let mut wire2 = vec![0x40u8; 30];
    wire2[1..9].copy_from_slice(&dcid);
    mux.recv(from, &wire2, Instant::now()).unwrap();
    let outgoing2: Vec<_> = mux.drain_outgoing().collect();
    let mut tail2 = [0u8; 16];
    let p2 = outgoing2[0].payload();
    tail2.copy_from_slice(&p2[p2.len() - 16..]);
    assert_eq!(tail, tail2, "SRT must be deterministic per (secret, dcid)");
}

#[test]
fn stateless_reset_obeys_checked_packet_ceiling() {
    let signing = support::signing_key(0x35);
    let config = conn::Config {
        stateless_reset_secret: Some([0xd4; 32]),
        ..Default::default()
    };
    let mut mux = Mux::server_with_outgoing_limits(NoopHandler, signing, config, 1, 22).unwrap();
    let mut wire = vec![0x40; 64];
    wire[1..9].copy_from_slice(&[0x99; 8]);
    mux.recv("127.0.0.1:4444".parse().unwrap(), &wire, Instant::now())
        .unwrap();
    let reset = mux.drain_outgoing().next().unwrap();
    assert_eq!(reset.payload().len(), 22);
    assert_eq!(mux.outgoing_bytes(), 0);
}

#[test]
fn server_without_secret_does_not_emit_reset() {
    let signing = support::signing_key(0x39);
    let mut mux = Mux::server(NoopHandler, signing, conn::Config::default()).unwrap();

    let dcid = [0x11u8; 8];
    let mut wire = vec![0x40u8; 30];
    wire[1..9].copy_from_slice(&dcid);

    let from: SocketAddr = "127.0.0.1:1".parse().unwrap();
    mux.recv(from, &wire, Instant::now()).unwrap();
    assert!(
        mux.drain_outgoing().next().is_none(),
        "no secret ⇒ no reset"
    );
}

#[test]
fn server_does_not_emit_reset_for_initial_packet() {
    let secret = [0xD2u8; 32];
    let mut mux = server_mux(secret);

    let wire = vec![0xC0u8; 30];
    let from: SocketAddr = "127.0.0.1:2".parse().unwrap();
    let _ = mux.recv(from, &wire, Instant::now());
    assert!(
        mux.drain_outgoing().next().is_none(),
        "Initial path must not emit reset"
    );
}

#[test]
fn end_to_end_server_restart_recovery() {
    let secret = [0xD3u8; 32];
    let (_old_server, mut client) = handshake(cfg(Some(secret)), cfg(None));
    let peer_dcid = peer_cid(&mut client);

    let mut server_b = server_mux(secret);
    let mut wire = vec![0x40u8; 30];
    wire[1..9].copy_from_slice(&peer_dcid);
    let from: SocketAddr = "127.0.0.1:33333".parse().unwrap();
    server_b.recv(from, &wire, Instant::now()).unwrap();
    let outgoing: Vec<_> = server_b.drain_outgoing().collect();
    assert_eq!(outgoing.len(), 1);
    let reset = outgoing[0].payload();

    client.recv_packet(reset, Instant::now()).unwrap();
    assert!(
        client.was_stateless_reset(),
        "client should accept the reset"
    );
    assert!(client.is_closed());
}

#[test]
fn different_secrets_yield_different_srts() {
    let secret_a = [0x01u8; 32];
    let secret_b = [0x02u8; 32];
    let (_, client_a) = handshake(cfg(Some(secret_a)), cfg(None));
    let (_, client_b) = handshake(cfg(Some(secret_b)), cfg(None));
    let token_a = client_a
        .peer_transport_params()
        .unwrap()
        .stateless_reset_token
        .unwrap();
    let token_b = client_b
        .peer_transport_params()
        .unwrap()
        .stateless_reset_token
        .unwrap();
    assert_ne!(token_a, token_b);
}
