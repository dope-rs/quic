pub mod support;

use std::net::SocketAddr;
use std::time::Instant;

use dope_quic::conn::server;
use dope_quic::conn::{self, session::Connection};
use dope_quic::mux::{Handler, Mux};
use dope_quic::transport_params;

const CID: [u8; 8] = [0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55];

fn drain<R: support::Receiver>(
    workspace: &mut conn::ReceiveWorkspace,
    from: &mut Connection,
    into: &mut R,
) {
    let now = Instant::now();
    for mut pkt in from.transmit().send(now) {
        into.receive(workspace, &mut pkt, now);
    }
}

fn cfg(secret: Option<[u8; 32]>) -> conn::config::Options {
    conn::config::Options {
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

fn handshake(
    server_cfg: conn::config::Options,
    client_cfg: conn::config::Options,
) -> (server::Connection, Connection, conn::ReceiveWorkspace) {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();

    let mut server = dope_quic::conn::setup::Server::<0>::accept(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        server_cfg,
    )
    .unwrap();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        client_cfg,
    )
    .unwrap();
    let mut workspace = conn::ReceiveWorkspace::new();

    drain(&mut workspace, &mut client, &mut server);
    drain(&mut workspace, &mut server, &mut client);
    drain(&mut workspace, &mut client, &mut server);
    drain(&mut workspace, &mut server, &mut client);
    drain(&mut workspace, &mut client, &mut server);
    assert!(client.status().is_established() && server.status().is_established());
    (server, client, workspace)
}

fn peer_cid(conn: &mut Connection) -> Vec<u8> {
    conn.datagrams().try_send(vec![0]).unwrap();
    let now = Instant::now();
    let release = conn.status().next_send_time().max(now);
    let packet = conn
        .transmit()
        .send(release)
        .into_iter()
        .next()
        .expect("application packet");
    packet[1..1 + CID.len()].to_vec()
}

#[test]
fn server_with_secret_advertises_initial_srt_in_tp() {
    let secret = [0xA5u8; 32];
    let (_server, client, _workspace) = handshake(cfg(Some(secret)), cfg(None));

    let peer_tp = client
        .status()
        .peer_transport_params()
        .expect("peer TP after handshake");
    let token = peer_tp
        .stateless_reset_token
        .expect("server should advertise stateless_reset_token");
    assert_ne!(token, [0u8; 16], "token must not be all zeros");
}

#[test]
fn server_without_secret_does_not_advertise_srt() {
    let (_server, client, _workspace) = handshake(cfg(None), cfg(None));
    let peer_tp = client.status().peer_transport_params().expect("peer TP");
    assert!(
        peer_tp.stateless_reset_token.is_none(),
        "no secret ⇒ no advertised SRT",
    );
}

#[test]
fn srt_is_stable_across_server_restarts_with_same_secret() {
    let secret = [0xBBu8; 32];
    let (_, client_a, _workspace_a) = handshake(cfg(Some(secret)), cfg(None));
    let (_, client_b, _workspace_b) = handshake(cfg(Some(secret)), cfg(None));

    let token_a = client_a
        .status()
        .peer_transport_params()
        .unwrap()
        .stateless_reset_token
        .unwrap();
    let token_b = client_b
        .status()
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
    let (_server, mut client, mut workspace) = handshake(cfg(Some(secret)), cfg(None));

    let token = client
        .status()
        .peer_transport_params()
        .and_then(|params| params.stateless_reset_token)
        .expect("peer stateless reset token");

    let mut reset = craft_stateless_reset(token);
    let now = Instant::now();

    client
        .recv_packet(&mut workspace, &mut reset, now)
        .expect("reset must not surface as Error");
    assert!(
        client.status().was_stateless_reset(),
        "client should mark stateless_reset_received",
    );
    assert!(client.status().is_closed());
}

#[test]
fn minimum_length_reset_is_accepted_regardless_of_header_form() {
    let secret = [0xC3u8; 32];
    let (_server, mut client, mut workspace) = handshake(cfg(Some(secret)), cfg(None));
    let token = client
        .status()
        .peer_transport_params()
        .and_then(|params| params.stateless_reset_token)
        .expect("peer stateless reset token");
    let mut reset = vec![0xC0; 21];
    let tail = reset.len() - 16;
    reset[tail..].copy_from_slice(&token);

    client
        .recv_packet(&mut workspace, &mut reset, Instant::now())
        .unwrap();

    assert!(client.status().was_stateless_reset());
    assert!(client.status().is_closed());
}

#[test]
fn unrecognised_tail_does_not_trigger_reset() {
    let secret = [0xC2u8; 32];
    let (_server, mut client, mut workspace) = handshake(cfg(Some(secret)), cfg(None));

    let mut bogus = [0u8; 16];
    for (i, b) in bogus.iter_mut().enumerate() {
        *b = (i as u8) ^ 0xAA;
    }
    let mut reset = craft_stateless_reset(bogus);
    let now = Instant::now();

    let _ = client.recv_packet(&mut workspace, &mut reset, now);
    assert!(
        !client.status().was_stateless_reset(),
        "random tail must not trigger reset",
    );
    assert!(client.status().is_established(), "conn stays open");
}

#[test]
fn pre_handshake_reset_is_ignored() {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();

    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        cfg(None),
    )
    .unwrap();
    let mut workspace = conn::ReceiveWorkspace::new();
    let mut reset = craft_stateless_reset([0xFFu8; 16]);
    let _ = client.recv_packet(&mut workspace, &mut reset, Instant::now());
    assert!(!client.status().was_stateless_reset());
}

struct NoopHandler;
impl Handler<0> for NoopHandler {
    type Connection = ();

    fn create_connection(&mut self, _conn: &mut Connection, _handle: dope_quic::conn::Handle) {}
}

fn server_mux(secret: [u8; 32]) -> Mux<NoopHandler> {
    let signing = support::signing_key(0x39);
    let cfg = conn::config::Options {
        stateless_reset_secret: Some(secret),
        ..Default::default()
    };
    dope_quic::mux::setup::Server::accept(NoopHandler, signing, cfg).unwrap()
}

#[test]
fn server_emits_reset_for_unknown_dcid() {
    let secret = [0xD1u8; 32];
    let mut mux = server_mux(secret);

    let dcid = [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89];
    let mut wire = vec![0x40u8; 30];
    wire[1..9].copy_from_slice(&dcid);

    let from: SocketAddr = "127.0.0.1:55555".parse().unwrap();
    mux.protocol()
        .recv(from, &mut wire, Instant::now())
        .unwrap();

    let outgoing: Vec<_> = mux.output().drain().collect();
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
        let server = dope_quic::conn::setup::Server::<0>::accept(
            CID.to_vec(),
            dcid.to_vec(),
            CID.to_vec(),
            signing,
            conn::config::Options {
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
    mux.protocol()
        .recv(from, &mut wire2, Instant::now())
        .unwrap();
    let outgoing2: Vec<_> = mux.output().drain().collect();
    let mut tail2 = [0u8; 16];
    let p2 = outgoing2[0].payload();
    tail2.copy_from_slice(&p2[p2.len() - 16..]);
    assert_eq!(tail, tail2, "SRT must be deterministic per (secret, dcid)");
}

#[test]
fn stateless_reset_obeys_checked_packet_ceiling() {
    let signing = support::signing_key(0x35);
    let config = conn::config::Options {
        stateless_reset_secret: Some([0xd4; 32]),
        ..Default::default()
    };
    let mut mux =
        dope_quic::mux::setup::Server::with_outgoing_limits(NoopHandler, signing, config, 1, 22)
            .unwrap();
    let mut wire = vec![0x40; 64];
    wire[1..9].copy_from_slice(&[0x99; 8]);
    mux.protocol()
        .recv("127.0.0.1:4444".parse().unwrap(), &mut wire, Instant::now())
        .unwrap();
    let reset = mux.output().drain().next().unwrap();
    assert_eq!(reset.payload().len(), 22);
    assert_eq!(mux.output().bytes(), 0);
}

#[test]
fn server_without_secret_does_not_emit_reset() {
    let signing = support::signing_key(0x39);
    let mut mux = dope_quic::mux::setup::Server::accept(
        NoopHandler,
        signing,
        conn::config::Options::default(),
    )
    .unwrap();

    let dcid = [0x11u8; 8];
    let mut wire = vec![0x40u8; 30];
    wire[1..9].copy_from_slice(&dcid);

    let from: SocketAddr = "127.0.0.1:1".parse().unwrap();
    mux.protocol()
        .recv(from, &mut wire, Instant::now())
        .unwrap();
    assert!(
        mux.output().drain().next().is_none(),
        "no secret ⇒ no reset"
    );
}

#[test]
fn server_does_not_emit_reset_for_initial_packet() {
    let secret = [0xD2u8; 32];
    let mut mux = server_mux(secret);

    let mut wire = vec![0xC0u8; 30];
    let from: SocketAddr = "127.0.0.1:2".parse().unwrap();
    let _ = mux.protocol().recv(from, &mut wire, Instant::now());
    assert!(
        mux.output().drain().next().is_none(),
        "Initial path must not emit reset"
    );
}

#[test]
fn end_to_end_server_restart_recovery() {
    let secret = [0xD3u8; 32];
    let (_old_server, mut client, mut workspace) = handshake(cfg(Some(secret)), cfg(None));
    let peer_dcid = peer_cid(&mut client);

    let mut server_b = server_mux(secret);
    let mut wire = vec![0x40u8; 30];
    wire[1..9].copy_from_slice(&peer_dcid);
    let from: SocketAddr = "127.0.0.1:33333".parse().unwrap();
    server_b
        .protocol()
        .recv(from, &mut wire, Instant::now())
        .unwrap();
    let mut outgoing: Vec<_> = server_b.output().drain().collect();
    assert_eq!(outgoing.len(), 1);
    let reset = outgoing[0].payload_mut();

    client
        .recv_packet(&mut workspace, reset, Instant::now())
        .unwrap();
    assert!(
        client.status().was_stateless_reset(),
        "client should accept the reset"
    );
    assert!(client.status().is_closed());
}

#[test]
fn different_secrets_yield_different_srts() {
    let secret_a = [0x01u8; 32];
    let secret_b = [0x02u8; 32];
    let (_, client_a, _workspace_a) = handshake(cfg(Some(secret_a)), cfg(None));
    let (_, client_b, _workspace_b) = handshake(cfg(Some(secret_b)), cfg(None));
    let token_a = client_a
        .status()
        .peer_transport_params()
        .unwrap()
        .stateless_reset_token
        .unwrap();
    let token_b = client_b
        .status()
        .peer_transport_params()
        .unwrap()
        .stateless_reset_token
        .unwrap();
    assert_ne!(token_a, token_b);
}
