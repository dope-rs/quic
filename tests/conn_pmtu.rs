pub mod support;

use std::time::Instant;

use dope_quic::conn::server;
use dope_quic::{TrySendError, conn, conn::session::Connection, transport_params};

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];

fn user_tp(max_datagram: u64) -> dope_quic::conn::config::Options {
    transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(max_datagram),
        ..transport_params::Params::default()
    }
    .into()
}

fn pair(
    client_max: u64,
    server_max: u64,
) -> (server::Connection, Connection, conn::ReceiveWorkspace) {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();
    let server = dope_quic::conn::setup::Server::<0>::accept(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        user_tp(server_max),
    )
    .unwrap();
    let client = dope_quic::conn::setup::Client::<0>::connect(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        user_tp(client_max),
    )
    .unwrap();
    (server, client, conn::ReceiveWorkspace::new())
}

fn complete_handshake(
    workspace: &mut conn::ReceiveWorkspace,
    server: &mut server::Connection,
    client: &mut Connection,
    now: Instant,
) {
    support::transfer(workspace, client, server, now);
    support::transfer(workspace, server, client, now);
    support::transfer(workspace, client, server, now);
    support::transfer(workspace, server, client, now);
}

#[test]
fn datagram_payload_pre_handshake_is_unknown() {
    let (_, mut client, _workspace) = pair(65535, 65535);
    assert!(client.datagrams().max_payload().is_none());
    let payload = b"x".to_vec();
    let err = client.datagrams().try_send(payload.clone()).unwrap_err();
    assert_eq!(err, TrySendError::Unsupported(payload));
}

#[test]
fn datagram_payload_clamped_to_pmtu_floor() {
    let (mut server, mut client, mut workspace) = pair(65535, 65535);
    complete_handshake(&mut workspace, &mut server, &mut client, Instant::now());
    let max = client
        .datagrams()
        .max_payload()
        .expect("post-handshake limit");
    assert!(max < 1200);
    assert!(max > 1100);
}

#[test]
fn datagram_payload_respects_peer_limit() {
    let (mut server, mut client, mut workspace) = pair(65535, 100);
    complete_handshake(&mut workspace, &mut server, &mut client, Instant::now());
    let max = client
        .datagrams()
        .max_payload()
        .expect("post-handshake limit");
    assert_eq!(max, 99);
    assert!(client.datagrams().try_send(vec![0; 99]).is_ok());
    let payload = vec![0; 100];
    let err = client.datagrams().try_send(payload.clone()).unwrap_err();
    assert_eq!(err, TrySendError::TooLarge(payload));
}

#[test]
fn server_with_unconfigured_datagram_limit_rejects() {
    let (mut server, mut client, mut workspace) = pair(65535, 0);
    complete_handshake(&mut workspace, &mut server, &mut client, Instant::now());
    let payload = vec![0; 10];
    let err = client.datagrams().try_send(payload.clone()).unwrap_err();
    assert_eq!(err, TrySendError::Unsupported(payload));
}

#[test]
fn cwnd_tracks_bytes_in_flight_during_handshake() {
    let (mut server, mut client, mut workspace) = pair(65535, 65535);
    let t0 = Instant::now();

    for mut p in client.transmit().send(t0) {
        server.recv_packet(&mut workspace, &mut p, t0).unwrap();
    }
    assert!(
        client.status().bytes_in_flight() >= 1200,
        "Initial in flight"
    );

    for mut p in server.transmit().send(t0) {
        client.recv_packet(&mut workspace, &mut p, t0).unwrap();
    }
    assert_eq!(
        client.status().unacked_count(0),
        0,
        "client Initial acked or discarded"
    );
}
