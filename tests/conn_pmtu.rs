pub mod support;

use std::time::Instant;

use dope_quic::conn::server;
use dope_quic::{Connection, TrySendError, transport_params};

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];

fn user_tp(max_datagram: u64) -> dope_quic::conn::Config {
    transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(max_datagram),
        ..transport_params::Params::default()
    }
    .into()
}

fn pair(client_max: u64, server_max: u64) -> (server::Connection, Connection) {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();
    let server = Connection::new_server(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        user_tp(server_max),
    )
    .unwrap();
    let client = Connection::new_client(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        user_tp(client_max),
    )
    .unwrap();
    (server, client)
}

fn complete_handshake(server: &mut server::Connection, client: &mut Connection, now: Instant) {
    support::transfer(client, server, now);
    support::transfer(server, client, now);
    support::transfer(client, server, now);
    support::transfer(server, client, now);
}

#[test]
fn datagram_payload_pre_handshake_is_unknown() {
    let (_, mut client) = pair(65535, 65535);
    assert!(client.max_datagram_payload().is_none());
    let payload = b"x".to_vec();
    let err = client.try_send_datagram(payload.clone()).unwrap_err();
    assert_eq!(err, TrySendError::Unsupported(payload));
}

#[test]
fn datagram_payload_clamped_to_pmtu_floor() {
    let (mut server, mut client) = pair(65535, 65535);
    complete_handshake(&mut server, &mut client, Instant::now());
    let max = client.max_datagram_payload().expect("post-handshake limit");
    assert!(max < 1200);
    assert!(max > 1100);
}

#[test]
fn datagram_payload_respects_peer_limit() {
    let (mut server, mut client) = pair(65535, 100);
    complete_handshake(&mut server, &mut client, Instant::now());
    let max = client.max_datagram_payload().expect("post-handshake limit");
    assert_eq!(max, 99);
    assert!(client.try_send_datagram(vec![0; 99]).is_ok());
    let payload = vec![0; 100];
    let err = client.try_send_datagram(payload.clone()).unwrap_err();
    assert_eq!(err, TrySendError::TooLarge(payload));
}

#[test]
fn server_with_unconfigured_datagram_limit_rejects() {
    let (mut server, mut client) = pair(65535, 0);
    complete_handshake(&mut server, &mut client, Instant::now());
    let payload = vec![0; 10];
    let err = client.try_send_datagram(payload.clone()).unwrap_err();
    assert_eq!(err, TrySendError::Unsupported(payload));
}

#[test]
fn cwnd_tracks_bytes_in_flight_during_handshake() {
    let (mut server, mut client) = pair(65535, 65535);
    let t0 = Instant::now();

    for mut p in client.send_packets(t0) {
        server.recv_packet(&mut p, t0).unwrap();
    }
    assert!(client.bytes_in_flight() >= 1200, "Initial in flight");

    for mut p in server.send_packets(t0) {
        client.recv_packet(&mut p, t0).unwrap();
    }
    assert_eq!(
        client.unacked_count(0),
        0,
        "client Initial acked or discarded"
    );
}
