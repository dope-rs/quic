use std::time::Instant;

use dope_quic::conn::DatagramError;
use dope_quic::{Conn, transport_params};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];

fn user_tp(max_datagram: u64) -> dope_quic::ConnConfig {
    transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(max_datagram),
        ..transport_params::Params::default()
    }
    .into()
}

fn pair(client_max: u64, server_max: u64) -> (Conn, Conn) {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing.pubkey();
    let server = Conn::new_server(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        user_tp(server_max),
    );
    let client = Conn::new_client(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        user_tp(client_max),
    );
    (server, client)
}

fn drain(from: &mut Conn, into: &mut Conn, now: Instant) {
    for pkt in from.send_packets(now) {
        into.recv_packet(&pkt, now).expect("recv");
    }
}

fn complete_handshake(server: &mut Conn, client: &mut Conn, now: Instant) {
    drain(client, server, now);
    drain(server, client, now);
    drain(client, server, now);
    drain(server, client, now);
}

#[test]
fn datagram_payload_pre_handshake_is_unknown() {
    let (_, mut client) = pair(65535, 65535);
    assert!(client.max_datagram_payload().is_none());
    let err = client.send_datagram(b"x".to_vec()).unwrap_err();
    assert_eq!(err, DatagramError::PeerDoesNotSupport);
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
    assert!(client.send_datagram(vec![0; 99]).is_ok());
    let err = client.send_datagram(vec![0; 100]).unwrap_err();
    assert_eq!(err, DatagramError::TooLarge);
}

#[test]
fn server_with_unconfigured_datagram_limit_rejects() {
    let (mut server, mut client) = pair(65535, 0);
    complete_handshake(&mut server, &mut client, Instant::now());
    let err = client.send_datagram(vec![0; 10]).unwrap_err();
    assert_eq!(err, DatagramError::PeerDoesNotSupport);
}

#[test]
fn cwnd_initial_state_after_construction() {
    let (server, client) = pair(65535, 65535);
    assert_eq!(client.cwnd(), dope_quic::new_reno::K_INITIAL_WINDOW);
    assert_eq!(client.bytes_in_flight(), 0);
    assert_eq!(server.cwnd(), dope_quic::new_reno::K_INITIAL_WINDOW);
}

#[test]
fn cwnd_tracks_bytes_in_flight_during_handshake() {
    let (mut server, mut client) = pair(65535, 65535);
    let t0 = Instant::now();

    for p in client.send_packets(t0) {
        server.recv_packet(&p, t0).unwrap();
    }
    assert!(client.bytes_in_flight() >= 1200, "Initial in flight");

    for p in server.send_packets(t0) {
        client.recv_packet(&p, t0).unwrap();
    }
    assert_eq!(
        client.unacked_count(0),
        0,
        "client Initial acked or discarded"
    );
}
