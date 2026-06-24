use std::time::Instant;

use dope_quic::{Conn, transport_params};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];

fn user_tp() -> dope_quic::ConnConfig {
    transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(65535),
        ..transport_params::Params::default()
    }
    .into()
}

fn signed_keys() -> ([u8; 32], SigningKey) {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let pubkey = *signing.pubkey().unwrap();
    (pubkey, signing)
}

#[test]
fn server_starts_unvalidated() {
    let (_, signing) = signed_keys();
    let server = Conn::new_server(CID.to_vec(), CID.to_vec(), CID.to_vec(), signing, user_tp());
    assert!(!server.peer_address_validated());
}

#[test]
fn client_starts_validated_no_anti_amp_for_client() {
    let (server_pubkey, _) = signed_keys();
    let client = Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, user_tp());
    assert!(client.peer_address_validated());
}

#[test]
fn server_first_response_under_3x_client_initial() {
    let (server_pubkey, signing) = signed_keys();
    let t0 = Instant::now();
    let mut server = Conn::new_server(CID.to_vec(), CID.to_vec(), CID.to_vec(), signing, user_tp());
    let mut client = Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, user_tp());

    let received_bytes: u64 = client
        .send_packets(t0)
        .iter()
        .map(|p| {
            server.recv_packet(p, t0).expect("recv");
            p.len() as u64
        })
        .sum();

    let server_response = server.send_packets(t0);
    let server_sent_bytes: u64 = server_response.iter().map(|p| p.len() as u64).sum();

    assert_eq!(server.amplification_received(), received_bytes);
    assert!(
        server_sent_bytes <= 3 * received_bytes,
        "server emitted {server_sent_bytes} bytes vs allowance {}",
        3 * received_bytes
    );
    assert!(!server.peer_address_validated(), "still pre-validation");
}

#[test]
fn server_validates_on_handshake_packet_from_client() {
    let (server_pubkey, signing) = signed_keys();
    let t0 = Instant::now();
    let mut server = Conn::new_server(CID.to_vec(), CID.to_vec(), CID.to_vec(), signing, user_tp());
    let mut client = Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, user_tp());

    for p in client.send_packets(t0) {
        server.recv_packet(&p, t0).expect("recv");
    }
    assert!(!server.peer_address_validated());

    for p in server.send_packets(t0) {
        client.recv_packet(&p, t0).expect("recv");
    }
    for p in client.send_packets(t0) {
        server.recv_packet(&p, t0).expect("recv");
    }

    assert!(server.peer_address_validated());
}

#[test]
fn validated_server_no_longer_capped() {
    let (server_pubkey, signing) = signed_keys();
    let t0 = Instant::now();
    let mut server = Conn::new_server(CID.to_vec(), CID.to_vec(), CID.to_vec(), signing, user_tp());
    let mut client = Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, user_tp());

    for _ in 0..4 {
        for p in client.send_packets(t0) {
            server.recv_packet(&p, t0).expect("recv");
        }
        for p in server.send_packets(t0) {
            client.recv_packet(&p, t0).expect("recv");
        }
    }
    assert!(server.is_established());
    assert!(server.peer_address_validated());

    for i in 0..50u8 {
        server.send_datagram(vec![i; 100]).unwrap();
    }
    let pkts = server.send_packets(t0);
    assert!(
        pkts.len() >= 50,
        "all datagrams emitted (got {})",
        pkts.len()
    );
}
