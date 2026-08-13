pub mod support;

use std::time::Instant;

use dope_quic::transport_params;
use shin::crypto::sig::SigningKey;

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];

fn user_tp() -> dope_quic::conn::config::Options {
    transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(65535),
        ..transport_params::Params::default()
    }
    .into()
}

fn signed_keys() -> ([u8; 32], SigningKey) {
    let signing = support::signing_key(0x39);
    let pubkey = *signing.pubkey().unwrap();
    (pubkey, signing)
}

#[test]
fn server_starts_unvalidated() {
    let (_, signing) = signed_keys();
    let server = dope_quic::conn::setup::Server::<0>::accept(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        user_tp(),
    )
    .unwrap();
    assert!(!server.status().peer_address_validated());
}

#[test]
fn client_starts_validated_no_anti_amp_for_client() {
    let (server_pubkey, _) = signed_keys();
    let client = dope_quic::conn::setup::Client::<0>::connect(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        user_tp(),
    )
    .unwrap();
    assert!(client.status().peer_address_validated());
}

#[test]
fn server_first_response_under_3x_client_initial() {
    let (server_pubkey, signing) = signed_keys();
    let t0 = Instant::now();
    let mut server = dope_quic::conn::setup::Server::<0>::accept(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        user_tp(),
    )
    .unwrap();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        user_tp(),
    )
    .unwrap();
    let mut workspace = dope_quic::conn::ReceiveWorkspace::new();

    let mut client_initial = client.transmit().send(t0);
    let received_bytes: u64 = client_initial
        .iter_mut()
        .map(|p| {
            server.recv_packet(&mut workspace, p, t0).expect("recv");
            p.len() as u64
        })
        .sum();

    let server_response = server.transmit().send(t0);
    let server_sent_bytes: u64 = server_response.iter().map(|p| p.len() as u64).sum();

    assert_eq!(server.status().amplification_received(), received_bytes);
    assert!(
        server_sent_bytes <= 3 * received_bytes,
        "server emitted {server_sent_bytes} bytes vs allowance {}",
        3 * received_bytes
    );
    assert!(
        !server.status().peer_address_validated(),
        "still pre-validation"
    );
}

#[test]
fn server_validates_on_handshake_packet_from_client() {
    let (server_pubkey, signing) = signed_keys();
    let t0 = Instant::now();
    let mut server = dope_quic::conn::setup::Server::<0>::accept(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        user_tp(),
    )
    .unwrap();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        user_tp(),
    )
    .unwrap();
    let mut workspace = dope_quic::conn::ReceiveWorkspace::new();

    for mut p in client.transmit().send(t0) {
        server
            .recv_packet(&mut workspace, &mut p, t0)
            .expect("recv");
    }
    assert!(!server.status().peer_address_validated());

    for mut p in server.transmit().send(t0) {
        client
            .recv_packet(&mut workspace, &mut p, t0)
            .expect("recv");
    }
    for mut p in client.transmit().send(t0) {
        server
            .recv_packet(&mut workspace, &mut p, t0)
            .expect("recv");
    }

    assert!(server.status().peer_address_validated());
}

#[test]
fn validated_server_no_longer_capped() {
    let (server_pubkey, signing) = signed_keys();
    let t0 = Instant::now();
    let mut server = dope_quic::conn::setup::Server::<0>::accept(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        user_tp(),
    )
    .unwrap();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        user_tp(),
    )
    .unwrap();
    let mut workspace = dope_quic::conn::ReceiveWorkspace::new();

    for _ in 0..4 {
        for mut p in client.transmit().send(t0) {
            server
                .recv_packet(&mut workspace, &mut p, t0)
                .expect("recv");
        }
        for mut p in server.transmit().send(t0) {
            client
                .recv_packet(&mut workspace, &mut p, t0)
                .expect("recv");
        }
    }
    assert!(server.status().is_established());
    assert!(server.status().peer_address_validated());

    for i in 0..50u8 {
        server.datagrams().try_send(vec![i; 100]).unwrap();
    }
    let pkts = server.transmit().send(t0);
    assert!(
        pkts.len() >= 50,
        "all datagrams emitted (got {})",
        pkts.len()
    );
}
