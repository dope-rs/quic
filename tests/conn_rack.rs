use std::time::{Duration, Instant};

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

#[test]
fn rack_finishes_handshake_when_first_initial_drops_quickly() {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();

    let t0 = Instant::now();
    let mut server = Conn::new_server(CID.to_vec(), CID.to_vec(), CID.to_vec(), signing, user_tp());
    let mut client = Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, user_tp());

    for _ in 0..3 {
        for p in client.send_packets(t0) {
            server.recv_packet(&p, t0).expect("server recv");
        }
        for p in server.send_packets(t0) {
            client.recv_packet(&p, t0).expect("client recv");
        }
    }
    assert!(client.is_established());
    assert!(server.is_established());
}

#[test]
fn loss_timer_shrinks_after_rtt_samples() {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();

    let t0 = Instant::now();
    let mut server = Conn::new_server(CID.to_vec(), CID.to_vec(), CID.to_vec(), signing, user_tp());
    let mut client = Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, user_tp());

    for p in client.send_packets(t0) {
        server
            .recv_packet(&p, t0 + Duration::from_micros(50))
            .expect("server recv");
    }
    let pto_before = client.next_timer().unwrap();
    assert!(pto_before >= t0 + Duration::from_millis(333));
    assert!(client.smoothed_rtt().is_none());

    for p in server.send_packets(t0 + Duration::from_micros(100)) {
        client
            .recv_packet(&p, t0 + Duration::from_micros(200))
            .expect("client recv");
    }
    assert!(
        client.smoothed_rtt().is_some(),
        "client took RTT sample after server's ACK"
    );

    for p in client.send_packets(t0 + Duration::from_micros(300)) {
        server
            .recv_packet(&p, t0 + Duration::from_micros(400))
            .expect("server recv");
    }
    assert!(client.is_established());
    assert!(server.is_established());

    if let Some(next) = client.next_timer() {
        let dt = next.saturating_duration_since(t0 + Duration::from_micros(400));
        assert!(
            dt < Duration::from_millis(100),
            "post-handshake loss timer is RTT-tight (dt={dt:?})"
        );
    }
}
