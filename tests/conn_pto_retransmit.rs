pub mod support;

use std::time::{Duration, Instant};

use dope_quic::{Conn, transport_params};
use shin::crypto::sig::SigningKey;

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];

fn user_tp() -> dope_quic::conn::Config {
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
fn pto_probes_dropped_client_initial() {
    let (server_pubkey, signing) = signed_keys();

    let t0 = Instant::now();

    let mut server =
        Conn::new_server(CID.to_vec(), CID.to_vec(), CID.to_vec(), signing, user_tp()).unwrap();
    let mut client =
        Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, user_tp()).unwrap();

    let dropped = client.send_packets(t0);
    assert_eq!(dropped.len(), 1);
    assert_eq!(client.unacked_count(0), 1, "client Initial in flight");

    let pto_deadline = client.next_timer().expect("PTO armed after sending");
    assert!(pto_deadline > t0);

    let t1 = pto_deadline + Duration::from_millis(1);
    client.check_loss(t1);
    let retransmit = client.send_packets(t1);
    assert_eq!(retransmit.len(), 2, "PTO produced two probes");
    assert_eq!(
        client.unacked_count(0),
        3,
        "original and probes remain tracked"
    );

    server
        .recv_packet(&retransmit[0], t1)
        .expect("server processes retransmitted Initial");
    let s_pkts = server.send_packets(t1);
    for p in &s_pkts {
        client.recv_packet(p, t1).expect("client recv");
    }
    let c_pkts = client.send_packets(t1);
    for p in &c_pkts {
        server.recv_packet(p, t1).expect("server recv");
    }

    assert!(
        client.is_established(),
        "client established after retransmit"
    );
    assert!(
        server.is_established(),
        "server established after retransmit"
    );
}

#[test]
fn pto_backs_off_on_consecutive_fires() {
    let (server_pubkey, _signing) = signed_keys();

    let t0 = Instant::now();
    let mut client =
        Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, user_tp()).unwrap();

    let _ = client.send_packets(t0);
    let pto1 = client.next_timer().expect("first PTO");

    let t1 = pto1 + Duration::from_millis(1);
    client.check_loss(t1);
    let _ = client.send_packets(t1);
    let pto2 = client.next_timer().expect("second PTO");
    let interval1 = pto1.saturating_duration_since(t0);
    let interval2 = pto2.saturating_duration_since(t1);
    assert!(
        interval2 >= interval1,
        "PTO backoff non-decreasing: {interval1:?} -> {interval2:?}"
    );

    let t2 = pto2 + Duration::from_millis(1);
    client.check_loss(t2);
    let _ = client.send_packets(t2);
    let pto3 = client.next_timer().expect("third PTO");
    let interval3 = pto3.saturating_duration_since(t2);
    assert!(
        interval3 > interval2,
        "PTO backoff strictly increases: {interval2:?} -> {interval3:?}"
    );
}

#[test]
fn ack_clears_pto_timer() {
    let (server_pubkey, signing) = signed_keys();

    let t0 = Instant::now();
    let mut server =
        Conn::new_server(CID.to_vec(), CID.to_vec(), CID.to_vec(), signing, user_tp()).unwrap();
    let mut client =
        Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, user_tp()).unwrap();

    let pkts = client.send_packets(t0);
    for p in &pkts {
        server.recv_packet(p, t0).expect("server recv");
    }
    let s_pkts = server.send_packets(t0 + Duration::from_micros(100));
    for p in &s_pkts {
        client
            .recv_packet(p, t0 + Duration::from_micros(200))
            .expect("client recv");
    }

    assert_eq!(client.unacked_count(0), 0, "client Initial acked");
}
