use std::time::Instant;

use dope_quic::pmtud::{BASE_PMTU, Pmtud};
use dope_quic::{Conn, ConnConfig, transport_params};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

#[test]
fn fresh_pmtud_starts_at_base() {
    let p = Pmtud::new(1500);
    assert_eq!(p.current(), BASE_PMTU);
    assert!(!p.done());
}

#[test]
fn next_probe_picks_midpoint_until_done() {
    let mut p = Pmtud::new(1500);
    let size = p.next_probe().expect("probe expected");
    assert_eq!(size, (BASE_PMTU + 1500) / 2);
    p.arm_probe(size);
    p.on_probe_acked();
    assert_eq!(p.current(), size);
    let next = p.next_probe().expect("further probe expected");
    assert_eq!(next, (size + 1500) / 2);
}

#[test]
fn search_converges_on_max_after_acks() {
    let mut p = Pmtud::new(1500);
    while let Some(size) = p.next_probe() {
        p.arm_probe(size);
        p.on_probe_acked();
    }
    assert!(p.done());
    assert!(
        p.current() >= 1496,
        "current {} must be within 4 of max",
        p.current()
    );
}

#[test]
fn three_losses_lower_upper_bound() {
    let mut p = Pmtud::new(1500);
    let size = p.next_probe().unwrap();
    for _ in 0..3 {
        p.arm_probe(size);
        p.on_probe_lost();
    }
    let next = p.next_probe().expect("smaller probe after loss");
    assert!(next < size, "post-loss probe {} must be < {}", next, size);
}

#[test]
fn ack_clears_in_flight_so_next_probe_emits() {
    let mut p = Pmtud::new(1500);
    let size = p.next_probe().unwrap();
    p.arm_probe(size);
    assert_eq!(p.next_probe(), None, "no probe while one is in flight");
    p.on_probe_acked();
    assert!(p.next_probe().is_some());
}

#[test]
fn done_when_search_window_collapses() {
    let p = Pmtud::new(1204);
    assert!(p.done() || p.next_probe().is_none());
}

const HS_CID: [u8; 8] = [0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78];

fn handshake_pair() -> (Conn, Conn) {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();
    let cfg = || ConnConfig {
        transport_params: transport_params::Params {
            max_idle_timeout_ms: 30_000,
            max_datagram_frame_size: Some(65535),
            active_connection_id_limit: 8,
            initial_max_data: 1 << 20,
            initial_max_stream_data_bidi_local: 1 << 20,
            initial_max_stream_data_bidi_remote: 1 << 20,
            initial_max_stream_data_uni: 1 << 20,
            ..transport_params::Params::default()
        },
        ..Default::default()
    };
    let mut server = Conn::new_server(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        signing,
        cfg(),
    );
    let mut client = Conn::new_client(HS_CID.to_vec(), HS_CID.to_vec(), server_pubkey, cfg());
    let now = Instant::now();
    for _ in 0..3 {
        for pkt in client.send_packets(now) {
            server.recv_packet(&pkt, now).expect("server recv");
        }
        for pkt in server.send_packets(now) {
            client.recv_packet(&pkt, now).expect("client recv");
        }
    }
    assert!(client.is_established() && server.is_established());
    (server, client)
}

#[test]
fn conn_path_mtu_pre_handshake_is_base() {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();
    let client = Conn::new_client(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        server_pubkey,
        ConnConfig::default(),
    );
    let _ = signing;
    assert_eq!(client.path_mtu(), BASE_PMTU);
}

#[test]
fn conn_emits_probes_and_grows_mtu_on_acks() {
    let (mut server, mut client) = handshake_pair();
    let now = Instant::now();
    for _ in 0..30 {
        for pkt in server.send_packets(now) {
            client.recv_packet(&pkt, now).expect("client recv probe");
        }
        for pkt in client.send_packets(now) {
            server.recv_packet(&pkt, now).expect("server recv ack");
        }
    }
    assert!(
        server.path_mtu() > BASE_PMTU,
        "PMTU should grow past {} via probes; got {}",
        BASE_PMTU,
        server.path_mtu(),
    );
}

#[test]
fn lossy_then_acked_converges_below_max() {
    let mut p = Pmtud::new(1500);
    let first = p.next_probe().unwrap();
    for _ in 0..3 {
        p.arm_probe(first);
        p.on_probe_lost();
    }
    while let Some(size) = p.next_probe() {
        p.arm_probe(size);
        p.on_probe_acked();
    }
    assert!(p.done());
    assert!(
        p.current() < first,
        "PMTU must be below the lossy size {}",
        first
    );
    assert!(p.current() >= BASE_PMTU);
}
