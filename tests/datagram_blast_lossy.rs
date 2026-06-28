use std::time::{Duration, Instant};

use dope_quic::{Conn, ConnConfig, DatagramCcMode, transport_params};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

const CID: [u8; 8] = [0x88; 8];

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as u32
    }
}

fn cfg(mode: DatagramCcMode) -> ConnConfig {
    ConnConfig {
        transport_params: transport_params::Params {
            max_idle_timeout_ms: 60_000,
            max_datagram_frame_size: Some(65535),
            ..transport_params::Params::default()
        },
        datagram_cc_mode: mode,
        pending_datagrams_cap: 4096,
        ..ConnConfig::default()
    }
}

fn handshake_pair(client_cfg: ConnConfig, server_cfg: ConnConfig) -> (Conn, Conn) {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();
    let mut server = Conn::new_server(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        server_cfg,
    );
    let mut client = Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, client_cfg);
    let now = Instant::now();
    for _ in 0..6 {
        for pkt in client.send_packets(now) {
            let _ = server.recv_packet(&pkt, now);
        }
        for pkt in server.send_packets(now) {
            let _ = client.recv_packet(&pkt, now);
        }
        if client.is_established() && server.is_established() {
            break;
        }
    }
    assert!(client.is_established());
    assert!(server.is_established());
    (client, server)
}

fn blast_drain(mode: DatagramCcMode, drop_per_million: u32, n: usize) -> (usize, usize, Duration) {
    let (mut client, mut server) = handshake_pair(cfg(mode), cfg(mode));
    let mut rng = Lcg(0xDEAD_BEEF_CAFE_BABE);

    for i in 0..n {
        client
            .send_datagram(format!("dg-{i:06}").into_bytes())
            .expect("queue");
    }

    let t0 = Instant::now();
    let mut now = t0;
    let mut received = 0usize;
    let mut iterations = 0usize;
    let max_iter = 50_000usize;

    while received < n && iterations < max_iter {
        let mut any_progress = false;

        for pkt in client.send_packets(now) {
            if rng.next() % 1_000_000 >= drop_per_million {
                let _ = server.recv_packet(&pkt, now);
                any_progress = true;
            }
        }
        while let Some(_dg) = server.recv_datagram() {
            received += 1;
        }
        for pkt in server.send_packets(now) {
            if rng.next() % 1_000_000 >= drop_per_million {
                let _ = client.recv_packet(&pkt, now);
                any_progress = true;
            }
        }

        client.check_loss(now);
        server.check_loss(now);

        iterations += 1;
        now += Duration::from_micros(100);
        if !any_progress
            && client.send_packets(now).is_empty()
            && server.send_packets(now).is_empty()
        {
            break;
        }
    }

    (received, iterations, now - t0)
}

#[test]
fn baseline_uncongested_drains_all() {
    let (recv, iters, sim) = blast_drain(DatagramCcMode::Uncongested, 0, 1000);
    eprintln!(
        "uncongested 0% loss: recv={} iters={} sim={:?}",
        recv, iters, sim
    );
    assert!(
        recv >= 950,
        "expected ≥950 / 1000 received in 0% loss, got {recv}"
    );
}

#[test]
fn uncongested_under_30pct_loss() {
    let (recv, iters, sim) = blast_drain(DatagramCcMode::Uncongested, 300_000, 1000);
    eprintln!(
        "uncongested 30% loss: recv={} iters={} sim={:?}",
        recv, iters, sim
    );
    let expected_min = 600;
    let expected_max = 800;
    assert!(
        (expected_min..=expected_max).contains(&recv),
        "expected {expected_min}..={expected_max} recv at 30% loss, got {recv}"
    );
}

#[test]
fn standard_under_30pct_loss() {
    let (recv, iters, sim) = blast_drain(DatagramCcMode::Standard, 300_000, 1000);
    eprintln!(
        "standard 30% loss: recv={} iters={} sim={:?}",
        recv, iters, sim
    );
}

#[test]
fn uncongested_first_burst_drains_full_queue() {
    let (mut client, server) = handshake_pair(
        cfg(DatagramCcMode::Uncongested),
        cfg(DatagramCcMode::Uncongested),
    );
    for i in 0..1000usize {
        client
            .send_datagram(format!("dg-{i:06}").into_bytes())
            .expect("queue");
    }
    let pkts = client.send_packets(Instant::now());
    eprintln!("first-burst pkt count: {}", pkts.len());
    assert!(
        pkts.len() >= 1000,
        "Uncongested must emit all 1000 in first burst, got {}",
        pkts.len()
    );
    let _ = server;
}
