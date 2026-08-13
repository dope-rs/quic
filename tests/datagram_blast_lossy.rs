pub mod support;

use std::time::{Duration, Instant};

use dope_quic::conn::server;
use dope_quic::conn::{self, datagram::CongestionControl};
use dope_quic::{conn::session::Connection, transport_params};

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

fn cfg(mode: CongestionControl) -> conn::config::Options {
    conn::config::Options {
        transport_params: transport_params::Params {
            max_idle_timeout_ms: 60_000,
            max_datagram_frame_size: Some(65535),
            ..transport_params::Params::default()
        },
        datagram_congestion_control: mode,
        pending_datagrams_capacity: 4096,
        ..conn::config::Options::default()
    }
}

fn handshake_pair(
    client_cfg: conn::config::Options,
    server_cfg: conn::config::Options,
) -> (Connection, server::Connection, conn::ReceiveWorkspace) {
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
    let now = Instant::now();
    let mut workspace = conn::ReceiveWorkspace::new();
    for _ in 0..6 {
        for mut pkt in client.transmit().send(now) {
            let _ = server.recv_packet(&mut workspace, &mut pkt, now);
        }
        for mut pkt in server.transmit().send(now) {
            let _ = client.recv_packet(&mut workspace, &mut pkt, now);
        }
        if client.status().is_established() && server.status().is_established() {
            break;
        }
    }
    assert!(client.status().is_established());
    assert!(server.status().is_established());
    (client, server, workspace)
}

fn blast_drain(
    mode: CongestionControl,
    drop_per_million: u32,
    n: usize,
) -> (usize, usize, Duration) {
    let (mut client, mut server, mut workspace) = handshake_pair(cfg(mode), cfg(mode));
    let mut rng = Lcg(0xDEAD_BEEF_CAFE_BABE);

    for i in 0..n {
        client
            .datagrams()
            .try_send(format!("dg-{i:06}").into_bytes())
            .expect("queue");
    }

    let t0 = Instant::now();
    let mut now = t0;
    let mut received = 0usize;
    let mut iterations = 0usize;
    let max_iter = 50_000usize;

    while received < n && iterations < max_iter {
        let mut any_progress = false;

        for mut pkt in client.transmit().send(now) {
            if rng.next() % 1_000_000 >= drop_per_million {
                let _ = server.recv_packet(&mut workspace, &mut pkt, now);
                any_progress = true;
            }
        }
        while let Some(_dg) = server.datagrams().recv() {
            received += 1;
        }
        for mut pkt in server.transmit().send(now) {
            if rng.next() % 1_000_000 >= drop_per_million {
                let _ = client.recv_packet(&mut workspace, &mut pkt, now);
                any_progress = true;
            }
        }

        conn::recovery::Loss::new(&mut client).check_loss(now);
        conn::recovery::Loss::new(&mut server).check_loss(now);

        iterations += 1;
        now += Duration::from_micros(100);
        if !any_progress
            && client.transmit().send(now).is_empty()
            && server.transmit().send(now).is_empty()
        {
            break;
        }
    }

    (received, iterations, now - t0)
}

#[test]
fn baseline_uncongested_drains_all() {
    let (recv, iters, sim) = blast_drain(CongestionControl::Uncongested, 0, 1000);
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
    let (recv, iters, sim) = blast_drain(CongestionControl::Uncongested, 300_000, 1000);
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
    let (recv, iters, sim) = blast_drain(CongestionControl::Standard, 300_000, 1000);
    eprintln!(
        "standard 30% loss: recv={} iters={} sim={:?}",
        recv, iters, sim
    );
}

#[test]
fn uncongested_bursts_are_bounded_without_dropping_the_queue() {
    let (mut client, _server, _workspace) = handshake_pair(
        cfg(CongestionControl::Uncongested),
        cfg(CongestionControl::Uncongested),
    );
    for i in 0..1000usize {
        client
            .datagrams()
            .try_send(format!("dg-{i:06}").into_bytes())
            .expect("queue");
    }
    let first = client.transmit().send(Instant::now());
    assert_eq!(first.len(), 64);
    let second = client.transmit().send(Instant::now());
    assert_eq!(second.len(), 64);
}
