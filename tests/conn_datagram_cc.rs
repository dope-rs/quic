use std::time::Instant;

use dope_quic::{Conn, ConnConfig, DatagramCcMode, DatagramError, transport_params};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

const CID: [u8; 8] = [0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77];

fn drain(from: &mut Conn, into: &mut Conn) {
    let now = Instant::now();
    for pkt in from.send_packets(now) {
        into.recv_packet(&pkt, now).expect("recv");
    }
}

fn handshake_pair(client_cfg: ConnConfig, server_cfg: ConnConfig) -> (Conn, Conn) {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing.pubkey();

    let mut server = Conn::new_server(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        server_cfg,
    );
    let mut client = Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, client_cfg);

    drain(&mut client, &mut server);
    drain(&mut server, &mut client);
    drain(&mut client, &mut server);
    drain(&mut server, &mut client);
    drain(&mut client, &mut server);
    assert!(client.is_established());
    assert!(server.is_established());
    (client, server)
}

fn tp() -> transport_params::Params {
    transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(65535),
        ..transport_params::Params::default()
    }
}

#[test]
fn standard_mode_throttles_datagrams_under_zero_cwnd() {
    let cfg = ConnConfig {
        transport_params: tp(),
        datagram_cc_mode: DatagramCcMode::Standard,
        pending_datagrams_cap: 1024,
        cid_prefix: None,
        stateless_reset_secret: None,
        require_address_validation: false,
        retry_token_secret: None,
        ticket_secret: None,
        resumption: None,
        enable_early_data: false,
        accept_early_data: false,
        resumption_peer_tp: None,
        alpn_protocols: Vec::new(),
        server_cert_chain: None,
    };
    let (mut client, _server) = handshake_pair(cfg.clone(), cfg);

    client.cc_mut().bytes_in_flight = client.cc_mut().cwnd;

    for _ in 0..8 {
        client.send_datagram(vec![0u8; 100]).unwrap();
    }
    let now = Instant::now();
    let pkts = client.send_packets(now);
    assert!(
        pkts.is_empty(),
        "Standard mode must respect cwnd; got {} packets",
        pkts.len(),
    );
}

#[test]
fn uncongested_mode_emits_datagrams_under_zero_cwnd() {
    let cfg = ConnConfig {
        transport_params: tp(),
        datagram_cc_mode: DatagramCcMode::Uncongested,
        pending_datagrams_cap: 1024,
        cid_prefix: None,
        stateless_reset_secret: None,
        require_address_validation: false,
        retry_token_secret: None,
        ticket_secret: None,
        resumption: None,
        enable_early_data: false,
        accept_early_data: false,
        resumption_peer_tp: None,
        alpn_protocols: Vec::new(),
        server_cert_chain: None,
    };
    let (mut client, _server) = handshake_pair(cfg.clone(), cfg);

    client.cc_mut().bytes_in_flight = client.cc_mut().cwnd;

    for _ in 0..8 {
        client.send_datagram(vec![0u8; 100]).unwrap();
    }
    let now = Instant::now();
    let pkts = client.send_packets(now);
    assert_eq!(
        pkts.len(),
        8,
        "Uncongested mode must drain all queued datagrams despite full cwnd",
    );
}

#[test]
fn queue_cap_returns_err_full() {
    let cfg = ConnConfig {
        transport_params: tp(),
        datagram_cc_mode: DatagramCcMode::Uncongested,
        pending_datagrams_cap: 4,
        cid_prefix: None,
        stateless_reset_secret: None,
        require_address_validation: false,
        retry_token_secret: None,
        ticket_secret: None,
        resumption: None,
        enable_early_data: false,
        accept_early_data: false,
        resumption_peer_tp: None,
        alpn_protocols: Vec::new(),
        server_cert_chain: None,
    };
    let (mut client, _server) = handshake_pair(cfg.clone(), cfg);
    client.cc_mut().bytes_in_flight = client.cc_mut().cwnd;
    for _ in 0..4 {
        client.send_datagram(vec![0u8; 8]).unwrap();
    }
    let res = client.send_datagram(vec![0u8; 8]);
    assert_eq!(res, Err(DatagramError::QueueFull));
}

fn cfg_with(mode: DatagramCcMode, cap: usize) -> ConnConfig {
    ConnConfig {
        transport_params: tp(),
        datagram_cc_mode: mode,
        pending_datagrams_cap: cap,
        cid_prefix: None,
        stateless_reset_secret: None,
        require_address_validation: false,
        retry_token_secret: None,
        ticket_secret: None,
        resumption: None,
        enable_early_data: false,
        accept_early_data: false,
        resumption_peer_tp: None,
        alpn_protocols: Vec::new(),
        server_cert_chain: None,
    }
}

#[test]
fn queue_full_recovers_after_drain() {
    let cfg = cfg_with(DatagramCcMode::Uncongested, 4);
    let (mut client, _server) = handshake_pair(cfg.clone(), cfg);
    client.cc_mut().bytes_in_flight = client.cc_mut().cwnd;

    for _ in 0..4 {
        client.send_datagram(vec![0u8; 8]).unwrap();
    }
    assert_eq!(
        client.send_datagram(vec![0u8; 8]),
        Err(DatagramError::QueueFull),
        "cap reached",
    );

    let now = Instant::now();
    let pkts = client.send_packets(now);
    assert_eq!(pkts.len(), 4, "Uncongested drains pending despite cwnd");

    for _ in 0..4 {
        client
            .send_datagram(vec![0u8; 8])
            .expect("post-drain send must succeed");
    }
    assert_eq!(
        client.send_datagram(vec![0u8; 8]),
        Err(DatagramError::QueueFull),
        "cap re-armed at the same depth",
    );
}

#[test]
fn uncongested_still_enforces_pmtu_too_large() {
    let cfg = cfg_with(DatagramCcMode::Uncongested, 1024);
    let (mut client, _server) = handshake_pair(cfg.clone(), cfg);

    let max = client
        .max_datagram_payload()
        .expect("peer advertised max_datagram_frame_size");
    let oversize = vec![0u8; max + 1];
    assert_eq!(client.send_datagram(oversize), Err(DatagramError::TooLarge),);

    client
        .send_datagram(vec![0u8; max])
        .expect("max-sized datagram is allowed");
}

#[test]
fn standard_mode_drains_when_cwnd_open() {
    let cfg = cfg_with(DatagramCcMode::Standard, 1024);
    let (mut client, _server) = handshake_pair(cfg.clone(), cfg);

    for _ in 0..8 {
        client.send_datagram(vec![0u8; 100]).unwrap();
    }
    let now = Instant::now();
    let pkts = client.send_packets(now);
    assert!(
        !pkts.is_empty(),
        "Standard mode must drain SOME datagrams when cwnd is open",
    );
    let still_pending: usize = 8 - pkts.len();
    assert!(
        still_pending < 8,
        "at least one datagram must have left the queue",
    );
}

#[test]
fn closed_conn_returns_err_closed_in_both_modes() {
    for mode in [DatagramCcMode::Standard, DatagramCcMode::Uncongested] {
        let cfg = cfg_with(mode, 1024);
        let (mut client, _server) = handshake_pair(cfg.clone(), cfg);
        client.close(0, Vec::new());
        let now = Instant::now();
        let _ = client.send_packets(now);
        assert!(
            client.is_closed(),
            "send_packets drives state→Closed for {mode:?}"
        );

        assert_eq!(
            client.send_datagram(vec![0u8; 8]),
            Err(DatagramError::Closed),
            "{mode:?}: send_datagram on closed conn must return Closed",
        );
    }
}
