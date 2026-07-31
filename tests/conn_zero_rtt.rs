pub mod support;

use std::time::Instant;

use dope_quic::conn::PacketBatch;
use dope_quic::early_data::EarlyDataReplayCache;
use dope_quic::{Conn, SessionTicket, conn, transport_params};
use shin::client::config::Resumption;
use shin::crypto::sig::SigningKey;

const HS_CID: [u8; 8] = [0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7];
const TICKET_SECRET: [u8; 32] = [0xCAu8; 32];

fn user_tp() -> transport_params::Params {
    transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(65535),
        active_connection_id_limit: 8,
        initial_max_data: 1 << 20,
        initial_max_stream_data_bidi_local: 1 << 20,
        initial_max_stream_data_bidi_remote: 1 << 20,
        initial_max_stream_data_uni: 1 << 20,
        initial_max_streams_bidi: 8,
        ..transport_params::Params::default()
    }
}

fn signing() -> SigningKey {
    SigningKey::from_seed(&[0x77u8; 32]).unwrap()
}

fn first_session_ticket() -> SessionTicket {
    let server_cfg = conn::Config {
        transport_params: user_tp(),
        ticket_secret: Some(TICKET_SECRET),
        ..Default::default()
    };
    let client_cfg = conn::Config {
        transport_params: user_tp(),
        ..Default::default()
    };
    let mut server = Conn::new_server(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        signing(),
        server_cfg,
    )
    .unwrap();
    let mut client = Conn::new_client(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    )
    .unwrap();
    let now = Instant::now();
    for _ in 0..4 {
        for pkt in client.send_packets(now) {
            server.recv_packet(&pkt, now).expect("server recv");
        }
        for pkt in server.send_packets(now) {
            client.recv_packet(&pkt, now).expect("client recv");
        }
    }
    assert!(client.is_established() && server.is_established());
    let tickets = client.take_session_tickets();
    assert!(!tickets.is_empty(), "ticket emitted");
    tickets.into_iter().next().unwrap()
}

#[test]
fn zero_rtt_followed_by_one_rtt_full_round_trip() {
    let ticket = first_session_ticket();

    let server_cfg = conn::Config {
        transport_params: user_tp(),
        ticket_secret: Some(TICKET_SECRET),
        ..Default::default()
    };
    let client_cfg = conn::Config {
        transport_params: user_tp(),
        resumption: Some(Resumption::new(
            ticket.psk,
            ticket.ticket.clone(),
            ticket.ticket_age_add,
            0,
        )),
        enable_early_data: true,
        resumption_peer_tp: Some(user_tp()),
        ..Default::default()
    };

    let mut server = Conn::new_server_with_early_data_guard(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        signing(),
        server_cfg,
        EarlyDataReplayCache::new(),
    )
    .unwrap();
    let mut client = Conn::new_client(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    )
    .unwrap();

    let now = Instant::now();
    let stream = client.open_bidi_stream().unwrap();
    client.stream_send(stream, b"early").unwrap();
    support::transfer(&mut client, &mut server, now);

    let mut got_early = Vec::new();
    server.stream_recv(stream, &mut got_early);
    assert_eq!(&got_early, b"early", "0-RTT bytes arrived before handshake");

    for _ in 0..3 {
        support::transfer(&mut server, &mut client, now);
        support::transfer(&mut client, &mut server, now);
    }
    assert!(client.is_established() && server.is_established());

    server.stream_send(stream, b"late-1rtt").unwrap();
    support::transfer(&mut server, &mut client, now);
    let mut got_late = Vec::new();
    client.stream_recv(stream, &mut got_late);
    assert_eq!(&got_late, b"late-1rtt", "1-RTT bytes flow after handshake");
}

#[test]
fn server_rejects_early_data_drops_zero_rtt_but_handshake_completes() {
    let ticket = first_session_ticket();

    let server_cfg = conn::Config {
        transport_params: user_tp(),
        ticket_secret: Some(TICKET_SECRET),
        ..Default::default()
    };
    let client_cfg = conn::Config {
        transport_params: user_tp(),
        resumption: Some(Resumption::new(
            ticket.psk,
            ticket.ticket.clone(),
            ticket.ticket_age_add,
            0,
        )),
        enable_early_data: true,
        resumption_peer_tp: Some(user_tp()),
        ..Default::default()
    };

    let mut server = Conn::new_server(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        signing(),
        server_cfg,
    )
    .unwrap();
    let mut client = Conn::new_client(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    )
    .unwrap();

    let now = Instant::now();
    let stream = client.open_bidi_stream().unwrap();
    client.stream_send(stream, b"rejected").unwrap();
    support::transfer(&mut client, &mut server, now);

    let mut got = Vec::new();
    server.stream_recv(stream, &mut got);
    assert!(
        got.is_empty(),
        "server has no 0-RTT guard, so 0-RTT bytes are silently dropped",
    );

    for _ in 0..3 {
        support::transfer(&mut server, &mut client, now);
        support::transfer(&mut client, &mut server, now);
    }
    assert!(client.is_established() && server.is_established());
    support::transfer(&mut client, &mut server, now);
    let mut retried = Vec::new();
    server.stream_recv(stream, &mut retried);
    assert_eq!(&retried, b"rejected");
}

#[test]
fn cached_peer_tp_caps_zero_rtt_stream_emission() {
    let ticket = first_session_ticket();
    let mut tight_tp = user_tp();
    tight_tp.initial_max_stream_data_bidi_remote = 4;
    tight_tp.initial_max_data = 4;

    let server_cfg = conn::Config {
        transport_params: tight_tp.clone(),
        ticket_secret: Some(TICKET_SECRET),
        ..Default::default()
    };
    let client_cfg = conn::Config {
        transport_params: user_tp(),
        resumption: Some(Resumption::new(
            ticket.psk,
            ticket.ticket.clone(),
            ticket.ticket_age_add,
            0,
        )),
        enable_early_data: true,
        resumption_peer_tp: Some(tight_tp),
        ..Default::default()
    };

    let mut server = Conn::new_server_with_early_data_guard(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        signing(),
        server_cfg,
        EarlyDataReplayCache::new(),
    )
    .unwrap();
    let mut client = Conn::new_client(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    )
    .unwrap();

    let now = Instant::now();
    let stream = client.open_bidi_stream().unwrap();
    client.stream_send(stream, b"abcdefghij").unwrap();
    for pkt in client.send_packets(now) {
        server.recv_packet(&pkt, now).expect("server recv");
    }
    let mut got = Vec::new();
    server.stream_recv(stream, &mut got);
    assert_eq!(
        &got, b"abcd",
        "cached peer TP must cap 0-RTT to initial_max_stream_data"
    );
}

#[test]
fn zero_rtt_stream_data_arrives_before_handshake_completes() {
    let ticket = first_session_ticket();

    let server_cfg = conn::Config {
        transport_params: user_tp(),
        ticket_secret: Some(TICKET_SECRET),
        ..Default::default()
    };
    let client_cfg = conn::Config {
        transport_params: user_tp(),
        resumption: Some(Resumption::new(
            ticket.psk,
            ticket.ticket.clone(),
            ticket.ticket_age_add,
            0,
        )),
        enable_early_data: true,
        resumption_peer_tp: Some(user_tp()),
        ..Default::default()
    };

    let mut server = Conn::new_server_with_early_data_guard(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        signing(),
        server_cfg,
        EarlyDataReplayCache::new(),
    )
    .unwrap();
    let mut client = Conn::new_client(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    )
    .unwrap();

    let now = Instant::now();
    let stream = client.open_bidi_stream().unwrap();
    client.stream_send(stream, b"early-bytes").unwrap();

    let first_flight = client.send_packets(now);
    let saw_zero_rtt = first_flight
        .iter()
        .any(|w| w.first().map(|b| b & 0xF0 == 0xD0).unwrap_or(false));
    assert!(
        saw_zero_rtt,
        "client first flight must contain a 0-RTT packet"
    );

    for pkt in &first_flight {
        server.recv_packet(pkt, now).expect("server recv 0-RTT");
    }

    let mut got = Vec::new();
    server.stream_recv(stream, &mut got);
    assert_eq!(&got, b"early-bytes", "server saw 0-RTT stream data");
    assert!(
        !server.is_established(),
        "server must process 0-RTT before handshake completes",
    );
}

#[test]
fn oversized_zero_rtt_stream_is_split_below_the_byte_ceiling() {
    let ticket = first_session_ticket();
    let client_cfg = conn::Config {
        transport_params: user_tp(),
        resumption: Some(Resumption::new(
            ticket.psk,
            ticket.ticket,
            ticket.ticket_age_add,
            0,
        )),
        enable_early_data: true,
        resumption_peer_tp: Some(user_tp()),
        ..Default::default()
    };
    let mut client = Conn::new_client(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    )
    .unwrap();
    let stream = client.open_bidi_stream().unwrap();
    client.stream_send(stream, &vec![0x33; 64 * 1024]).unwrap();
    let mut packets = PacketBatch::default();
    client.send_batch(&mut packets, Instant::now(), 64, 1200);
    let zero_rtt = packets
        .iter()
        .filter(|packet| packet.first().is_some_and(|byte| byte & 0xf0 == 0xd0))
        .count();
    assert!(zero_rtt > 1);
    assert!(packets.iter().all(|packet| packet.len() <= 1200));
}
