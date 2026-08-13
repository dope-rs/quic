pub mod support;

use std::time::Instant;

use dope_quic::conn::{packet::Batch, session::Ticket};
use dope_quic::early_data::ReplayCache;
use dope_quic::{conn, transport_params};
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

fn first_session_ticket(replay: ReplayCache) -> Ticket {
    let server_cfg = conn::config::Options {
        transport_params: user_tp(),
        ticket_secret: Some(TICKET_SECRET),
        ..Default::default()
    };
    let client_cfg = conn::config::Options {
        transport_params: user_tp(),
        ..Default::default()
    };
    let mut server = dope_quic::conn::setup::Server::<0>::accept_with_guard(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        signing(),
        server_cfg,
        replay,
    )
    .unwrap();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    )
    .unwrap();
    let now = Instant::now();
    let mut workspace = conn::ReceiveWorkspace::new();
    for _ in 0..4 {
        for mut pkt in client.transmit().send(now) {
            server
                .recv_packet(&mut workspace, &mut pkt, now)
                .expect("server recv");
        }
        for mut pkt in server.transmit().send(now) {
            client
                .recv_packet(&mut workspace, &mut pkt, now)
                .expect("client recv");
        }
    }
    assert!(client.status().is_established() && server.status().is_established());
    let tickets = client.take_session_tickets();
    assert!(!tickets.is_empty(), "ticket emitted");
    tickets.into_iter().next().unwrap()
}

#[test]
fn zero_rtt_followed_by_one_rtt_full_round_trip() {
    let replay = ReplayCache::new().unwrap();
    let ticket = first_session_ticket(replay.clone());

    let server_cfg = conn::config::Options {
        transport_params: user_tp(),
        ticket_secret: Some(TICKET_SECRET),
        ..Default::default()
    };
    let client_cfg = conn::config::Options {
        transport_params: user_tp(),
        resumption: Some(ticket),
        enable_early_data: true,
        resumption_peer_tp: Some(user_tp()),
        ..Default::default()
    };

    let mut server = dope_quic::conn::setup::Server::<0>::accept_with_guard(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        signing(),
        server_cfg,
        replay,
    )
    .unwrap();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    )
    .unwrap();

    let now = Instant::now();
    let mut workspace = conn::ReceiveWorkspace::new();
    let stream = client.streams().open_bidi().unwrap();
    client.streams().send(stream, b"early").unwrap();
    support::transfer(&mut workspace, &mut client, &mut server, now);

    let mut got_early = Vec::new();
    server.streams().recv(stream, &mut got_early);
    assert_eq!(&got_early, b"early", "0-RTT bytes arrived before handshake");

    for _ in 0..3 {
        support::transfer(&mut workspace, &mut server, &mut client, now);
        support::transfer(&mut workspace, &mut client, &mut server, now);
    }
    assert!(client.status().is_established() && server.status().is_established());

    server.streams().send(stream, b"late-1rtt").unwrap();
    support::transfer(&mut workspace, &mut server, &mut client, now);
    let mut got_late = Vec::new();
    client.streams().recv(stream, &mut got_late);
    assert_eq!(&got_late, b"late-1rtt", "1-RTT bytes flow after handshake");
}

#[test]
fn server_rejects_early_data_drops_zero_rtt_but_handshake_completes() {
    let ticket = first_session_ticket(ReplayCache::new().unwrap());

    let server_cfg = conn::config::Options {
        transport_params: user_tp(),
        ticket_secret: Some(TICKET_SECRET),
        ..Default::default()
    };
    let client_cfg = conn::config::Options {
        transport_params: user_tp(),
        resumption: Some(ticket),
        enable_early_data: true,
        resumption_peer_tp: Some(user_tp()),
        ..Default::default()
    };

    let mut server = dope_quic::conn::setup::Server::<0>::accept(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        signing(),
        server_cfg,
    )
    .unwrap();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    )
    .unwrap();

    let now = Instant::now();
    let mut workspace = conn::ReceiveWorkspace::new();
    let stream = client.streams().open_bidi().unwrap();
    client.streams().send(stream, b"rejected").unwrap();
    support::transfer(&mut workspace, &mut client, &mut server, now);

    let mut got = Vec::new();
    server.streams().recv(stream, &mut got);
    assert!(
        got.is_empty(),
        "server has no 0-RTT guard, so 0-RTT bytes are silently dropped",
    );

    for _ in 0..3 {
        support::transfer(&mut workspace, &mut server, &mut client, now);
        support::transfer(&mut workspace, &mut client, &mut server, now);
    }
    assert!(client.status().is_established() && server.status().is_established());
    support::transfer(&mut workspace, &mut client, &mut server, now);
    let mut retried = Vec::new();
    server.streams().recv(stream, &mut retried);
    assert_eq!(&retried, b"rejected");
}

#[test]
fn cached_peer_tp_caps_zero_rtt_stream_emission() {
    let replay = ReplayCache::new().unwrap();
    let ticket = first_session_ticket(replay.clone());
    let mut tight_tp = user_tp();
    tight_tp.initial_max_stream_data_bidi_remote = 4;
    tight_tp.initial_max_data = 4;

    let server_cfg = conn::config::Options {
        // The ticket is bound to the issuing server's transport context. Keep
        // that context stable while deliberately supplying a tighter cached
        // peer view to exercise the client's 0-RTT send ceiling.
        transport_params: user_tp(),
        ticket_secret: Some(TICKET_SECRET),
        ..Default::default()
    };
    let client_cfg = conn::config::Options {
        transport_params: user_tp(),
        resumption: Some(ticket),
        enable_early_data: true,
        resumption_peer_tp: Some(tight_tp),
        ..Default::default()
    };

    let mut server = dope_quic::conn::setup::Server::<0>::accept_with_guard(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        signing(),
        server_cfg,
        replay,
    )
    .unwrap();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    )
    .unwrap();

    let now = Instant::now();
    let mut workspace = conn::ReceiveWorkspace::new();
    let stream = client.streams().open_bidi().unwrap();
    client.streams().send(stream, b"abcdefghij").unwrap();
    for mut pkt in client.transmit().send(now) {
        server
            .recv_packet(&mut workspace, &mut pkt, now)
            .expect("server recv");
    }
    let mut got = Vec::new();
    server.streams().recv(stream, &mut got);
    assert_eq!(
        &got, b"abcd",
        "cached peer TP must cap 0-RTT to initial_max_stream_data"
    );
}

#[test]
fn zero_rtt_stream_data_arrives_before_handshake_completes() {
    let replay = ReplayCache::new().unwrap();
    let ticket = first_session_ticket(replay.clone());

    let server_cfg = conn::config::Options {
        transport_params: user_tp(),
        ticket_secret: Some(TICKET_SECRET),
        ..Default::default()
    };
    let client_cfg = conn::config::Options {
        transport_params: user_tp(),
        resumption: Some(ticket),
        enable_early_data: true,
        resumption_peer_tp: Some(user_tp()),
        ..Default::default()
    };

    let mut server = dope_quic::conn::setup::Server::<0>::accept_with_guard(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        signing(),
        server_cfg,
        replay,
    )
    .unwrap();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    )
    .unwrap();

    let now = Instant::now();
    let mut workspace = conn::ReceiveWorkspace::new();
    let stream = client.streams().open_bidi().unwrap();
    client.streams().send(stream, b"early-bytes").unwrap();

    let mut first_flight = client.transmit().send(now);
    let saw_zero_rtt = first_flight
        .iter()
        .any(|w| w.first().map(|b| b & 0xF0 == 0xD0).unwrap_or(false));
    assert!(
        saw_zero_rtt,
        "client first flight must contain a 0-RTT packet"
    );

    for pkt in &mut first_flight {
        server
            .recv_packet(&mut workspace, pkt, now)
            .expect("server recv 0-RTT");
    }

    let mut got = Vec::new();
    server.streams().recv(stream, &mut got);
    assert_eq!(&got, b"early-bytes", "server saw 0-RTT stream data");
    assert!(
        !server.status().is_established(),
        "server must process 0-RTT before handshake completes",
    );
}

#[test]
fn oversized_zero_rtt_stream_is_split_below_the_byte_ceiling() {
    let ticket = first_session_ticket(ReplayCache::new().unwrap());
    let client_cfg = conn::config::Options {
        transport_params: user_tp(),
        resumption: Some(ticket),
        enable_early_data: true,
        resumption_peer_tp: Some(user_tp()),
        ..Default::default()
    };
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    )
    .unwrap();
    let stream = client.streams().open_bidi().unwrap();
    client
        .streams()
        .send(stream, &vec![0x33; 64 * 1024])
        .unwrap();
    let mut packets = Batch::default();
    client
        .transmit()
        .send_batch(&mut packets, Instant::now(), 64, 1200);
    let zero_rtt = packets
        .iter()
        .filter(|packet| packet.first().is_some_and(|byte| byte & 0xf0 == 0xd0))
        .count();
    assert!(zero_rtt > 1);
    assert!(packets.iter().all(|packet| packet.len() <= 1200));
}
