use std::time::Instant;

use dope_quic::{Conn, ConnConfig, SessionTicket, transport_params};
use shin::client::Resumption;
use shin::sig::SigningKey;

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
        ..transport_params::Params::default()
    }
}

fn signing() -> SigningKey {
    SigningKey::from_seed(&[0x77u8; 32]).unwrap()
}

fn first_session_ticket() -> SessionTicket {
    let server_cfg = ConnConfig {
        transport_params: user_tp(),
        ticket_secret: Some(TICKET_SECRET),
        accept_early_data: true,
        ..Default::default()
    };
    let client_cfg = ConnConfig {
        transport_params: user_tp(),
        ..Default::default()
    };
    let mut server = Conn::new_server(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        signing(),
        server_cfg,
    );
    let mut client = Conn::new_client(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    );
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

fn drain(from: &mut Conn, into: &mut Conn, now: Instant) {
    for pkt in from.send_packets(now) {
        into.recv_packet(&pkt, now).expect("recv");
    }
}

#[test]
fn zero_rtt_followed_by_one_rtt_full_round_trip() {
    let ticket = first_session_ticket();

    let server_cfg = ConnConfig {
        transport_params: user_tp(),
        ticket_secret: Some(TICKET_SECRET),
        accept_early_data: true,
        ..Default::default()
    };
    let client_cfg = ConnConfig {
        transport_params: user_tp(),
        resumption: Some(Resumption {
            psk: ticket.psk,
            ticket: ticket.ticket.clone(),
            ticket_age_add: ticket.ticket_age_add,
            age_millis: 0,
        }),
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
    );
    let mut client = Conn::new_client(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    );

    let now = Instant::now();
    client.stream_send(4, b"early");
    drain(&mut client, &mut server, now);

    let mut got_early = Vec::new();
    server.stream_recv(4, &mut got_early);
    assert_eq!(&got_early, b"early", "0-RTT bytes arrived before handshake");

    for _ in 0..3 {
        drain(&mut server, &mut client, now);
        drain(&mut client, &mut server, now);
    }
    assert!(client.is_established() && server.is_established());

    server.stream_send(8, b"late-1rtt");
    drain(&mut server, &mut client, now);
    let mut got_late = Vec::new();
    client.stream_recv(8, &mut got_late);
    assert_eq!(&got_late, b"late-1rtt", "1-RTT bytes flow after handshake");
}

#[test]
fn server_rejects_early_data_drops_zero_rtt_but_handshake_completes() {
    let ticket = first_session_ticket();

    let server_cfg = ConnConfig {
        transport_params: user_tp(),
        ticket_secret: Some(TICKET_SECRET),
        accept_early_data: false,
        ..Default::default()
    };
    let client_cfg = ConnConfig {
        transport_params: user_tp(),
        resumption: Some(Resumption {
            psk: ticket.psk,
            ticket: ticket.ticket.clone(),
            ticket_age_add: ticket.ticket_age_add,
            age_millis: 0,
        }),
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
    );
    let mut client = Conn::new_client(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    );

    let now = Instant::now();
    client.stream_send(4, b"rejected");
    drain(&mut client, &mut server, now);

    let mut got = Vec::new();
    server.stream_recv(4, &mut got);
    assert!(
        got.is_empty(),
        "server has no 0-RTT keys when accept_early_data=false; 0-RTT bytes silently dropped",
    );

    for _ in 0..3 {
        drain(&mut server, &mut client, now);
        drain(&mut client, &mut server, now);
    }
    assert!(client.is_established() && server.is_established());
}

#[test]
fn cached_peer_tp_caps_zero_rtt_stream_emission() {
    let ticket = first_session_ticket();
    let mut tight_tp = user_tp();
    tight_tp.initial_max_stream_data_bidi_remote = 4;
    tight_tp.initial_max_data = 4;

    let server_cfg = ConnConfig {
        transport_params: tight_tp.clone(),
        ticket_secret: Some(TICKET_SECRET),
        accept_early_data: true,
        ..Default::default()
    };
    let client_cfg = ConnConfig {
        transport_params: user_tp(),
        resumption: Some(Resumption {
            psk: ticket.psk,
            ticket: ticket.ticket.clone(),
            ticket_age_add: ticket.ticket_age_add,
            age_millis: 0,
        }),
        enable_early_data: true,
        resumption_peer_tp: Some(tight_tp),
        ..Default::default()
    };

    let mut server = Conn::new_server(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        signing(),
        server_cfg,
    );
    let mut client = Conn::new_client(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    );

    let now = Instant::now();
    client.stream_send(4, b"abcdefghij");
    for pkt in client.send_packets(now) {
        server.recv_packet(&pkt, now).expect("server recv");
    }
    let mut got = Vec::new();
    server.stream_recv(4, &mut got);
    assert_eq!(
        &got, b"abcd",
        "cached peer TP must cap 0-RTT to initial_max_stream_data"
    );
}

#[test]
fn zero_rtt_stream_data_arrives_before_handshake_completes() {
    let ticket = first_session_ticket();

    let server_cfg = ConnConfig {
        transport_params: user_tp(),
        ticket_secret: Some(TICKET_SECRET),
        accept_early_data: true,
        ..Default::default()
    };
    let client_cfg = ConnConfig {
        transport_params: user_tp(),
        resumption: Some(Resumption {
            psk: ticket.psk,
            ticket: ticket.ticket.clone(),
            ticket_age_add: ticket.ticket_age_add,
            age_millis: 0,
        }),
        enable_early_data: true,
        ..Default::default()
    };

    let mut server = Conn::new_server(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        signing(),
        server_cfg,
    );
    let mut client = Conn::new_client(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        *signing().pubkey().unwrap(),
        client_cfg,
    );

    let now = Instant::now();
    client.stream_send(4, b"early-bytes");

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
    server.stream_recv(4, &mut got);
    assert_eq!(&got, b"early-bytes", "server saw 0-RTT stream data");
    assert!(
        !server.is_established(),
        "server must process 0-RTT before handshake completes",
    );
}
