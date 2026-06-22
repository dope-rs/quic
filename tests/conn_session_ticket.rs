use std::time::Instant;

use dope_quic::{Conn, ConnConfig, transport_params};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

const HS_CID: [u8; 8] = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8];

fn handshake_pair() -> (Conn, Conn) {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing.pubkey();
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
        ticket_secret: Some([0x77u8; 32]),
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
fn server_emits_session_ticket_after_handshake() {
    let (mut server, mut client) = handshake_pair();
    let now = Instant::now();
    for pkt in server.send_packets(now) {
        client
            .recv_packet(&pkt, now)
            .expect("client recv app crypto");
    }
    let tickets = client.take_session_tickets();
    assert_eq!(
        tickets.len(),
        1,
        "exactly one ticket emitted on handshake completion"
    );
    let t = &tickets[0];
    assert_eq!(t.ticket_lifetime, 7200);
    assert_eq!(t.ticket_nonce.len(), 8);
    assert_eq!(t.ticket.len(), 12 + 32 + 4 + 16, "nonce|psk|age_add|tag");
    assert!(
        !t.psk.iter().all(|&b| b == 0),
        "client must derive PSK from rms+nonce"
    );
}

#[test]
fn client_takes_tickets_drains_buffer() {
    let (mut server, mut client) = handshake_pair();
    let now = Instant::now();
    for pkt in server.send_packets(now) {
        client.recv_packet(&pkt, now).expect("client recv");
    }
    let _ = client.take_session_tickets();
    assert!(
        client.take_session_tickets().is_empty(),
        "second drain is empty"
    );
}
