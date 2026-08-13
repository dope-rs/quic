pub mod support;

use std::time::Instant;

use dope_quic::conn::server;
use dope_quic::{conn, conn::session::Connection, transport_params};

const HS_CID: [u8; 8] = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8];

fn handshake_pair() -> (server::Connection, Connection, conn::ReceiveWorkspace) {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();
    let cfg = || conn::config::Options {
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
    let mut server = dope_quic::conn::setup::Server::<0>::accept(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        signing,
        cfg(),
    )
    .unwrap();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        HS_CID.to_vec(),
        HS_CID.to_vec(),
        server_pubkey,
        cfg(),
    )
    .unwrap();
    let now = Instant::now();
    let mut workspace = conn::ReceiveWorkspace::new();
    for _ in 0..3 {
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
    (server, client, workspace)
}

#[test]
fn server_emits_session_ticket_after_handshake() {
    let (mut server, mut client, mut workspace) = handshake_pair();
    let now = Instant::now();
    for mut pkt in server.transmit().send(now) {
        client
            .recv_packet(&mut workspace, &mut pkt, now)
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
    assert!(
        !t.ticket.is_empty(),
        "the server-issued opaque ticket must be present"
    );
    assert!(
        !t.psk.as_slice().iter().all(|&b| b == 0),
        "client must derive PSK from rms+nonce"
    );
}

#[test]
fn client_takes_tickets_drains_buffer() {
    let (mut server, mut client, mut workspace) = handshake_pair();
    let now = Instant::now();
    for mut pkt in server.transmit().send(now) {
        client
            .recv_packet(&mut workspace, &mut pkt, now)
            .expect("client recv");
    }
    let _ = client.take_session_tickets();
    assert!(
        client.take_session_tickets().is_empty(),
        "second drain is empty"
    );
}
