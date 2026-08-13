use std::time::{Duration, Instant};

use dope_quic::conn::server;
use dope_quic::{conn, conn::session::Connection, transport_params};
use shin::crypto::sig::SigningKey;

const CID: [u8; 8] = [0x8b; 8];

fn config() -> conn::config::Options {
    conn::config::Options {
        transport_params: transport_params::Params {
            max_idle_timeout_ms: 30_000,
            initial_max_data: 1 << 24,
            initial_max_stream_data_bidi_local: 1 << 16,
            initial_max_stream_data_bidi_remote: 1 << 16,
            initial_max_streams_bidi: 512,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn established() -> (
    Connection,
    server::Connection,
    conn::ReceiveWorkspace,
    Instant,
) {
    let signing = SigningKey::from_seed(&[0x7d; 32]).unwrap();
    let public_key = *signing.pubkey().unwrap();
    let mut server = dope_quic::conn::setup::Server::<0>::accept(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        config(),
    )
    .unwrap();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        CID.to_vec(),
        CID.to_vec(),
        public_key,
        config(),
    )
    .unwrap();
    let now = Instant::now();
    let mut workspace = conn::ReceiveWorkspace::new();
    for round in 0..8 {
        let at = now + Duration::from_millis(round);
        for mut packet in client.transmit().send(at) {
            server.recv_packet(&mut workspace, &mut packet, at).unwrap();
        }
        for mut packet in server.transmit().send(at) {
            client.recv_packet(&mut workspace, &mut packet, at).unwrap();
        }
    }
    assert!(client.status().is_established() && server.status().is_established());
    (client, server, workspace, now + Duration::from_millis(20))
}

#[test]
fn busy_first_snapshot_does_not_starve_later_streams() {
    let (mut client, mut server, mut workspace, now) = established();
    for stream_index in 0..300u64 {
        let stream_id = client.streams().open_bidi().unwrap();
        assert_eq!(stream_id, stream_index * 4);
        if stream_index < 256 {
            client.streams().send(stream_id, &[0x31; 1 << 15]).unwrap();
        } else {
            client
                .streams()
                .send(stream_id, &[stream_index as u8])
                .unwrap();
        }
    }

    for mut packet in client.transmit().send(now) {
        server
            .recv_packet(&mut workspace, &mut packet, now)
            .unwrap();
    }
    let ack_at = now + Duration::from_millis(20);
    for mut packet in server.transmit().send(ack_at) {
        client
            .recv_packet(&mut workspace, &mut packet, ack_at)
            .unwrap();
    }
    let second_send = ack_at + Duration::from_millis(20);
    for mut packet in client.transmit().send(second_send) {
        server
            .recv_packet(&mut workspace, &mut packet, second_send)
            .unwrap();
    }

    let mut received = Vec::new();
    assert_eq!(server.streams().recv(256 * 4, &mut received), 1);
    assert_eq!(received, vec![0]);
}
