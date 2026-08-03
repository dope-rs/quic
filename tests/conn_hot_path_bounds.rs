use std::time::{Duration, Instant};

use dope_quic::conn::server;
use dope_quic::{Connection, conn, transport_params};
use shin::crypto::sig::SigningKey;

const CID: [u8; 8] = [0x8b; 8];

fn config() -> conn::Config {
    conn::Config {
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

fn established() -> (Connection, server::Connection, Instant) {
    let signing = SigningKey::from_seed(&[0x7d; 32]).unwrap();
    let public_key = *signing.pubkey().unwrap();
    let mut server =
        Connection::new_server(CID.to_vec(), CID.to_vec(), CID.to_vec(), signing, config())
            .unwrap();
    let mut client =
        Connection::new_client(CID.to_vec(), CID.to_vec(), public_key, config()).unwrap();
    let now = Instant::now();
    for round in 0..8 {
        let at = now + Duration::from_millis(round);
        for mut packet in client.send_packets(at) {
            server.recv_packet(&mut packet, at).unwrap();
        }
        for mut packet in server.send_packets(at) {
            client.recv_packet(&mut packet, at).unwrap();
        }
    }
    assert!(client.is_established() && server.is_established());
    (client, server, now + Duration::from_millis(20))
}

#[test]
fn busy_first_snapshot_does_not_starve_later_streams() {
    let (mut client, mut server, now) = established();
    for stream_index in 0..300u64 {
        let stream_id = client.open_bidi_stream().unwrap();
        assert_eq!(stream_id, stream_index * 4);
        if stream_index < 256 {
            client.stream_send(stream_id, &[0x31; 1 << 15]).unwrap();
        } else {
            client
                .stream_send(stream_id, &[stream_index as u8])
                .unwrap();
        }
    }

    for mut packet in client.send_packets(now) {
        server.recv_packet(&mut packet, now).unwrap();
    }
    let ack_at = now + Duration::from_millis(20);
    for mut packet in server.send_packets(ack_at) {
        client.recv_packet(&mut packet, ack_at).unwrap();
    }
    let second_send = ack_at + Duration::from_millis(20);
    for mut packet in client.send_packets(second_send) {
        server.recv_packet(&mut packet, second_send).unwrap();
    }

    let mut received = Vec::new();
    assert_eq!(server.stream_recv(256 * 4, &mut received), 1);
    assert_eq!(received, vec![0]);
}
