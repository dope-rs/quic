pub mod support;

use std::time::{Duration, Instant};

use dope_quic::{Conn, transport_params};

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];

fn user_tp(idle_ms: u64) -> dope_quic::conn::Config {
    transport_params::Params {
        max_idle_timeout_ms: idle_ms,
        max_datagram_frame_size: Some(65535),
        ..transport_params::Params::default()
    }
    .into()
}

fn build_pair(idle_ms: u64) -> (Conn, Conn) {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();
    let server = Conn::new_server(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        user_tp(idle_ms),
    )
    .unwrap();
    let client =
        Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, user_tp(idle_ms)).unwrap();
    (server, client)
}

fn drain(from: &mut Conn, into: &mut Conn, now: Instant) {
    for pkt in from.send_packets(now) {
        into.recv_packet(&pkt, now).expect("recv");
    }
}

fn complete_handshake(server: &mut Conn, client: &mut Conn, now: Instant) {
    drain(client, server, now);
    drain(server, client, now);
    drain(client, server, now);
    drain(server, client, now);
}

#[test]
fn handshake_done_confirms_client_and_discards_handshake_keys() {
    let (mut server, mut client) = build_pair(30_000);
    let t0 = Instant::now();

    drain(&mut client, &mut server, t0);
    drain(&mut server, &mut client, t0);
    drain(&mut client, &mut server, t0);
    assert!(client.is_established());
    assert!(server.is_established());
    assert!(!client.handshake_confirmed(), "client not yet confirmed");

    drain(&mut server, &mut client, t0);
    assert!(client.handshake_confirmed(), "HANDSHAKE_DONE received");
    assert_eq!(client.unacked_count(0), 0);
    assert_eq!(client.unacked_count(1), 0);
}

#[test]
fn close_emits_connection_close_and_peer_transitions_to_closed() {
    let (mut server, mut client) = build_pair(30_000);
    let t0 = Instant::now();
    complete_handshake(&mut server, &mut client, t0);
    assert!(client.is_established());
    assert!(server.is_established());

    client.close(7, b"goodbye".to_vec());
    drain(&mut client, &mut server, t0);

    assert!(client.is_closed(), "client closed after sending CLOSE");
    assert!(server.is_closed(), "server closed after receiving CLOSE");
}

#[test]
fn idle_timeout_silently_closes_after_inactivity() {
    let (mut server, mut client) = build_pair(50);
    let t0 = Instant::now();
    complete_handshake(&mut server, &mut client, t0);

    let t1 = t0 + Duration::from_millis(100);
    client.check_loss(t1);
    server.check_loss(t1);
    assert!(client.is_closed(), "client idle-closed");
    assert!(server.is_closed(), "server idle-closed");
}

#[test]
fn activity_resets_idle_timer() {
    let (mut server, mut client) = build_pair(100);
    let t0 = Instant::now();
    complete_handshake(&mut server, &mut client, t0);

    let t1 = t0 + Duration::from_millis(80);
    client.try_send_datagram(b"keepalive".to_vec()).unwrap();
    drain(&mut client, &mut server, t1);
    assert!(!client.is_closed());
    assert!(!server.is_closed());

    let t2 = t1 + Duration::from_millis(50);
    client.check_loss(t2);
    server.check_loss(t2);
    assert!(!client.is_closed(), "datagram refreshed client idle");
    assert!(!server.is_closed(), "datagram refreshed server idle");
}

#[test]
fn repeated_sends_without_receive_do_not_defer_idle_timeout() {
    let (mut server, mut client) = build_pair(100);
    let t0 = Instant::now();
    complete_handshake(&mut server, &mut client, t0);

    let first_send = t0 + Duration::from_millis(80);
    client.try_send_datagram(b"first".to_vec()).unwrap();
    assert!(!client.send_packets(first_send).is_empty());

    let later_send = t0 + Duration::from_millis(150);
    client.try_send_datagram(b"second".to_vec()).unwrap();
    assert!(!client.send_packets(later_send).is_empty());

    client.check_loss(first_send + Duration::from_millis(101));
    assert!(
        client.is_closed(),
        "only the first ack-eliciting send after a receive may restart idle timeout",
    );
}

#[test]
fn server_discards_handshake_keys_after_handshake_done_send() {
    let (mut server, mut client) = build_pair(30_000);
    let t0 = Instant::now();
    complete_handshake(&mut server, &mut client, t0);
    assert_eq!(server.unacked_count(1), 0);

    let _ = server.send_packets(t0);
    let datagram = client.send_packets(t0);
    let _ = datagram;
}
