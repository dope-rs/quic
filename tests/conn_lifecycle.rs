pub mod support;

use std::time::{Duration, Instant};

use dope_quic::conn::server;
use dope_quic::{conn, conn::session::Connection, transport_params};

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];

fn user_tp(idle_ms: u64) -> dope_quic::conn::config::Options {
    transport_params::Params {
        max_idle_timeout_ms: idle_ms,
        max_datagram_frame_size: Some(65535),
        ..transport_params::Params::default()
    }
    .into()
}

fn build_pair(idle_ms: u64) -> (server::Connection, Connection, conn::ReceiveWorkspace) {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();
    let server = dope_quic::conn::setup::Server::<0>::accept(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        user_tp(idle_ms),
    )
    .unwrap();
    let client = dope_quic::conn::setup::Client::<0>::connect(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        user_tp(idle_ms),
    )
    .unwrap();
    (server, client, conn::ReceiveWorkspace::new())
}

fn drain<R: support::Receiver>(
    workspace: &mut conn::ReceiveWorkspace,
    from: &mut Connection,
    into: &mut R,
    now: Instant,
) {
    for mut pkt in from.transmit().send(now) {
        into.receive(workspace, &mut pkt, now);
    }
}

fn complete_handshake(
    workspace: &mut conn::ReceiveWorkspace,
    server: &mut server::Connection,
    client: &mut Connection,
    now: Instant,
) {
    drain(workspace, client, server, now);
    drain(workspace, server, client, now);
    drain(workspace, client, server, now);
    drain(workspace, server, client, now);
}

#[test]
fn handshake_done_confirms_client_and_discards_handshake_keys() {
    let (mut server, mut client, mut workspace) = build_pair(30_000);
    let t0 = Instant::now();

    drain(&mut workspace, &mut client, &mut server, t0);
    drain(&mut workspace, &mut server, &mut client, t0);
    drain(&mut workspace, &mut client, &mut server, t0);
    assert!(client.status().is_established());
    assert!(server.status().is_established());
    assert!(
        !client.status().handshake_confirmed(),
        "client not yet confirmed"
    );

    drain(&mut workspace, &mut server, &mut client, t0);
    assert!(
        client.status().handshake_confirmed(),
        "HANDSHAKE_DONE received"
    );
    assert_eq!(client.status().unacked_count(0), 0);
    assert_eq!(client.status().unacked_count(1), 0);
}

#[test]
fn close_emits_connection_close_and_peer_transitions_to_closed() {
    let (mut server, mut client, mut workspace) = build_pair(30_000);
    let t0 = Instant::now();
    complete_handshake(&mut workspace, &mut server, &mut client, t0);
    assert!(client.status().is_established());
    assert!(server.status().is_established());

    client.close(7, b"goodbye".to_vec());
    drain(&mut workspace, &mut client, &mut server, t0);

    assert!(
        client.status().is_closed(),
        "client closed after sending CLOSE"
    );
    assert!(
        server.status().is_closed(),
        "server closed after receiving CLOSE"
    );
}

#[test]
fn idle_timeout_silently_closes_after_inactivity() {
    let (mut server, mut client, mut workspace) = build_pair(50);
    let t0 = Instant::now();
    complete_handshake(&mut workspace, &mut server, &mut client, t0);

    let t1 = t0 + Duration::from_millis(100);
    conn::recovery::Loss::new(&mut client).check_loss(t1);
    conn::recovery::Loss::new(&mut server).check_loss(t1);
    assert!(client.status().is_closed(), "client idle-closed");
    assert!(server.status().is_closed(), "server idle-closed");
}

#[test]
fn activity_resets_idle_timer() {
    let (mut server, mut client, mut workspace) = build_pair(100);
    let t0 = Instant::now();
    complete_handshake(&mut workspace, &mut server, &mut client, t0);

    let t1 = t0 + Duration::from_millis(80);
    client.datagrams().try_send(b"keepalive".to_vec()).unwrap();
    drain(&mut workspace, &mut client, &mut server, t1);
    assert!(!client.status().is_closed());
    assert!(!server.status().is_closed());

    let t2 = t1 + Duration::from_millis(50);
    conn::recovery::Loss::new(&mut client).check_loss(t2);
    conn::recovery::Loss::new(&mut server).check_loss(t2);
    assert!(
        !client.status().is_closed(),
        "datagram refreshed client idle"
    );
    assert!(
        !server.status().is_closed(),
        "datagram refreshed server idle"
    );
}

#[test]
fn repeated_sends_without_receive_do_not_defer_idle_timeout() {
    let (mut server, mut client, mut workspace) = build_pair(100);
    let t0 = Instant::now();
    complete_handshake(&mut workspace, &mut server, &mut client, t0);

    let first_send = t0 + Duration::from_millis(80);
    client.datagrams().try_send(b"first".to_vec()).unwrap();
    assert!(!client.transmit().send(first_send).is_empty());

    let later_send = t0 + Duration::from_millis(150);
    client.datagrams().try_send(b"second".to_vec()).unwrap();
    assert!(!client.transmit().send(later_send).is_empty());

    conn::recovery::Loss::new(&mut client).check_loss(first_send + Duration::from_millis(101));
    assert!(
        client.status().is_closed(),
        "only the first ack-eliciting send after a receive may restart idle timeout",
    );
}

#[test]
fn server_discards_handshake_keys_after_handshake_done_send() {
    let (mut server, mut client, mut workspace) = build_pair(30_000);
    let t0 = Instant::now();
    complete_handshake(&mut workspace, &mut server, &mut client, t0);
    assert_eq!(server.status().unacked_count(1), 0);

    let _ = server.transmit().send(t0);
    let datagram = client.transmit().send(t0);
    let _ = datagram;
}
