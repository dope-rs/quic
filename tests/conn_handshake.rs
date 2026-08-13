pub mod support;

use std::time::Instant;

use dope_quic::{conn, conn::session::Connection, transport_params};

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];

fn drain<R: support::Receiver>(
    workspace: &mut conn::ReceiveWorkspace,
    from: &mut Connection,
    into: &mut R,
) {
    let now = Instant::now();
    for mut pkt in from.transmit().send(now) {
        into.receive(workspace, &mut pkt, now);
    }
}

fn user_tp() -> dope_quic::conn::config::Options {
    transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(65535),
        ..transport_params::Params::default()
    }
    .into()
}

#[test]
fn conn_handshake_and_datagram_round_trip() {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();

    let mut server = dope_quic::conn::setup::Server::<0>::accept(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        user_tp(),
    )
    .unwrap();
    let mut workspace = conn::ReceiveWorkspace::new();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        user_tp(),
    )
    .unwrap();

    assert!(client.status().is_handshaking());
    assert!(server.status().is_handshaking());

    drain(&mut workspace, &mut client, &mut server);
    drain(&mut workspace, &mut server, &mut client);
    drain(&mut workspace, &mut client, &mut server);

    assert!(client.status().is_established(), "client handshake done");
    assert!(server.status().is_established(), "server handshake done");

    let client_view = client.status().peer_transport_params().expect("server tp");
    assert_eq!(client_view.max_idle_timeout_ms, 30_000);
    assert_eq!(client_view.max_datagram_frame_size, Some(65535));
    let server_view = server.status().peer_transport_params().expect("client tp");
    assert_eq!(server_view.max_datagram_frame_size, Some(65535));

    client
        .datagrams()
        .try_send(b"hello server".to_vec())
        .unwrap();
    drain(&mut workspace, &mut client, &mut server);
    assert_eq!(
        server.datagrams().recv().as_deref(),
        Some(b"hello server".as_slice())
    );
    assert_eq!(server.datagrams().recv(), None);

    server
        .datagrams()
        .try_send(b"hello client".to_vec())
        .unwrap();
    drain(&mut workspace, &mut server, &mut client);
    assert_eq!(
        client.datagrams().recv().as_deref(),
        Some(b"hello client".as_slice())
    );
}

#[test]
fn conn_buffers_multiple_outgoing_datagrams() {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();

    let mut server = dope_quic::conn::setup::Server::<0>::accept(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        user_tp(),
    )
    .unwrap();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        user_tp(),
    )
    .unwrap();
    let mut workspace = conn::ReceiveWorkspace::new();

    drain(&mut workspace, &mut client, &mut server);
    drain(&mut workspace, &mut server, &mut client);
    drain(&mut workspace, &mut client, &mut server);
    assert!(client.status().is_established());

    for i in 0..5 {
        client.datagrams().try_send(vec![i as u8; 16]).unwrap();
    }
    drain(&mut workspace, &mut client, &mut server);

    for i in 0..5 {
        let dg = server.datagrams().recv().unwrap();
        assert_eq!(dg, vec![i as u8; 16]);
    }
    assert!(server.datagrams().recv().is_none());
}

#[test]
fn coalesced_long_packets_round_trip() {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();
    let mut server = dope_quic::conn::setup::Server::<0>::accept(
        CID.to_vec(),
        CID.to_vec(),
        CID.to_vec(),
        signing,
        user_tp(),
    )
    .unwrap();
    let mut workspace = conn::ReceiveWorkspace::new();
    let mut client = dope_quic::conn::setup::Client::<0>::connect(
        CID.to_vec(),
        CID.to_vec(),
        server_pubkey,
        user_tp(),
    )
    .unwrap();
    let now = Instant::now();

    drain(&mut workspace, &mut client, &mut server);
    let packets = server.transmit().send(now);
    assert!(packets.len() >= 2, "server emits coalescible long packets");
    let mut datagram = Vec::with_capacity(packets.iter().map(Vec::len).sum());
    for packet in packets {
        datagram.extend_from_slice(&packet);
    }
    client
        .recv_packet(&mut workspace, &mut datagram, now)
        .unwrap();
    drain(&mut workspace, &mut client, &mut server);

    assert!(client.status().is_established());
    assert!(server.status().is_established());
}
