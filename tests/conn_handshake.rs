pub mod support;

use std::time::Instant;

use dope_quic::{Conn, transport_params};

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];

fn drain<R: support::Receiver>(from: &mut Conn, into: &mut R) {
    let now = Instant::now();
    for pkt in from.send_packets(now) {
        into.receive(&pkt, now);
    }
}

fn user_tp() -> dope_quic::conn::Config {
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

    let mut server =
        Conn::new_server(CID.to_vec(), CID.to_vec(), CID.to_vec(), signing, user_tp()).unwrap();
    let mut client =
        Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, user_tp()).unwrap();

    assert!(client.is_handshaking());
    assert!(server.is_handshaking());

    drain(&mut client, &mut server);
    drain(&mut server, &mut client);
    drain(&mut client, &mut server);

    assert!(client.is_established(), "client handshake done");
    assert!(server.is_established(), "server handshake done");

    let client_view = client.peer_transport_params().expect("server tp");
    assert_eq!(client_view.max_idle_timeout_ms, 30_000);
    assert_eq!(client_view.max_datagram_frame_size, Some(65535));
    let server_view = server.peer_transport_params().expect("client tp");
    assert_eq!(server_view.max_datagram_frame_size, Some(65535));

    client.try_send_datagram(b"hello server".to_vec()).unwrap();
    drain(&mut client, &mut server);
    assert_eq!(
        server.recv_datagram().as_deref(),
        Some(b"hello server".as_slice())
    );
    assert_eq!(server.recv_datagram(), None);

    server.try_send_datagram(b"hello client".to_vec()).unwrap();
    drain(&mut server, &mut client);
    assert_eq!(
        client.recv_datagram().as_deref(),
        Some(b"hello client".as_slice())
    );
}

#[test]
fn conn_buffers_multiple_outgoing_datagrams() {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();

    let mut server =
        Conn::new_server(CID.to_vec(), CID.to_vec(), CID.to_vec(), signing, user_tp()).unwrap();
    let mut client =
        Conn::new_client(CID.to_vec(), CID.to_vec(), server_pubkey, user_tp()).unwrap();

    drain(&mut client, &mut server);
    drain(&mut server, &mut client);
    drain(&mut client, &mut server);
    assert!(client.is_established());

    for i in 0..5 {
        client.try_send_datagram(vec![i as u8; 16]).unwrap();
    }
    drain(&mut client, &mut server);

    for i in 0..5 {
        let dg = server.recv_datagram().unwrap();
        assert_eq!(dg, vec![i as u8; 16]);
    }
    assert!(server.recv_datagram().is_none());
}
