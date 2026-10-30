use crate::common::peer;
pub mod common;
use common::suite::peers::config::{FixedTime, Parameters as _};
use dope_quic::conn::life::options::Options;
use dope_quic::wire::packet::cid;
use std::{sync::Arc, time::Instant};

use dope_quic::{conn, security::crypto};
use peer::Pair;
use peer::Receiver as _;

#[test]
fn retires_failed_handshake() {
    let server = Options::try_pto().expect("server options");
    let client = Options::try_pto().expect("client options");
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_config(
        server,
        client,
        cid::Id::try_from([0x71; 8]).expect("fixture CID"),
        |server, client| {
            server.alpn_protocols = vec![b"h3".to_vec()];
            client.alpn_protocols = vec![b"wrong".to_vec()];
        },
    )
    .expect("opening peers");
    let now = Instant::now();
    let mut wire = {
        let (emitted_packets, send_result) =
            client.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("client initial flight");
        emitted_packets
    }
    .remove(0);
    let mut first = wire.clone();
    assert!(matches!(
        server.receive(&mut work, &mut first, now),
        Err(peer::Transfer::Input(conn::Error::Handshake(cause)))
            if matches!(cause.error, rustls::Error::NoApplicationProtocol)
    ));
    server
        .receive(&mut work, &mut wire, now)
        .expect("closing connection must not reenter failed TLS");
}

#[test]
fn missing_native_time() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_config(
        Options::try_pto().expect("server options"),
        Options::try_pto().expect("client options"),
        cid::Id::try_from([0x72; 8]).expect("fixture CID"),
        |_, client| client.time_provider = Arc::new(FixedTime(None)),
    )
    .expect("opening does not require civil time");
    let now = Instant::now();
    server
        .receive_from(&mut work, &mut client, now)
        .expect("ClientHello reaches the server");
    assert!(matches!(
        client.receive_from(&mut work, &mut server, now),
        Err(peer::Transfer::Input(conn::Error::Handshake(cause)))
            if matches!(cause.error, rustls::Error::FailedToGetCurrentTime)
    ));
}

#[test]
fn roundtrips_datagrams() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_open(
        Options::try_pto().expect("fixture configuration bounds"),
        Options::try_pto().expect("fixture configuration bounds"),
    )
    .expect("fixture peers must open");

    assert!(
        client.view().lifecycle().is_opening(),
        "a fresh client must begin in the handshaking state"
    );
    assert!(
        server.view().lifecycle().is_opening(),
        "a fresh server must begin in the handshaking state"
    );

    assert!(
        server
            .receive_from(&mut work, &mut client, Instant::now())
            .is_ok()
    );
    assert!(
        client
            .receive_from(&mut work, &mut server, Instant::now())
            .is_ok()
    );
    assert!(
        server
            .receive_from(&mut work, &mut client, Instant::now())
            .is_ok()
    );

    assert!(
        client.view().lifecycle().is_ready(),
        "three fixture flights must establish the client"
    );
    assert!(
        server.view().lifecycle().is_ready(),
        "three fixture flights must establish the server"
    );

    let peer =
        (client.view().peer().params()).expect("established peer parameters must be retained");
    assert_eq!(peer.timing().idle_ms(), 30_000);
    assert_eq!(peer.flow().datagram(), Some(65_535));
    let peer =
        (server.view().peer().params()).expect("established peer parameters must be retained");
    assert_eq!(peer.flow().datagram(), Some(65_535));

    assert!(
        client
            .with_scope(|mut scope| scope.datagrams().try_send(b"hello server".to_vec()))
            .is_ok(),
        "fixture DATAGRAM must fit its negotiated queue"
    );
    assert!(
        server
            .receive_from(&mut work, &mut client, Instant::now())
            .is_ok()
    );
    assert_eq!(
        server
            .with_scope(|mut scope| scope.datagrams().recv())
            .as_deref(),
        Some(b"hello server".as_slice())
    );
    assert_eq!(
        server.with_scope(|mut scope| scope.datagrams().recv()),
        None
    );

    assert!(
        server
            .with_scope(|mut scope| scope.datagrams().try_send(b"hello client".to_vec()))
            .is_ok(),
        "fixture DATAGRAM must fit its negotiated queue"
    );
    assert!(
        client
            .receive_from(&mut work, &mut server, Instant::now())
            .is_ok()
    );
    assert_eq!(
        client
            .with_scope(|mut scope| scope.datagrams().recv())
            .as_deref(),
        Some(b"hello client".as_slice())
    );
}

#[test]
fn buffers_datagrams() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_open(
        Options::try_pto().expect("fixture configuration bounds"),
        Options::try_pto().expect("fixture configuration bounds"),
    )
    .expect("fixture peers must open");

    assert!(
        server
            .receive_from(&mut work, &mut client, Instant::now())
            .is_ok()
    );
    assert!(
        client
            .receive_from(&mut work, &mut server, Instant::now())
            .is_ok()
    );
    assert!(
        server
            .receive_from(&mut work, &mut client, Instant::now())
            .is_ok()
    );
    assert!(client.view().lifecycle().is_ready());

    for i in 0..5 {
        assert!(
            client
                .with_scope(|mut scope| scope.datagrams().try_send(vec![i as u8; 16]))
                .is_ok(),
            "five fixture DATAGRAMs must fit the negotiated queue"
        );
    }
    assert!(
        server
            .receive_from(&mut work, &mut client, Instant::now())
            .is_ok()
    );

    for i in 0..5 {
        let datagram = (server.with_scope(|mut scope| scope.datagrams().recv()))
            .expect("queued DATAGRAM must arrive");
        assert_eq!(datagram, vec![i as u8; 16]);
    }
    assert!(
        server
            .with_scope(|mut scope| scope.datagrams().recv())
            .is_none()
    );
}

#[test]
fn coalesces_long_packets() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_open(
        Options::try_pto().expect("fixture configuration bounds"),
        Options::try_pto().expect("fixture configuration bounds"),
    )
    .expect("fixture peers must open");
    let now = Instant::now();

    assert!(
        server
            .receive_from(&mut work, &mut client, Instant::now())
            .is_ok()
    );
    let (packets, send_result) = server.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("server journals must admit coalesced handshake output");
    assert!(packets.len() >= 2, "server emits coalescible long packets");
    let mut datagram = Vec::with_capacity(packets.iter().map(Vec::len).sum());
    for packet in packets {
        datagram.extend_from_slice(&packet);
    }
    assert!(client.receive(&mut work, &mut datagram, now).is_ok());
    assert!(
        server
            .receive_from(&mut work, &mut client, Instant::now())
            .is_ok()
    );

    assert!(client.view().lifecycle().is_ready());
    assert!(server.view().lifecycle().is_ready());
}

#[test]
fn rejects_forged_scid() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_open(
        Options::try_pto().expect("fixture configuration bounds"),
        Options::try_pto().expect("fixture configuration bounds"),
    )
    .expect("fixture peers must open");
    let now = Instant::now();

    assert!(
        server
            .receive_from(&mut work, &mut client, Instant::now())
            .is_ok()
    );
    let (mut flight, send_result) = server.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("server journals must admit the forged-SCID fixture flight");
    let initial = (flight.iter().find(|packet| packet[0] & 0x30 == 0))
        .expect("first server flight must contain an Initial");
    let mut forged = initial.clone();
    let dcid_len = usize::from(forged[5]);
    let scid_at = 6 + dcid_len;
    assert_ne!(forged[scid_at], 0);
    forged[scid_at + 1] ^= 0x5a;
    assert!(
        matches!(
            client.with_scope(|mut scope| scope.input(&mut work).recv_packet(
                &mut forged,
                now,
                |_: &rustls::Error| {}
            )),
            Err(conn::Error::Crypto(crypto::Error::Decrypt(
                rustls::Error::DecryptError
            )))
        ),
        "changing the authenticated SCID must fail packet authentication"
    );

    for packet in &mut flight {
        assert!(client.receive(&mut work, packet, now).is_ok());
    }
    for _ in 0..4 {
        assert!(
            server
                .receive_from(&mut work, &mut client, Instant::now())
                .is_ok()
        );
        assert!(
            client
                .receive_from(&mut work, &mut server, Instant::now())
                .is_ok()
        );
    }
    assert!(client.view().lifecycle().is_ready());
    assert!(server.view().lifecycle().is_ready());
}
