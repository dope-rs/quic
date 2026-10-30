use common::peer::Config;
use common::peer::Pair;
use common::peer::Receiver;
use common::peer::Scope as _;
pub mod common;
use common::peer;
use peer::Bind;

use peer::Event;

use std::time::{Duration, Instant};

use dope_quic::{conn::stream::Error, errors};

#[test]
fn peer_allocator_enforces() {
    let (_, mut client, _) = Pair::try_new(
        Config::new(1 << 20, 1 << 20, 1, 0)
            .try_build()
            .expect("fixture transport parameters"),
        Config::new(1 << 20, 1 << 20, 1, 0)
            .try_build()
            .expect("fixture transport parameters"),
    )
    .expect("connected peers")
    .into_parts();
    assert_eq!(client.send_streams().open_bidi().map(|id| id.get()), Ok(0));
    assert!(matches!(
        client.send_streams().open_bidi(),
        Err(Error::PeerLimit)
    ));
    assert!(matches!(
        client.send_streams().open_uni(),
        Err(Error::PeerLimit)
    ));
}

#[test]
fn local_differs_from_peer() {
    let server = Config::new(1 << 20, 1 << 20, 2, 0)
        .try_build()
        .expect("fixture transport parameters");
    let client = (Config::new(1 << 20, 1 << 20, 2, 0)
        .try_build()
        .expect("fixture transport parameters")
        .into_builder()
        .streams(|streams| streams.local_bidi(1))
        .try_build())
    .expect("fixture connection options");
    let (_, mut client, _) = Pair::try_new(server, client)
        .expect("connected peers")
        .into_parts();

    assert_eq!(client.send_streams().open_bidi().map(|id| id.get()), Ok(0));
    assert!(matches!(
        client.send_streams().open_bidi(),
        Err(Error::Capacity)
    ));
}

#[test]
fn local_returns_on_retire() {
    let server = Config::new(1 << 20, 1 << 20, 2, 0)
        .try_build()
        .expect("fixture transport parameters");
    let client = (Config::new(1 << 20, 1 << 20, 2, 0)
        .try_build()
        .expect("fixture transport parameters")
        .into_builder()
        .streams(|streams| streams.local_bidi(1))
        .try_build())
    .expect("fixture connection options");
    let (mut server, mut client, mut work) = Pair::try_new(server, client)
        .expect("connected peers")
        .into_parts();
    let stream = client
        .send_streams()
        .open_bidi()
        .expect("client can consume its sole local stream slot");
    let peer = Bind::bind(stream, &server).expect("peer stream");
    assert!(matches!(
        client.send_streams().open_bidi(),
        Err(Error::Capacity)
    ));

    client
        .send_streams()
        .send(stream, b"request")
        .expect("client can send the request");
    client
        .send_streams()
        .finish(stream)
        .expect("client can finish its send half");
    let now = Instant::now();
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");
    assert_eq!(
        server
            .recv()
            .recv_owned(peer)
            .expect("server can move the request batch")
            .as_deref(),
        Some(&b"request"[..])
    );
    server
        .send_streams()
        .send(peer, b"response")
        .expect("server can send the response");
    server
        .send_streams()
        .finish(peer)
        .expect("server can finish its send half");
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    assert!(matches!(
        client.send_streams().open_bidi(),
        Err(Error::Capacity)
    ));
    assert_eq!(
        client
            .recv()
            .recv_owned(stream)
            .expect("client can move the response batch")
            .as_deref(),
        Some(&b"response"[..])
    );

    for round in 1..=4 {
        let at = now + Duration::from_millis(round * 20);
        Receiver::receive_from(&mut server, &mut work, &mut client, at)
            .expect("peer packet transfer");
        Receiver::receive_from(&mut client, &mut work, &mut server, at)
            .expect("peer packet transfer");
    }
    assert_eq!(client.send_streams().open_bidi().map(|id| id.get()), Ok(4));
}

#[test]
fn bidi_close_replenishes() {
    let (mut server, mut client, mut work) = Pair::try_new(
        Config::new(1 << 20, 1 << 20, 2, 0)
            .try_build()
            .expect("fixture transport parameters"),
        Config::new(1 << 20, 1 << 20, 2, 0)
            .try_build()
            .expect("fixture transport parameters"),
    )
    .expect("connected peers")
    .into_parts();
    let streams = [
        client
            .send_streams()
            .open_bidi()
            .expect("client can open the first credited stream"),
        client
            .send_streams()
            .open_bidi()
            .expect("client can open the second credited stream"),
    ];
    assert!(matches!(
        client.send_streams().open_bidi(),
        Err(Error::PeerLimit)
    ));

    let now = Instant::now();
    for stream in streams {
        client
            .send_streams()
            .send(stream, b"request")
            .expect("client can send each request");
        client
            .send_streams()
            .finish(stream)
            .expect("client can finish each request stream");
    }
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");
    for stream in streams {
        let peer = Bind::bind(stream, &server).expect("peer stream");
        assert_eq!(
            server
                .recv()
                .recv_owned(peer)
                .expect("server can move each request batch")
                .as_deref(),
            Some(&b"request"[..]),
        );
        server
            .send_streams()
            .send(peer, b"response")
            .expect("server can send each response");
        server
            .send_streams()
            .finish(peer)
            .expect("server can finish each response stream");
    }
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    for round in 1..=4 {
        let at = now + Duration::from_millis(round * 20);
        Receiver::receive_from(&mut server, &mut work, &mut client, at)
            .expect("peer packet transfer");
        Receiver::receive_from(&mut client, &mut work, &mut server, at)
            .expect("peer packet transfer");
    }

    assert_eq!(client.send_streams().open_bidi().map(|id| id.get()), Ok(8));
}

#[test]
fn uni_consume_replenishes() {
    let (mut server, mut client, mut work) = Pair::try_new(
        Config::new(1 << 20, 1 << 20, 0, 2)
            .try_build()
            .expect("fixture transport parameters"),
        Config::new(1 << 20, 1 << 20, 0, 2)
            .try_build()
            .expect("fixture transport parameters"),
    )
    .expect("connected peers")
    .into_parts();
    let streams = [
        client
            .send_streams()
            .open_uni()
            .expect("client can open the first credited stream"),
        client
            .send_streams()
            .open_uni()
            .expect("client can open the second credited stream"),
    ];
    assert!(matches!(
        client.send_streams().open_uni(),
        Err(Error::PeerLimit)
    ));

    let now = Instant::now();
    for stream in streams {
        client
            .send_streams()
            .send(stream, b"one-way")
            .expect("client can send each one-way batch");
        client
            .send_streams()
            .finish(stream)
            .expect("client can finish each one-way stream");
    }
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");
    for stream in streams {
        let peer = Bind::bind(stream, &server).expect("peer stream");
        assert_eq!(
            server
                .recv()
                .recv_owned(peer)
                .expect("server can consume each one-way batch")
                .as_deref(),
            Some(&b"one-way"[..]),
        );
    }
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");

    assert_eq!(client.send_streams().open_uni().map(|id| id.get()), Ok(10));
}

#[test]
fn uni_reset_replenishes() {
    let (mut server, mut client, mut work) = Pair::try_new(
        Config::new(1 << 20, 1 << 20, 0, 1)
            .try_build()
            .expect("fixture transport parameters"),
        Config::new(1 << 20, 1 << 20, 0, 1)
            .try_build()
            .expect("fixture transport parameters"),
    )
    .expect("connected peers")
    .into_parts();
    let stream = client
        .send_streams()
        .open_uni()
        .expect("client can consume its sole peer stream credit");
    let peer = Bind::bind(stream, &server).expect("peer stream");
    assert!(matches!(
        client.send_streams().open_uni(),
        Err(Error::PeerLimit)
    ));

    client
        .send_streams()
        .reset(
            stream,
            errors::Code::new(0x42).expect("0x42 is a QUIC application code"),
        )
        .expect("client can reset the open stream");
    let now = Instant::now();
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");
    assert!(
        server.poll().poll_event()
            == Some(Event::Reset {
                stream_id: peer,
                error_code: dope_quic::errors::Code::from_u8(0x42),
            })
    );
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");

    assert!(client.send_streams().open_uni().is_ok());
}
