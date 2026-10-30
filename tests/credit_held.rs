use common::peer::Receiver;
pub mod common;
use common::peer::Scope as _;
use common::peer::{Bind, Config, Event, Pair};
use dope_quic::conn::stream::Error;
use dope_quic::errors::Code;
use std::{num::NonZero, time::Instant};

#[test]
fn held_defers_credit() {
    let (mut server, mut client, mut work) = Pair::try_new(
        Config::new(5, 1 << 20, 8, 8)
            .try_build()
            .expect("fixture transport parameters"),
        Config::new(5, 1 << 20, 8, 8)
            .try_build()
            .expect("fixture transport parameters"),
    )
    .expect("connected peers")
    .into_parts();
    let stream = server
        .send_streams()
        .open_bidi()
        .expect("server can open the configured bidirectional stream");
    let peer = Bind::bind(stream, &client).expect("peer stream");
    server
        .send_streams()
        .send(stream, b"abcdefghij")
        .expect("server can queue data beyond current stream credit");
    server
        .send_streams()
        .finish(stream)
        .expect("server can finish the open stream");
    let now = Instant::now();
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");

    let first = client
        .recv()
        .hold(peer)
        .expect("client can inspect the peer receive stream")
        .expect("the admitted prefix is available to hold");
    assert_eq!(first.as_ref(), b"abcde");
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    assert!(
        client
            .recv()
            .hold(peer)
            .expect("client can inspect the held receive stream")
            .is_none()
    );

    let first = client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let mut receive = streams.receive();
        let first = first
            .rebind(&mut receive)
            .map_err(|error| error.kind())
            .expect("held credit belongs to this connection");
        first.release(&mut receive)
    });
    assert_eq!(first.as_slice(), b"abcde");
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    let second = client
        .recv()
        .hold(peer)
        .expect("client can inspect the peer receive stream")
        .expect("released credit admits the remaining bytes");
    assert_eq!(second.as_ref(), b"fghij");
    assert!(
        client
            .stream_state()
            .recv_eof(peer)
            .expect("peer stream remains addressable at EOF")
    );
    assert_eq!(
        client
            .release_held(second)
            .map_err(|error| error.kind())
            .expect("second held batch belongs to this connection")
            .as_slice(),
        b"fghij"
    );
    assert!(
        client
            .stream_state()
            .recv_eof(peer)
            .expect("released stream remains addressable at EOF")
    );
}

#[test]
fn held_commits_in_order() {
    let options = || {
        Config::new(10, 10, 8, 1)
            .try_build()
            .expect("fixture transport parameters")
    };
    let (mut server, mut client, mut work) = Pair::try_new(options(), options())
        .expect("connected peers")
        .into_parts();
    let stream = server
        .send_streams()
        .open_uni()
        .expect("server can open the configured unidirectional stream");
    let peer = Bind::bind(stream, &client).expect("peer stream");
    let now = Instant::now();

    server
        .send_streams()
        .send(stream, b"first")
        .expect("server can send the first batch");
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    let first = client
        .recv()
        .hold(peer)
        .expect("client can inspect the peer receive stream")
        .expect("first batch is available to hold");

    server
        .send_streams()
        .send(stream, b"last!")
        .expect("server can send the last batch");
    server
        .send_streams()
        .finish(stream)
        .expect("server can finish the open stream");
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    let last = client
        .recv()
        .hold(peer)
        .expect("client can inspect the peer receive stream")
        .expect("last batch is available to hold");
    assert!(
        client
            .stream_state()
            .recv_eof(peer)
            .expect("peer stream remains addressable at EOF")
    );
    assert!(matches!(
        server.send_streams().open_uni(),
        Err(Error::PeerLimit)
    ));

    assert_eq!(
        client
            .release_held(last)
            .map_err(|cause| cause.kind())
            .expect("last held batch belongs to this connection")
            .as_slice(),
        b"last!"
    );
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");
    assert!(matches!(
        server.send_streams().open_uni(),
        Err(Error::PeerLimit)
    ));

    assert_eq!(
        client
            .release_held(first)
            .map_err(|cause| cause.kind())
            .expect("first held batch belongs to this connection")
            .as_slice(),
        b"first"
    );
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");
    assert!(server.send_streams().open_uni().is_ok());
}

#[test]
fn split_credit_merges() {
    let options = || {
        Config::new(10, 10, 8, 1)
            .try_build()
            .expect("fixture transport parameters")
    };
    let (mut server, mut client, mut work) = Pair::try_new(options(), options())
        .expect("connected peers")
        .into_parts();
    let stream = server
        .send_streams()
        .open_uni()
        .expect("server can open the configured unidirectional stream");
    let peer = Bind::bind(stream, &client).expect("peer stream");
    let now = Instant::now();

    server
        .send_streams()
        .send(stream, b"first")
        .expect("server can send the first batch");
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    let (first, credit) = client
        .recv()
        .hold(peer)
        .expect("client can inspect the peer receive stream")
        .expect("first batch is available to hold")
        .into_parts();
    assert_eq!(first.as_slice(), b"first");

    server
        .send_streams()
        .send(stream, b"last!")
        .expect("server can send the last batch");
    server
        .send_streams()
        .finish(stream)
        .expect("server can finish the open stream");
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    let (last, tail) = client
        .recv()
        .hold(peer)
        .expect("client can inspect the peer receive stream")
        .expect("last batch is available to hold")
        .into_parts();
    assert_eq!(last.as_slice(), b"last!");
    client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let mut receive = streams.receive();
        let mut credit = credit
            .rebind(&mut receive)
            .map_err(|error| error.kind())
            .expect("first credit belongs to this connection");
        let tail = tail
            .rebind(&mut receive)
            .map_err(|error| error.kind())
            .expect("last credit belongs to this connection");
        assert!(credit.try_merge(tail).is_ok());
        assert_eq!(credit.len(), 10);

        assert!(
            credit
                .take_prefix(NonZero::new(11).expect("nonzero"))
                .is_none()
        );
        assert_eq!(credit.len(), 10);
        let prefix = credit
            .take_prefix(NonZero::new(7).expect("nonzero"))
            .expect("merged credit contains the requested prefix");
        assert_eq!(prefix.len(), 7);
        assert_eq!(credit.len(), 3);
        prefix.release(&mut receive);
        let tail = credit
            .take_prefix(NonZero::new(3).expect("nonzero"))
            .expect("the remaining credit has three bytes");
        tail.release(&mut receive);
        assert!(credit.is_empty());
        assert!(credit.take_prefix(NonZero::<usize>::MIN).is_none());
        credit.release_conn(&mut receive).release(&mut receive);
    });
    assert!(
        client
            .stream_state()
            .recv_eof(peer)
            .expect("peer stream remains addressable at EOF")
    );
}

#[test]
fn connection_credit_moves() {
    let options = || {
        Config::new(5, 5, 8, 2)
            .try_build()
            .expect("fixture transport parameters")
    };
    let (mut server, mut client, mut work) = Pair::try_new(options(), options())
        .expect("connected peers")
        .into_parts();
    let held = server
        .send_streams()
        .open_uni()
        .expect("server can open the held stream");
    let other = server
        .send_streams()
        .open_uni()
        .expect("server can open the progress stream");
    let held_rx = Bind::bind(held, &client).expect("peer stream");
    let other_rx = Bind::bind(other, &client).expect("peer stream");
    let now = Instant::now();

    server
        .send_streams()
        .send(held, b"held!")
        .expect("server can send the held batch");
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    let (buffer, credit) = client
        .recv()
        .hold(held_rx)
        .expect("client can inspect the held receive stream")
        .expect("held batch is available")
        .into_parts();
    assert_eq!(buffer.as_slice(), b"held!");
    let credit = client
        .release_conn(credit)
        .map_err(|error| error.kind())
        .expect("held batch can release only its connection credit");

    server
        .send_streams()
        .send(held, b"later")
        .expect("server can queue more data on the held stream");
    server
        .send_streams()
        .send(other, b"other")
        .expect("server can send on the progress stream");
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    assert_eq!(
        client
            .recv()
            .recv_owned(other_rx)
            .expect("client can move the progress stream batch")
            .as_deref(),
        Some(&b"other"[..]),
        "connection credit must admit another stream",
    );
    assert!(
        client
            .recv()
            .recv_owned(held_rx)
            .expect("client can inspect the blocked held stream")
            .is_none()
    );

    client
        .release(credit)
        .map_err(|error| error.kind())
        .expect("remaining stream credit belongs to this connection");
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    assert_eq!(
        client
            .recv()
            .recv_owned(held_rx)
            .expect("released stream credit admits the remaining bytes")
            .as_deref(),
        Some(&b"later"[..]),
    );
}

#[test]
fn reset_waits_for_credit() {
    let options = || {
        Config::new(5, 5, 8, 1)
            .try_build()
            .expect("fixture transport parameters")
    };
    let (mut server, mut client, mut work) = Pair::try_new(options(), options())
        .expect("connected peers")
        .into_parts();
    let stream = server
        .send_streams()
        .open_uni()
        .expect("server can open one unidirectional stream");
    let peer = Bind::bind(stream, &client).expect("peer stream");
    let now = Instant::now();
    server
        .send_streams()
        .send(stream, b"held!")
        .expect("server can send the held batch");
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    let held = client
        .recv()
        .hold(peer)
        .expect("peer receive stream")
        .expect("held batch");

    client
        .recv()
        .stop(peer, Code::ZERO)
        .expect("stopped receive keeps the outstanding credit");

    let code = Code::from_u8(0x51);
    server
        .send_streams()
        .reset(stream, code)
        .expect("server can reset the held stream");
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    assert!(
        client.poll().poll_event()
            == Some(Event::Reset {
                stream_id: peer,
                error_code: code,
            })
    );
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");
    assert!(matches!(
        server.send_streams().open_uni(),
        Err(Error::PeerLimit)
    ));
    assert_eq!(
        client
            .release_held(held)
            .map_err(|error| error.kind())
            .expect("held credit survives its stream reset")
            .as_slice(),
        b"held!"
    );
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");
    let next = server
        .send_streams()
        .open_uni()
        .expect("settlement returns the stream slot");
    let peer = Bind::bind(next, &client).expect("next peer stream");
    server
        .send_streams()
        .send(next, b"next!")
        .expect("server can send on the reused slot");
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    assert_eq!(
        client
            .recv()
            .recv_owned(peer)
            .expect("reused receive slot")
            .as_deref(),
        Some(&b"next!"[..])
    );
}
