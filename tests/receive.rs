use common::peer::Config;
use common::peer::Pair;
use common::peer::Receiver;
use common::peer::Scope as _;
pub mod common;
use common::peer;
use peer::Bind;

use peer::Event;

use std::time::Instant;

use dope_quic::{conn::stream::SendOutcome, errors, stream::send};
use errors::Code;
use o3::buffer::storage;

#[test]
fn borrow_keeps_backing() {
    use dope_quic::stream::{Recv as _, RecvBuffer};
    use o3::buffer::{Residency as _, bytes::scope};

    let bytes = Vec::from(&b"abcdef"[..]);
    let pointer = bytes.as_ptr();
    let capacity = bytes.capacity();
    let mut buffer = RecvBuffer::<false>::from_vec(bytes);
    scope::Owner::with(&mut buffer, |owner| {
        let range = owner.view().try_get(1..5).expect("contained receive range");
        let buffer = owner.project(range);
        assert_eq!(buffer.as_ref(), b"bcde");
        assert_eq!(buffer.as_ref().as_ptr(), pointer);
        assert_eq!(buffer.resident(), capacity);
    });
    scope::Owner::with(&mut buffer, |owner| {
        let range = owner
            .view()
            .try_get(2..2)
            .expect("empty interior receive range");
        let buffer = owner.project(range);
        assert!(buffer.is_empty());
        assert_eq!(buffer.as_ref().as_ptr(), pointer);
        assert_eq!(buffer.resident(), capacity);
    });
    assert!(buffer.is_empty());
    assert_eq!(buffer.resident(), capacity);
}

#[test]
fn foreign_receipt_owned() {
    let options = || {
        Config::new(5, 5, 8, 1)
            .try_build()
            .expect("fixture transport parameters")
    };
    let (mut server_a, mut client_a, mut work_a) = Pair::try_new(options(), options())
        .expect("connected peers")
        .into_parts();
    let (mut server_b, mut client_b, mut work_b) = Pair::try_new(options(), options())
        .expect("connected peers")
        .into_parts();
    let stream_a = server_a
        .send_streams()
        .open_uni()
        .expect("first server can open its configured stream");
    let stream_b = server_b
        .send_streams()
        .open_uni()
        .expect("second server can open its configured stream");
    let peer_a = Bind::bind(stream_a, &client_a).expect("peer stream");
    let peer_b = Bind::bind(stream_b, &client_b).expect("peer stream");
    server_a
        .send_streams()
        .send(stream_a, b"alpha")
        .expect("first server can send its batch");
    server_b
        .send_streams()
        .send(stream_b, b"bravo")
        .expect("second server can send its batch");
    let now = Instant::now();
    Receiver::receive_from(&mut client_a, &mut work_a, &mut server_a, now)
        .expect("peer packet transfer");
    Receiver::receive_from(&mut client_b, &mut work_b, &mut server_b, now)
        .expect("peer packet transfer");
    let held_a = client_a
        .recv()
        .hold(peer_a)
        .expect("first client can inspect its receive stream")
        .expect("first batch is available to hold");
    let held_b = client_b
        .recv()
        .hold(peer_b)
        .expect("second client can inspect its receive stream")
        .expect("second batch is available to hold");

    let error = client_b
        .release_held(held_a)
        .expect_err("a foreign connection returns the held receipt failure");
    assert_eq!(
        error.kind(),
        dope_quic::conn::stream::recv::hold::ErrorKind::ForeignConnection
    );
    let held_a = error.into_inner();
    assert_eq!(held_a.as_ref(), b"alpha");
    assert_eq!(held_b.as_ref(), b"bravo");

    assert_eq!(
        client_a
            .release_held(held_a)
            .map_err(|cause| cause.kind())
            .expect("returned receipt retains its first connection owner")
            .as_slice(),
        b"alpha"
    );
    assert_eq!(
        client_b
            .release_held(held_b)
            .map_err(|cause| cause.kind())
            .expect("second receipt retains its connection owner")
            .as_slice(),
        b"bravo"
    );
}

#[test]
fn foreign_credit_owned() {
    let options = || {
        Config::new(5, 5, 8, 1)
            .try_build()
            .expect("fixture transport parameters")
    };
    let (mut server_a, mut client_a, mut work) = Pair::try_new(options(), options())
        .expect("connected peers")
        .into_parts();
    let (_, mut client_b, _) = Pair::try_new(options(), options())
        .expect("connected peers")
        .into_parts();
    let stream = server_a
        .send_streams()
        .open_uni()
        .expect("first server can open its configured stream");
    let peer = Bind::bind(stream, &client_a).expect("peer stream");
    server_a
        .send_streams()
        .send(stream, b"alpha")
        .expect("first server can send its batch");
    Receiver::receive_from(&mut client_a, &mut work, &mut server_a, Instant::now())
        .expect("peer packet transfer");
    let (_, credit) = client_a
        .recv()
        .hold(peer)
        .expect("first client can inspect its receive stream")
        .expect("first batch is available to hold")
        .into_parts();
    let credit = client_a
        .release_conn(credit)
        .expect("held receipt can release only its connection credit");

    let error = client_b
        .release(credit)
        .expect_err("a foreign connection returns the stream credit failure");
    assert_eq!(
        error.kind(),
        dope_quic::conn::stream::recv::hold::ErrorKind::ForeignConnection
    );
    let credit = error.into_inner();
    assert_eq!(credit.len(), 5);
    client_a
        .release(credit)
        .expect("returned credit retains its first connection owner");
}

#[test]
fn segments_cross_stream() {
    let (mut server, mut client, mut work) =
        Pair::try_default().expect("connected peers").into_parts();
    let stream = server
        .send_streams()
        .open_bidi()
        .expect("server can open a bidirectional stream");
    let peer = Bind::bind(stream, &client).expect("peer stream");
    let prefix = (send::Buffer::inline(b"frame-")).expect("frame prefix fits inline storage");
    assert!(matches!(
        server.send_streams().try_buffer(stream, prefix),
        SendOutcome::Accepted
    ));
    assert!(matches!(
        server.send_streams().try_buffer(
            stream,
            send::Buffer::Retained(
                storage::Shared::try_copy(b"body").expect("retained fixture body")
            ),
        ),
        SendOutcome::Accepted
    ));
    server
        .send_streams()
        .finish(stream)
        .expect("server can finish the open stream");

    Receiver::receive_from(&mut client, &mut work, &mut server, Instant::now())
        .expect("peer packet transfer");

    assert_eq!(
        client
            .recv()
            .recv_owned(peer)
            .expect("client can move the combined stream batch")
            .as_deref(),
        Some(&b"frame-body"[..])
    );
    assert!(
        client
            .stream_state()
            .recv_eof(peer)
            .expect("peer stream remains addressable at EOF")
    );
}

#[test]
fn recv_retire_keeps_send() {
    let (mut server, mut client, mut work) =
        Pair::try_default().expect("connected peers").into_parts();
    let stream = client
        .send_streams()
        .open_bidi()
        .expect("client can open a bidirectional stream");
    let peer = Bind::bind(stream, &server).expect("peer stream");
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
    assert!(
        server
            .stream_state()
            .recv_eof(peer)
            .expect("peer stream remains addressable after receive retirement")
    );

    server
        .send_streams()
        .send(peer, b"response")
        .expect("retired receive half leaves the send half open");
    server
        .send_streams()
        .finish(peer)
        .expect("server can finish its send half");
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    assert_eq!(
        client
            .recv()
            .recv_owned(stream)
            .expect("client can move the response batch")
            .as_deref(),
        Some(&b"response"[..])
    );
    assert!(
        client
            .stream_state()
            .recv_eof(stream)
            .expect("local stream remains addressable at EOF")
    );
}

#[test]
fn stop_returns_reset() {
    let (mut server, mut client, mut work) =
        Pair::try_default().expect("connected peers").into_parts();
    let stream = server
        .send_streams()
        .open_bidi()
        .expect("server can open a bidirectional stream");
    let peer = Bind::bind(stream, &client).expect("peer stream");
    server
        .send_streams()
        .send(stream, b"unwanted")
        .expect("server can send the unwanted batch");
    let now = Instant::now();
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    assert!(
        client.poll().poll_event()
            == Some(Event::Readable {
                stream_id: peer.into()
            })
    );
    client
        .recv()
        .stop(peer, Code::from_u8(0x99))
        .expect("client can stop its open receive half");
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");
    assert!(
        server
            .stream_state()
            .stopped(stream)
            .expect("local stream remains addressable after STOP_SENDING")
            == Some(Code::from_u8(0x99))
    );
    Receiver::receive_from(&mut client, &mut work, &mut server, now).expect("peer packet transfer");
    assert!(
        client.poll().poll_event()
            == Some(Event::Reset {
                stream_id: peer.into(),
                error_code: dope_quic::errors::Code::from_u8(0x99),
            })
    );
    assert!(
        client
            .stream_state()
            .recv_eof(peer)
            .expect("stopped peer stream remains addressable at EOF")
    );
}

#[test]
fn reset_replaces_readable() {
    let (mut server, mut client, mut work) =
        Pair::try_default().expect("connected peers").into_parts();
    let stream = client
        .send_streams()
        .open_bidi()
        .expect("client can open a bidirectional stream");
    let peer = Bind::bind(stream, &server).expect("peer stream");
    let now = Instant::now();

    client
        .send_streams()
        .send(stream, b"partial")
        .expect("client can send the partial batch");
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");
    assert!(server.stream_state().has_events());

    client
        .send_streams()
        .reset(
            stream,
            errors::Code::new(0x51).expect("0x51 is a QUIC application code"),
        )
        .expect("client can reset the open stream");
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");

    assert!(
        server.poll().poll_event()
            == Some(Event::Reset {
                stream_id: peer.into(),
                error_code: dope_quic::errors::Code::from_u8(0x51),
            })
    );
    assert!(server.poll().poll_event().is_none());
}
