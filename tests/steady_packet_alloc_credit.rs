use crate::common::peer;
use common::suite::peers::config::Parameters as _;
pub mod common;
use dope_quic::conn::life::options::Options;
use std::time::{Duration, Instant};

use dope_quic::conn::stream::SendOutcome;
use dope_quic::errors::Code;
use dope_quic::stream::send;
use dope_test::alloc::Tracker;
use peer::Bind as _;
use peer::Event;
use peer::Pair;
use peer::Scope as _;

#[test]
fn held_release() {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_new(
        Options::try_steady().expect("allocation fixture transport parameters"),
        Options::try_steady().expect("allocation fixture transport parameters"),
    )
    .expect("test precondition");
    let stream = server
        .send_streams()
        .open_uni()
        .expect("fixture server must retain one unidirectional stream slot");
    let peer = stream.bind(&client);
    let peer = (peer).expect("test precondition");
    server
        .send_streams()
        .send(stream, b"held receive")
        .expect("fixture stream credit must accept the held payload");
    server
        .send_streams()
        .finish(stream)
        .expect("fixture send stream must finish once");
    let now = Instant::now() + Duration::from_secs(1);
    for mut packet in server.with_scope(|mut scope| {
        let (packets, result) = scope.output().send(now);
        result.expect("warmed server journals must admit the held-receive packet");
        packets
    }) {
        assert!(
            client
                .with_scope(|mut scope| {
                    scope
                        .input(&mut work)
                        .recv_packet(&mut packet, now, |_: &rustls::Error| {})
                })
                .is_ok(),
            "server packet must pass paired client ingress"
        );
    }

    let sample = Tracker::begin();
    let buffer = client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let stream = streams
            .view()
            .resolve_recv(peer.id())
            .expect("peer stream ID must resolve to its receive state");
        let mut receive = streams.receive();
        let held = receive
            .hold(stream)
            .expect("delivered stream payload must detach from receive state");
        let (buffer, credit) = held.into_parts();
        let credit = credit.release_conn(&mut receive);
        credit.release(&mut receive);
        buffer
    });
    let activity = sample.finish();

    assert_eq!(buffer, b"held receive");
    assert_eq!(
        activity.allocations, 0,
        "held receive allocation size {}",
        activity.allocated_bytes
    );
}

#[test]
fn send_budget() {
    let pair = Pair::try_new(
        Options::try_credit().expect("fixture configuration bounds"),
        Options::try_credit().expect("fixture configuration bounds"),
    );
    let mut client = pair.expect("test precondition").client;
    let active = client
        .send_streams()
        .open_bidi()
        .expect("fixture client must retain its active bidirectional stream slot");
    let retry = client
        .send_streams()
        .open_bidi()
        .expect("fixture client must retain its retry bidirectional stream slot");
    let [first, next] = [0x71, 0x72]
        .map(|byte| send::Buffer::inline(&[byte]).expect("one byte must fit inline send storage"));
    assert!(matches!(
        client.send_streams().try_buffer(active, first),
        SendOutcome::Accepted
    ));
    let outcome = client.send_streams().try_buffer(retry, next);
    assert!(matches!(outcome, SendOutcome::Blocked(_)));
    let SendOutcome::Blocked(owner) = outcome else {
        return;
    };

    let sample = Tracker::begin();
    assert!(
        client
            .send_streams()
            .reset(active, Code::from_u8(0x73))
            .is_ok(),
        "active stream reset must release its send budget"
    );
    assert!(client.poll().poll_event() == Some(Event::Writable));
    assert!(matches!(
        client.send_streams().try_buffer(retry, owner),
        SendOutcome::Accepted
    ));
    let activity = sample.finish();

    assert_eq!(
        activity.allocations, 0,
        "send retry allocation size {}",
        activity.allocated_bytes
    );
}

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();
