use crate::common::peer;
pub mod common;
use std::time::{Duration, Instant};

use dope_quic::conn::wire::packet::Batch;
use dope_test::alloc::Tracker;
use peer::Bind as _;
use peer::Event;
use peer::Pair;
use peer::Scope as _;

#[test]
fn first_receive() {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_default().expect("test precondition");
    let stream = client
        .send_streams()
        .open_uni()
        .expect("fixture client must retain its first unidirectional stream slot");
    let peer = stream.bind(&server);
    let peer = (peer).expect("test precondition");
    client
        .send_streams()
        .finish(stream)
        .expect("first send stream must finish once");
    let now = Instant::now() + Duration::from_secs(4);
    let (mut packets, result) = client.with_scope(|mut scope| scope.output().send(now));
    result.expect("fresh client journals must admit the first stream packet");
    assert!(!packets.is_empty());

    let sample = Tracker::begin();
    for packet in &mut packets {
        assert!(
            server
                .with_scope(|mut scope| {
                    scope
                        .input(&mut work)
                        .recv_packet(packet, now, |_: &rustls::Error| {})
                })
                .is_ok(),
            "first stream packet must pass server ingress"
        );
    }
    let activity = sample.finish();

    assert!(server.poll().poll_event() == Some(Event::Readable { stream_id: peer }));
    assert_eq!(
        activity.allocations, 0,
        "first receive-stream state allocation size {}",
        activity.allocated_bytes
    );
}

/// Retiring the stream returns its indexed state while retaining the
/// contiguous receive allocation for the next stream on this connection.
#[test]
fn recycled_receive() {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_default().expect("test precondition");
    let now = Instant::now() + Duration::from_secs(4);
    let first = client
        .send_streams()
        .open_uni()
        .expect("first unidirectional stream slot must be available");
    let srv_old = first.bind(&server);
    let srv_old = (srv_old).expect("test precondition");
    client
        .send_streams()
        .send(first, &[0x51; 512])
        .expect("first stream credit must admit its payload");
    client
        .send_streams()
        .finish(first)
        .expect("first send stream must finish once");
    let (mut packets, result) = client.with_scope(|mut scope| scope.output().send(now));
    result.expect("fresh client journals must admit the first recycled stream packet");
    assert!(!packets.is_empty());
    for packet in &mut packets {
        assert!(
            server
                .with_scope(|mut scope| {
                    scope
                        .input(&mut work)
                        .recv_packet(packet, now, |_: &rustls::Error| {})
                })
                .is_ok(),
            "first stream packet must pass server ingress"
        );
    }
    assert!(server.poll().poll_event() == Some(Event::Readable { stream_id: srv_old }));

    let mut received = vec![0];
    assert_eq!(server.recv().recv(srv_old, &mut received), Ok(512));
    assert!(
        server
            .stream_state()
            .recv_eof(srv_old)
            .expect("completed first receive stream must retain state")
    );

    let second = client
        .send_streams()
        .open_uni()
        .expect("retired first stream slot must admit a second stream");
    let srv_next = second.bind(&server);
    let srv_next = (srv_next).expect("test precondition");
    client
        .send_streams()
        .send(second, &[0x52; 128])
        .expect("second stream credit must admit its payload");
    client
        .send_streams()
        .finish(second)
        .expect("second send stream must finish once");
    let at = now + Duration::from_millis(1);
    let (mut packets, result) = client.with_scope(|mut scope| scope.output().send(at));
    result.expect("warmed client journals must admit the second recycled stream packet");
    assert!(!packets.is_empty());

    let sample = Tracker::begin();
    for packet in &mut packets {
        assert!(
            server
                .with_scope(|mut scope| {
                    scope
                        .input(&mut work)
                        .recv_packet(packet, at, |_: &rustls::Error| {})
                })
                .is_ok(),
            "second stream packet must pass server ingress"
        );
    }
    let activity = sample.finish();

    assert!(
        server.poll().poll_event()
            == Some(Event::Readable {
                stream_id: srv_next,
            })
    );
    assert_eq!(
        activity.allocations, 0,
        "recycled receive-stream allocation size {}",
        activity.allocated_bytes
    );
}

/// A non-empty destination makes Receiver retain its warmed allocation.
#[test]
fn recurring_event() {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_default().expect("test precondition");
    let stream = client
        .send_streams()
        .open_bidi()
        .expect("fixture client must retain a bidirectional stream slot");
    let peer = stream.bind(&server);
    let peer = (peer).expect("test precondition");
    let now = Instant::now() + Duration::from_secs(3);

    client
        .send_streams()
        .send(stream, &[0x41; 512])
        .expect("first recurring payload must fit stream credit");
    let (packets, result) = client.with_scope(|mut scope| scope.output().send(now));
    result.expect("fresh client journals must admit the first recurring stream packet");
    let mut first = packets
        .into_iter()
        .next()
        .expect("first recurring payload must emit a packet");
    assert!(
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut first, now, |_: &rustls::Error| {})
            })
            .is_ok(),
        "first recurring stream packet must pass server ingress"
    );
    assert!(
        server.poll().poll_event()
            == Some(Event::Readable {
                stream_id: peer.receive(),
            })
    );

    let mut received = vec![0];
    assert_eq!(server.recv().recv(peer, &mut received), Ok(512));
    received.clear();

    client
        .send_streams()
        .send(stream, &[0x42; 128])
        .expect("second recurring payload must fit stream credit");
    let at = now + Duration::from_millis(1);
    let (packets, result) = client.with_scope(|mut scope| scope.output().send(at));
    result.expect("warmed client journals must admit the second recurring stream packet");
    let mut second = packets
        .into_iter()
        .next()
        .expect("second recurring payload must emit a packet");

    let sample = Tracker::begin();
    assert!(
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut second, at, |_: &rustls::Error| {})
            })
            .is_ok(),
        "second recurring stream packet must pass server ingress"
    );
    let activity = sample.finish();

    assert!(
        server.poll().poll_event()
            == Some(Event::Readable {
                stream_id: peer.receive(),
            })
    );
    assert_eq!(
        activity.allocations, 0,
        "recurring stream event allocation size {}",
        activity.allocated_bytes
    );
}

#[test]
fn ack_generation() {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_default().expect("test precondition");
    let stream = client
        .send_streams()
        .open_bidi()
        .expect("fixture client must retain a bidirectional stream slot");
    let now = Instant::now() + Duration::from_secs(5);

    client
        .send_streams()
        .send(stream, &[0x31; 2_048])
        .expect("fragmented payload must fit stream credit");
    let (mut packets, result) = client.with_scope(|mut scope| scope.output().send(now));
    result.expect("fresh client journals must admit fragmented stream packets");
    assert!(packets.len() >= 2);
    assert!(
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut packets[0], now, |_: &rustls::Error| {})
            })
            .is_ok(),
        "first fragmented stream packet must pass server ingress"
    );

    let delay = Duration::from_millis(u64::from(
        client
            .view()
            .peer()
            .params()
            .expect("server transport parameters")
            .timing()
            .ack_ms(),
    ));
    let mut batch = Batch::default();
    server
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, now + delay, 1, 1_200))
        .expect("fresh server journals must admit the first stream acknowledgement");
    assert_eq!(batch.packets(), 1);

    client
        .send_streams()
        .send(stream, &[0x32; 128])
        .expect("follow-up payload must fit stream credit");
    let at = now + delay + Duration::from_millis(1);
    let (packets, result) = client.with_scope(|mut scope| scope.output().send(at));
    result.expect("warmed client journals must admit the follow-up stream packet");
    let mut packet = packets
        .into_iter()
        .next()
        .expect("follow-up payload must emit a packet");
    assert!(
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut packet, at, |_: &rustls::Error| {})
            })
            .is_ok(),
        "follow-up stream packet must pass server ingress"
    );

    let sample = Tracker::begin();
    server
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, at + delay, 1, 1_200))
        .expect("warmed server journals must admit the measured stream acknowledgement");
    let activity = sample.finish();

    assert_eq!(batch.packets(), 1);
    assert_eq!(
        activity.allocations, 0,
        "ACK generation allocation size {}",
        activity.allocated_bytes
    );
}

#[test]
fn out_of_order_ack() {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_default().expect("test precondition");
    let stream = client
        .send_streams()
        .open_bidi()
        .expect("fixture client must retain a bidirectional stream slot");
    let peer = stream.bind(&server);
    let peer = (peer).expect("test precondition");
    client
        .send_streams()
        .send(stream, &[0x6b; 8192])
        .expect("fragmented payload must fit stream credit");
    client
        .send_streams()
        .finish(stream)
        .expect("fragmented send stream must finish once");
    let now = Instant::now() + Duration::from_secs(10);
    let (mut packets, result) = client.with_scope(|mut scope| scope.output().send(now));
    result.expect("fresh client journals must admit fragmented out-of-order stream packets");
    assert!(packets.len() >= 3);
    let mut first = packets.remove(0);

    let mut split = false;
    for packet in packets.iter_mut() {
        let sample = Tracker::begin();
        assert!(
            server
                .with_scope(|mut scope| {
                    scope
                        .input(&mut work)
                        .recv_packet(packet, now, |_: &rustls::Error| {})
                })
                .is_ok(),
            "out-of-order stream packet must pass server ingress"
        );
        let activity = sample.finish();
        let count = activity.allocations;
        assert!(
            count <= 1,
            "out-of-order DATA allocated metadata in addition to its payload, last size {}",
            activity.allocated_bytes
        );
        split |= count == 1;
    }
    assert!(split, "the allocation proof must exercise a DATA gap");
    let (suffix, result) =
        server.with_scope(|mut scope| scope.output().send(now + Duration::from_millis(1)));
    result.expect("fresh server journals must admit the suffix acknowledgement");
    assert!(!suffix.is_empty());
    let sample = Tracker::begin();
    for mut packet in suffix {
        assert!(
            client
                .with_scope(|mut scope| {
                    scope.input(&mut work).recv_packet(
                        &mut packet,
                        now + Duration::from_millis(1),
                        |_: &rustls::Error| {},
                    )
                })
                .is_ok(),
            "suffix acknowledgement must pass client ingress"
        );
    }
    let activity = sample.finish();
    assert_eq!(
        activity.allocations, 0,
        "suffix ACK allocation size {}",
        activity.allocated_bytes
    );

    assert!(
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut first, now, |_: &rustls::Error| {})
            })
            .is_ok(),
        "missing stream prefix must pass server ingress"
    );
    let (prefix, result) =
        server.with_scope(|mut scope| scope.output().send(now + Duration::from_millis(2)));
    result.expect("warmed server journals must admit the prefix acknowledgement");
    assert!(!prefix.is_empty());
    let sample = Tracker::begin();
    for mut packet in prefix {
        assert!(
            client
                .with_scope(|mut scope| {
                    scope.input(&mut work).recv_packet(
                        &mut packet,
                        now + Duration::from_millis(2),
                        |_: &rustls::Error| {},
                    )
                })
                .is_ok(),
            "prefix acknowledgement must pass client ingress"
        );
    }
    let activity = sample.finish();
    assert_eq!(
        activity.allocations, 0,
        "prefix collapse allocation size {}",
        activity.allocated_bytes
    );
    assert_eq!(
        server
            .recv()
            .recv_owned(peer)
            .expect("completed stream must remain readable")
            .as_deref(),
        Some(&[0x6b; 8192][..])
    );
}

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();
