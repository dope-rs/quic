pub mod common;
use crate::common::peer;
use common::suite::peers::receive::datagram;
use std::time::{Duration, Instant};

use dope_quic::conn::Epoch;
use dope_quic::conn::wire::packet::Batch;
use dope_test::alloc::Tracker;
use peer::Pair;
use peer::Receiver as _;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

fn drain(pair: &mut Pair, start: Instant) -> Instant {
    let now = datagram::try_settle(pair, start).expect("settle peer acknowledgments");
    assert_eq!(pair.client.view().recovery().unacked(Epoch::Application), 0,);
    assert_eq!(pair.server.view().recovery().unacked(Epoch::Application), 0,);
    now
}

#[test]
fn ack_bypasses_full_cwnd() {
    let mut pair = Pair::try_default().expect("test precondition");
    let settled = drain(&mut pair, Instant::now() + Duration::from_secs(1));
    let mut now = settled + Duration::from_secs(1);
    let Pair {
        mut server,
        mut client,
        mut work,
    } = pair;

    for byte in 0..128_u8 {
        client
            .with_scope(|mut scope| scope.datagrams().try_send(vec![byte; 1_100]))
            .expect("128 fixture datagrams must fit the warmed client queue");
    }
    let mut batch = Batch::default();
    for _ in 0..64 {
        client
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 64, 1_200))
            .expect("warmed congestion fixture journals must admit output");
        if client.view().recovery().in_flight() >= client.view().recovery().window() {
            break;
        }
        now = client
            .view()
            .recovery()
            .send_at(now + Duration::from_nanos(1));
    }
    assert!(!batch.is_empty());
    let full = client.view().recovery().in_flight();
    assert!(
        full >= client.view().recovery().window(),
        "test must close the congestion window: in_flight={full}, cwnd={}",
        client.view().recovery().window(),
    );

    server
        .with_scope(|mut scope| scope.datagrams().try_send(vec![0x7a]))
        .expect("the one-byte ACK stimulus must fit the warmed server queue");
    let mut stimulus = Batch::default();
    server
        .with_scope(|mut scope| scope.output().send_batch(&mut stimulus, now, 1, 1_200))
        .expect("warmed server journals must admit ACK stimulus");
    assert_eq!(stimulus.packets(), 1);
    assert_eq!(server.view().recovery().unacked(Epoch::Application), 1,);
    assert!(client.receive_all(&mut work, &mut stimulus, now).is_ok());
    let ack_at = now + Duration::from_millis(25);

    let measure = Tracker::begin();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, ack_at, 1, 1_200))
        .expect("warmed client journals must admit ACK-only output");
    let activity = measure.finish();
    assert_eq!(
        batch.packets(),
        1,
        "ACK-only output must not wait for a cwnd or pacer release",
    );
    assert_eq!(
        activity.allocations, 0,
        "a warmed ACK-only transaction must not allocate",
    );
    assert_eq!(
        client.view().recovery().in_flight(),
        full,
        "the bypass packet must contain no queued DATAGRAM/STREAM/control work",
    );

    assert!(server.receive_all(&mut work, &mut batch, ack_at).is_ok());
    assert_eq!(
        server.view().recovery().unacked(Epoch::Application),
        0,
        "the emitted packet must acknowledge the exact Application PN space",
    );
}

#[test]
fn failed_seal_keeps_ack() {
    let mut pair = Pair::try_default().expect("test precondition");
    let now = drain(&mut pair, Instant::now() + Duration::from_secs(1)) + Duration::from_secs(1);
    let Pair {
        mut server,
        mut client,
        mut work,
    } = pair;

    server
        .with_scope(|mut scope| scope.datagrams().try_send(vec![0x41]))
        .expect("the one-byte retry stimulus must fit the warmed server queue");
    let mut stimulus = Batch::default();
    server
        .with_scope(|mut scope| scope.output().send_batch(&mut stimulus, now, 1, 1_200))
        .expect("warmed server journals must admit retry stimulus");
    assert_eq!(stimulus.packets(), 1);
    assert!(client.receive_all(&mut work, &mut stimulus, now).is_ok());
    let ack_at = now + Duration::from_millis(25);

    let mut ack = Batch::default();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut ack, ack_at, 1, 1))
        .expect("warmed client journals must admit the failed-seal attempt");
    assert!(
        ack.is_empty(),
        "an unsealable ACK must not publish bytes or commit receive state",
    );

    client
        .with_scope(|mut scope| scope.output().send_batch(&mut ack, ack_at, 1, 1_200))
        .expect("warmed client journals must admit the retained ACK");
    assert_eq!(
        ack.packets(),
        1,
        "the lifetime-bound ACK intent must survive an aborted packet transaction",
    );
    assert!(server.receive_all(&mut work, &mut ack, ack_at).is_ok());
    assert_eq!(server.view().recovery().unacked(Epoch::Application), 0,);
}
