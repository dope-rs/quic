use std::time::{Duration, Instant};

use dope_quic::conn::output::transmit::{Admission, Error};
use dope_quic::errors::SendFailure;
use dope_test::alloc::Tracker;

pub mod common;
use common::peer::Pair;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn queue_alloc_retry() {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_default().expect("fixture peers must establish");
    let payload = vec![0x51; 32];
    let pointer = payload.as_ptr();
    let capacity = payload.capacity();
    let failed = Tracker::fail_after(0, || {
        client.with_scope(|mut scope| scope.datagrams().try_send(payload))
    })
    .expect_err("queue allocation must fail");
    let (payload, error) = match failed {
        SendFailure::Admission(payload, error) => Some((payload, error)),
        _ => None,
    }
    .expect("queue allocation must return admission failure");
    assert!(matches!(error, Admission::Datagrams(_)));
    assert_eq!(payload.as_ptr(), pointer);
    assert_eq!(payload.capacity(), capacity);
    assert_eq!(payload, [0x51; 32]);
    client
        .with_scope(|mut scope| scope.datagrams().try_send(payload))
        .expect("retry must retain queue capacity and byte credit");
    let now = client
        .view()
        .recovery()
        .send_at(Instant::now() + Duration::from_secs(1));
    for mut packet in client.with_scope(|mut scope| {
        let (packets, result) = scope.output().send(now);
        result.expect("retry output");
        packets
    }) {
        server
            .with_scope(|mut scope| scope.input(&mut work).recv_packet(&mut packet, now, |_| {}))
            .expect("retry packet must authenticate");
    }
    assert_eq!(
        server
            .with_scope(|mut scope| scope.datagrams().recv())
            .as_deref(),
        Some([0x51; 32].as_slice()),
    );
    assert!(
        server
            .with_scope(|mut scope| scope.datagrams().recv())
            .is_none()
    );
}

#[test]
fn datagram_alloc_retry() {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_default().expect("fixture peers must establish");
    let payload = [0x51; 32];
    client
        .with_scope(|mut scope| scope.datagrams().try_send(payload.to_vec()))
        .expect("fixture datagram fits the queue");
    let now = client
        .view()
        .recovery()
        .send_at(Instant::now() + Duration::from_secs(1));
    let timer = client.view().recovery().next_timer();
    let (packets, result) = Tracker::fail_after(0, || {
        client.with_scope(|mut scope| scope.output().send(now))
    });
    let error = result.expect_err("packet-list allocation must return its exact failure");
    assert!(packets.is_empty());
    assert_eq!(
        error,
        Error::Admission(Admission::Packets {
            error: o3::alloc::Error::Exhausted,
            requested: 1,
        })
    );
    assert_eq!(client.view().recovery().next_timer(), timer);

    for mut packet in client.with_scope(|mut scope| {
        let (packets, result) = scope.output().send(now);
        result.expect("retry must retain the queued datagram");
        packets
    }) {
        server
            .with_scope(|mut scope| scope.input(&mut work).recv_packet(&mut packet, now, |_| {}))
            .expect("retry packet must authenticate");
    }
    assert_eq!(
        server.with_scope(|mut scope| scope.datagrams().recv()),
        Some(payload.to_vec())
    );
    assert!(
        server
            .with_scope(|mut scope| scope.datagrams().recv())
            .is_none()
    );
}
