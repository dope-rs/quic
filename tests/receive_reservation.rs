use crate::common::peer;
pub mod common;

use common::suite::peers::receive::Receive;
use dope_test::alloc::Tracker;
use peer::Scope as _;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn empty_keeps_allocation() {
    let mut certs = Vec::new();
    let mut fixture = Receive::try_new(|cause| certs.push(format!("{cause:?}")))
        .expect("established stream fixture");
    let mut first = fixture.try_send(b"first").expect("fixture stream output");
    assert!(!first.is_empty());
    fixture.deliver(&mut first).expect("first stream packet");
    let mut dst = Vec::with_capacity(128);
    let pointer = dst.as_ptr();
    let capacity = dst.capacity();
    assert_eq!(
        fixture.pair.server.recv().recv(fixture.peer, &mut dst),
        Ok(5)
    );
    assert_eq!(dst, b"first");

    let mut second = fixture.try_send(b"second").expect("fixture stream output");
    assert!(!second.is_empty());
    let pointers = second.iter().map(Vec::as_ptr).collect::<Vec<_>>();
    let (result, activity) = Tracker::activity(|| fixture.deliver(&mut second));
    result.expect("the receiver retains its empty dst allocation");
    assert_eq!(activity.allocations, 0);
    assert_eq!(activity.deallocations, 0);
    for (packet, source) in second.iter().zip(pointers) {
        assert_eq!(packet.as_ptr(), source);
    }
    let received = fixture
        .pair
        .server
        .recv()
        .recv_owned(fixture.peer)
        .expect("bound stream")
        .expect("second payload");
    assert_eq!(received, b"second");
    assert_eq!(received.as_ptr(), pointer);
    assert_eq!(received.capacity(), capacity);
    drop(fixture);
    assert!(certs.is_empty(), "{certs:?}");
}

#[test]
fn nonempty_keeps_owner() {
    let mut certs = Vec::new();
    let mut fixture = Receive::try_new(|cause| certs.push(format!("{cause:?}")))
        .expect("established stream fixture");
    let mut warm = fixture.try_send(b"warm").expect("fixture stream output");
    fixture.deliver(&mut warm).expect("warm stream packet");
    let mut dst = Vec::with_capacity(128);
    let pointer = dst.as_ptr();
    let capacity = dst.capacity();
    assert_eq!(
        fixture.pair.server.recv().recv(fixture.peer, &mut dst),
        Ok(4)
    );

    let mut first = fixture.try_send(b"first").expect("fixture stream output");
    fixture.deliver(&mut first).expect("first buffered payload");
    let mut second = fixture.try_send(b"second").expect("fixture stream output");
    assert!(!second.is_empty());
    let pointers = second.iter().map(Vec::as_ptr).collect::<Vec<_>>();
    let (result, activity) = Tracker::activity(|| fixture.deliver(&mut second));
    result.expect("the receiver appends to its nonempty dst allocation");
    assert_eq!(activity.allocations, 0);
    assert_eq!(activity.deallocations, 0);
    for (packet, source) in second.iter().zip(pointers) {
        assert_eq!(packet.as_ptr(), source);
    }
    let received = fixture
        .pair
        .server
        .recv()
        .recv_owned(fixture.peer)
        .expect("bound stream")
        .expect("both buffered payloads");
    assert_eq!(received, b"firstsecond");
    assert_eq!(received.as_ptr(), pointer);
    assert_eq!(received.capacity(), capacity);
    drop(fixture);
    assert!(certs.is_empty(), "{certs:?}");
}

#[test]
fn failed_growth_keeps_data() {
    use common::suite::peers::receive::Rejected;
    use dope_quic::stream::Capacity;
    use o3::alloc;

    let mut certs = Vec::new();
    let mut fixture = Receive::try_new(|cause| certs.push(format!("{cause:?}")))
        .expect("established stream fixture");
    let mut warm = fixture.try_send(b"warm").expect("fixture stream output");
    fixture.deliver(&mut warm).expect("warm stream packet");
    let mut dst = Vec::with_capacity(8);
    let pointer = dst.as_ptr();
    let capacity = dst.capacity();
    assert_eq!(
        fixture.pair.server.recv().recv(fixture.peer, &mut dst),
        Ok(4)
    );
    let mut first = fixture.try_send(b"kept").expect("fixture stream output");
    fixture
        .deliver(&mut first)
        .expect("buffered stream payload");

    let mut packets = fixture
        .try_send(&[0x53; 512])
        .expect("fixture stream output");
    assert_eq!(packets.len(), 1);
    let mut replay = packets.clone();
    let source = packets[0].as_ptr();
    let mut alerts = Vec::new();
    let mut rejected = Rejected::new(|cause| alerts.push(format!("{cause:?}")));
    let (result, activity) = Tracker::activity(|| {
        Tracker::fail_after(0, || {
            fixture.pair.server.with_scope(|mut scope| {
                scope.input(&mut fixture.pair.work).recv_with(
                    &mut packets[0],
                    fixture.at,
                    &mut rejected,
                )
            })
        })
    });
    result.expect("a resource rejection drops the uncommitted packet");
    assert_eq!(rejected.observed, 1);
    assert!(rejected.unexpected.is_none(), "{:?}", rejected.unexpected);
    assert_eq!(
        rejected.error,
        Some(Capacity::Allocation {
            error: alloc::Error::Exhausted,
            requested: 512,
        })
    );
    assert_eq!(rejected.id, Some(fixture.peer.id()));
    drop(rejected);
    assert!(alerts.is_empty(), "{alerts:?}");
    assert_eq!(activity.allocations, 0);
    assert_eq!(activity.deallocations, 0);
    assert_eq!(packets[0].as_ptr(), source);
    let received = fixture
        .pair
        .server
        .recv()
        .recv_owned(fixture.peer)
        .expect("bound receiver remains installed")
        .expect("previous payload remains available");
    assert_eq!(received, b"kept");
    assert_eq!(received.as_ptr(), pointer);
    assert_eq!(received.capacity(), capacity);
    fixture
        .deliver(&mut replay)
        .expect("uncommitted packet remains retryable");
    let received = fixture
        .pair
        .server
        .recv()
        .recv_owned(fixture.peer)
        .expect("same receiver after retry")
        .expect("the retried payload is delivered once");
    assert_eq!(received, [0x53; 512]);
    drop(fixture);
    assert!(certs.is_empty(), "{certs:?}");
}

#[test]
fn fresh_keeps_cache() {
    use common::suite::peers::receive::Rejected;
    use dope_quic::stream::Capacity;
    use o3::alloc;

    let mut certs = Vec::new();
    let mut fixture = Receive::try_new(|cause| certs.push(format!("{cause:?}")))
        .expect("established stream fixture");
    let mut warm = fixture.try_send(b"warm").expect("fixture stream output");
    fixture.deliver(&mut warm).expect("warm stream packet");
    let mut dst = Vec::with_capacity(128);
    let pointer = dst.as_ptr();
    let capacity = dst.capacity();
    assert_eq!(
        fixture.pair.server.recv().recv(fixture.peer, &mut dst),
        Ok(4)
    );
    fixture
        .pair
        .client
        .send_streams()
        .send(fixture.stream, b"done")
        .expect("final payload");
    fixture
        .pair
        .client
        .send_streams()
        .finish(fixture.stream)
        .expect("final boundary");
    let mut packets = fixture.try_flush().expect("fixture pending output");
    fixture
        .deliver(&mut packets)
        .expect("completed stream packet");
    assert_eq!(
        fixture.pair.server.recv().recv(fixture.peer, &mut dst),
        Ok(4)
    );
    assert_eq!(dst, b"warmdone");
    assert_eq!(
        fixture.pair.server.stream_state().recv_eof(fixture.peer),
        Ok(true)
    );

    fixture.try_open().expect("next fixture stream");
    let mut packets = fixture
        .try_send(&[0x53; 512])
        .expect("fixture stream output");
    assert_eq!(packets.len(), 1);
    let mut alerts = Vec::new();
    let mut rejected = Rejected::new(|cause| alerts.push(format!("{cause:?}")));
    let (result, activity) = Tracker::activity(|| {
        Tracker::fail_after(0, || {
            fixture.pair.server.with_scope(|mut scope| {
                scope.input(&mut fixture.pair.work).recv_with(
                    &mut packets[0],
                    fixture.at,
                    &mut rejected,
                )
            })
        })
    });
    result.expect("fresh receiver preparation rejects before commit");
    assert_eq!(rejected.observed, 1);
    assert!(rejected.unexpected.is_none(), "{:?}", rejected.unexpected);
    assert_eq!(
        rejected.error,
        Some(Capacity::Allocation {
            error: alloc::Error::Exhausted,
            requested: 512,
        })
    );
    assert_eq!(rejected.id, Some(fixture.peer.id()));
    drop(rejected);
    assert!(alerts.is_empty(), "{alerts:?}");
    assert_eq!(activity.allocations, 0);
    assert_eq!(activity.deallocations, 0);
    assert_eq!(
        fixture.pair.server.recv().recv_owned(fixture.peer),
        Ok(None)
    );

    fixture.try_open().expect("next fixture stream");
    let mut packets = fixture
        .try_send(&[0x54; 64])
        .expect("fixture stream output");
    assert!(!packets.is_empty());
    let (result, activity) = Tracker::activity(|| fixture.deliver(&mut packets));
    result.expect("next receiver reuses the returned warm slot");
    assert_eq!(activity.allocations, 0);
    assert_eq!(activity.deallocations, 0);
    let received = fixture
        .pair
        .server
        .recv()
        .recv_owned(fixture.peer)
        .expect("next receiver remains bound")
        .expect("next receiver committed its exact bytes");
    assert_eq!(received, [0x54; 64]);
    assert_eq!(received.as_ptr(), pointer);
    assert_eq!(received.capacity(), capacity);
    drop(fixture);
    assert!(certs.is_empty(), "{certs:?}");
}

#[test]
fn empty_fin_without_alloc() {
    let mut certs = Vec::new();
    let mut fixture = Receive::try_new(|cause| certs.push(format!("{cause:?}")))
        .expect("established stream fixture");
    let mut warm = fixture.try_flush().expect("fixture pending output");
    fixture
        .deliver(&mut warm)
        .expect("drain handshake and control flights before STREAM frames");
    fixture
        .pair
        .client
        .send_streams()
        .finish(fixture.stream)
        .expect("empty final boundary");
    let mut packets = fixture.try_flush().expect("fixture pending output");
    assert_eq!(packets.len(), 1);
    let pointer = packets[0].as_ptr();
    let (result, activity) =
        Tracker::activity(|| Tracker::fail_after(0, || fixture.deliver(&mut packets)));
    result.expect("empty FIN needs no receive allocation");
    assert_eq!(activity.allocations, 0);
    assert_eq!(activity.deallocations, 0);
    assert_eq!(packets[0].as_ptr(), pointer);
    assert_eq!(
        fixture.pair.server.stream_state().recv_eof(fixture.peer),
        Ok(true)
    );
    assert_eq!(
        fixture.pair.server.recv().recv_owned(fixture.peer),
        Ok(None)
    );
    drop(fixture);
    assert!(certs.is_empty(), "{certs:?}");
}

#[test]
fn rejection_keeps_fin() {
    use common::suite::peers::receive::Rejected;
    use dope_quic::stream::Capacity;
    use o3::alloc;

    let mut certs = Vec::new();
    let mut fixture = Receive::try_new(|cause| certs.push(format!("{cause:?}")))
        .expect("established stream fixture");
    let mut warm = fixture.try_flush().expect("fixture pending output");
    fixture
        .deliver(&mut warm)
        .expect("drain handshake and control flights before STREAM frames");
    let first = fixture.peer;
    fixture
        .pair
        .client
        .send_streams()
        .finish(fixture.stream)
        .expect("first empty final boundary");
    fixture.try_open().expect("next fixture stream");
    let mut packets = fixture
        .try_send(&[0x75; 512])
        .expect("fixture stream output");
    assert_eq!(packets.len(), 1);
    let mut replay = packets.clone();
    let mut alerts = Vec::new();
    let mut rejected = Rejected::new(|cause| alerts.push(format!("{cause:?}")));
    let (result, activity) = Tracker::activity(|| {
        Tracker::fail_after(0, || {
            fixture.pair.server.with_scope(|mut scope| {
                scope.input(&mut fixture.pair.work).recv_with(
                    &mut packets[0],
                    fixture.at,
                    &mut rejected,
                )
            })
        })
    });
    result.expect("resource rejection drops the complete uncommitted packet");
    assert_eq!(rejected.observed, 1);
    assert!(rejected.unexpected.is_none(), "{:?}", rejected.unexpected);
    assert_eq!(
        rejected.error,
        Some(Capacity::Allocation {
            error: alloc::Error::Exhausted,
            requested: 512,
        })
    );
    assert_eq!(rejected.id, Some(fixture.peer.id()));
    drop(rejected);
    assert!(alerts.is_empty(), "{alerts:?}");
    assert_eq!(activity.allocations, 0);
    assert_eq!(
        fixture.pair.server.stream_state().recv_eof(first),
        Ok(false)
    );
    assert_eq!(
        fixture.pair.server.recv().recv_owned(fixture.peer),
        Ok(None)
    );
    fixture
        .deliver(&mut replay)
        .expect("both stream frames remain retryable");
    assert_eq!(fixture.pair.server.stream_state().recv_eof(first), Ok(true));
    let bytes = fixture
        .pair
        .server
        .recv()
        .recv_owned(fixture.peer)
        .expect("second stream remains bound")
        .expect("second payload commits after replay");
    assert_eq!(bytes, [0x75; 512]);
    drop(fixture);
    assert!(certs.is_empty(), "{certs:?}");
}
