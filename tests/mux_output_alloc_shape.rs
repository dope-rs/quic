use dope_quic::{errors, runtime::mux::builder};
use dope_test::alloc::Tracker;
use std::{pin::Pin, time::Duration};

pub mod common;
use common::suite::mux::{dispatch::Capture, output::Seen};

#[test]
fn small_burst_stays_plain() {
    const CONNECTIONS: usize = 3;
    let (mut client, handles, now) =
        Seen::try_many(true, CONNECTIONS).expect("GSO fixture must establish");
    for &handle in &handles {
        Seen::enqueue(&mut client, handle, 1, 1_150, now).expect("output enqueue");
    }

    let burst = Pin::new(&mut client)
        .observe(now, |mut turn| {
            turn.output().drive()?;
            Ok::<Vec<_>, errors::Transmit>(turn.output().drain().collect())
        })
        .expect("fixture connections must admit the small burst");
    assert_eq!(burst.len(), CONNECTIONS);
    assert_eq!(Seen::packet_count(&burst), CONNECTIONS);
    assert!(burst.iter().all(|outgoing| !outgoing.is_segmented()));
}

#[test]
fn wire_shapes_stay_plain() {
    const CONNECTIONS: usize = 4;
    let (mut client, handles, now) =
        Seen::try_many(true, CONNECTIONS).expect("GSO fixture must establish");
    for (ordinal, &handle) in handles.iter().enumerate() {
        Seen::enqueue(&mut client, handle, 1, 1_100 + ordinal, now).expect("output enqueue");
    }

    let burst = Pin::new(&mut client)
        .observe(now, |mut turn| {
            turn.output().drive()?;
            Ok::<Vec<_>, errors::Transmit>(turn.output().drain().collect())
        })
        .expect("fixture connections must admit the varied wire shapes");
    assert_eq!(burst.len(), CONNECTIONS);
    assert_eq!(Seen::packet_count(&burst), CONNECTIONS);
    assert!(burst.iter().all(|outgoing| !outgoing.is_segmented()));
}

#[test]
fn reuses_owner() {
    for (gso, packets) in [(false, 1), (true, 4)] {
        let (mut client, handles, mut now) =
            Seen::try_many(gso, 1).expect("single connection fixture must establish");
        let [handle]: &[_; 1] = handles
            .as_slice()
            .try_into()
            .expect("single connection fixture must retain exactly one handle");
        let handle = *handle;
        let bytes = if gso { 1_150 } else { 64 };

        Seen::enqueue(&mut client, handle, packets, bytes, now).expect("output enqueue");
        let warm = Seen::take_one(&mut client, now)
            .expect("output take_one")
            .expect("the enqueued payload must produce one mux flight");
        assert_eq!(warm.is_segmented(), gso);
        let owner = warm.payload().as_ptr();
        Pin::new(&mut client).output().recycle(warm);

        now += Duration::from_millis(1);
        Seen::enqueue(&mut client, handle, packets, bytes, now).expect("output enqueue");
        let span = Tracker::begin();
        let measured = Seen::take_one(&mut client, now)
            .expect("output take_one")
            .expect("the enqueued payload must produce one mux flight");
        let activity = span.finish();

        assert_eq!(activity.allocations, 0);
        assert_eq!(measured.is_segmented(), gso);
        assert_eq!(measured.payload().as_ptr(), owner);
        Pin::new(&mut client).output().recycle(measured);
    }
}

#[test]
fn gso_reuses_across_conns() {
    const CONNECTIONS: usize = 4;
    let (mut client, handles, mut now) =
        Seen::try_many(true, CONNECTIONS).expect("output fixture must establish");

    for &handle in &handles {
        Seen::enqueue(&mut client, handle, 1, 1_150, now).expect("output enqueue");
    }
    let warm = Seen::take_one(&mut client, now)
        .expect("output take_one")
        .expect("the enqueued payload must produce one mux flight");
    assert!(warm.is_segmented());
    assert_eq!(warm.packet_count().get(), CONNECTIONS);
    let owner = warm.payload().as_ptr();
    Pin::new(&mut client).output().recycle(warm);

    now += Duration::from_millis(1);
    for &handle in &handles {
        Seen::enqueue(&mut client, handle, 1, 1_150, now).expect("output enqueue");
    }
    let span = Tracker::begin();
    let measured = Seen::take_one(&mut client, now)
        .expect("output take_one")
        .expect("the enqueued payload must produce one mux flight");
    let activity = span.finish();

    assert_eq!(activity.allocations, 0);
    assert!(measured.is_segmented());
    assert_eq!(measured.packet_count().get(), CONNECTIONS);
    assert_eq!(measured.payload().as_ptr(), owner);
    Pin::new(&mut client).output().recycle(measured);
}

#[test]
fn allocation_returns() {
    let limits = builder::Plan::try_new(1, 2, 2_400).expect("valid output limits");
    let capture = Capture::default();
    let builder = builder::Builder::client(capture.clone()).limits(limits);
    let (result, count) = Tracker::count(|| builder.build());
    drop(result.expect("output allocation baseline"));

    let mut output = false;
    for budget in 0..count {
        let builder = builder::Builder::client(capture.clone()).limits(limits);
        let (result, activity) =
            Tracker::activity(|| Tracker::fail_after(budget, || builder.build()));
        let error = result.err().expect("failed allocation returns its cause");
        if let builder::Failure::Output {
            packets,
            bytes,
            error,
        } = error
        {
            assert_eq!(error, o3::alloc::Error::Exhausted);
            assert_eq!(packets.get(), limits.outgoing());
            assert_eq!(bytes, limits.bytes());
            output = true;
        }
        assert_eq!(activity.allocations, activity.deallocations);
        assert_eq!(activity.allocated_bytes, activity.deallocated_bytes);
    }
    assert!(
        output,
        "output storage must exercise its allocation failures"
    );
    assert!(
        capture
            .events
            .borrow()
            .owners
            .iter()
            .all(|(owner, handle)| owner == handle)
    );
}

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();
