use std::mem::{align_of, needs_drop, size_of};
use std::ptr;

use dope_quic::errors::SendFailure;
use dope_quic::proto::datagram::{self, Arena, Packet, batch};
use dope_test::alloc::Tracker;
use o3::buffer::pool::borrowed;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn routed_capacity() {
    assert_eq!(
        datagram::Arena::payload_max(1200, dope_quic::runtime::routing::CONNECTION_ID_LEN),
        Some(1169)
    );
}

#[test]
fn batch_layout() {
    assert_eq!(size_of::<Packet<'static>>(), 24);
    assert_eq!(size_of::<Option<Packet<'static>>>(), 24);
    assert_eq!(size_of::<batch::Source<'static, 8>>(), 24);
    assert_eq!(size_of::<batch::Writable<'static, 0>>(), 0);
    assert_eq!(size_of::<batch::Writable<'static, 1>>(), 32);
    assert_eq!(size_of::<batch::Writable<'static, 8>>(), 256);
    assert_eq!(size_of::<batch::Pending<'static, 0>>(), 8);
    assert_eq!(size_of::<batch::Pending<'static, 1>>(), 32);
    assert_eq!(size_of::<batch::Pending<'static, 8>>(), 200);
    assert_eq!(align_of::<batch::Writable<'static, 8>>(), 8);
    assert_eq!(align_of::<batch::Pending<'static, 8>>(), 8);
    assert!(!needs_drop::<batch::Source<'static, 8>>());
    assert!(needs_drop::<batch::Writable<'static, 8>>());
    assert!(needs_drop::<batch::Pending<'static, 8>>());
}

#[test]
fn partial_acquire() {
    let arena = Arena::try_new(7, 1200).expect("arena");
    let source = batch::Source::<8>::try_new(&arena, 64).expect("batch source");
    assert!(source.try_acquire().is_err());
    assert_eq!(arena.available(), 7);
}

#[test]
fn validates_size() {
    let arena = Arena::try_new(1, 1200).expect("arena");
    std::assert_matches!(
        batch::Source::<1>::try_new(&arena, 1200).map(drop),
        Err(borrowed::Error::Capacity {
            length: 1200, suffix: 16, capacity,
        }) if capacity.get() == 1200
    );
    let short = batch::Source::<1>::try_new(&arena, 64).expect("batch source");
    std::assert_matches!(
        short.try_split::<65>().map(drop),
        Err(borrowed::Error::Partition {
            length: 64,
            suffix: 65
        })
    );
    let source = batch::Source::<1>::try_new(&arena, 64).expect("batch source");
    {
        let mut held = source.try_acquire().expect("packet batch");
        assert_eq!(held.prefixes_mut().len(), 1);
        let [suffix]: [&mut [u8; 0]; 1] = held.suffixes_mut();
        assert!(suffix.is_empty());
        assert!(source.try_acquire().is_err());
    }
    assert!(source.try_acquire().is_ok());
    let source = source.try_split::<64>().expect("complete suffix");
    let mut held = source.try_acquire().expect("packet batch");
    let [suffix]: [&mut [u8; 64]; 1] = held.suffixes_mut();
    *suffix = [7; 64];
    let mut packets = held.finish().into_packets();
    assert_eq!(packets.next().expect("encoded packet").payload(), [7; 64]);
    assert_eq!(arena.available(), 1);
}

#[test]
fn backpressure_retains() {
    let arena = Arena::try_new(1, 1200).expect("arena");
    let source = batch::Source::<1>::try_new(&arena, 64).expect("batch source");
    let mut batch = source.try_acquire().expect("packet batch").finish();
    assert_eq!(arena.available(), 0);

    assert!(matches!(
        batch.try_send(|packet| Err(SendFailure::Full(packet))),
        Err(batch::Error::Full(0))
    ));
    assert_eq!(arena.available(), 0);

    assert!(batch.try_send(|_| Ok(())).is_ok());
    assert_eq!(arena.available(), 1);
}

#[test]
fn warmed_no_alloc() {
    let arena = Arena::try_new(8, 1200).expect("arena");
    let source = batch::Source::<8>::try_new(&arena, 64).expect("batch source");
    {
        let mut warm = source.try_acquire().expect("warm packet batch");
        assert_eq!(warm.prefixes_mut().len(), 8);
    }

    let span = Tracker::begin();
    let mut batch = source.try_acquire().expect("packet batch").finish();
    let mut accepted = 0;
    while !batch.is_empty() {
        batch
            .try_send(|_| {
                accepted += 1;
                Ok(())
            })
            .expect("packet acceptance");
    }
    let activity = span.finish();

    assert_eq!(accepted, 8);
    assert_eq!(activity.allocations, 0);
    assert_eq!(arena.available(), 8);
}

#[test]
fn zero_batch() {
    let arena = Arena::try_new(1, 1200).expect("arena");
    let source = batch::Source::<0>::try_new(&arena, 64).expect("batch source");
    let mut batch = source.try_acquire().expect("empty batch").finish();
    assert_eq!(batch.len(), 0);
    let mut exposed = false;
    assert!(matches!(
        batch.try_send(|_| {
            exposed = true;
            Ok(())
        }),
        Ok(batch::Advance::Empty)
    ));
    assert!(!exposed, "zero-capacity batch exposed a packet");
    assert_eq!(arena.available(), 1);
}

#[test]
fn acquire_keeps_cause() {
    let arena = Arena::try_new(1, 32);
    let arena = (arena).expect("required fixture outcome");
    assert!(
        matches!(arena.try_acquire(17), Err(datagram::Error::Storage(borrowed::Error::Capacity { length: 17, suffix: 16, capacity })) if capacity.get() == 32)
    );
    assert_eq!(arena.available(), 1);
    let held = arena.try_acquire(16);
    assert!(held.is_ok());
    assert!(matches!(
        arena.try_acquire(16),
        Err(datagram::Error::Full(datagram::Full))
    ));
    drop(held);
    assert_eq!(arena.available(), 1);
}

#[test]
fn writes_fixed_payload() {
    let arena = Arena::try_new(1, 32).expect("packet arena");
    let mut entered = false;
    assert!(matches!(
        arena.try_with::<17>(|_| entered = true),
        Err(datagram::Error::Storage(borrowed::Error::Capacity {
            length: 17, suffix: 16, capacity,
        })) if capacity.get() == 32
    ));
    assert!(!entered);
    let mut address = ptr::null();
    let (packet, activity) = Tracker::counts(|| {
        arena.try_with::<16>(|out| {
            address = out.as_ptr();
            *out = [7; 16];
        })
    });
    let packet = packet.expect("fixed payload");
    assert_eq!(activity, [0, 0]);
    assert_eq!(packet.payload().as_ptr(), address);
    assert_eq!(packet.payload(), [7; 16]);
    assert!(matches!(
        arena.try_with::<16>(|_| entered = true),
        Err(datagram::Error::Full(datagram::Full))
    ));
    assert!(!entered);
    drop(packet);
    let empty = arena.try_with::<0>(|out| {
        entered = true;
        assert!(out.is_empty());
    });
    assert!(empty.expect("empty fixed payload").is_empty());
    assert!(entered);
    assert_eq!(arena.available(), 1);
}

#[test]
fn failure_keeps_position() {
    use dope_quic::security::crypto;

    let arena = Arena::try_new(2, 1200);
    let arena = (arena).expect("required fixture outcome");
    let source = batch::Source::<2>::try_new(&arena, 64);
    let source = (source).expect("required fixture outcome");
    let packets = source.try_acquire();
    let packets = (packets).expect("required fixture outcome");
    let mut packets = packets.finish();
    let cause = crypto::Error::Sample {
        actual: 0,
        required: 16,
    };
    let ((), allocs) = Tracker::usage(|| {
        assert!(
            packets
                .try_send(|packet| {
                    drop(packet);
                    Err(SendFailure::Crypto(cause.clone()))
                })
                .err()
                .expect("crypto failure consumes its plaintext")
                == batch::Error::Crypto { index: 0, cause }
        );
        assert_eq!(packets.len(), 1);
        assert_eq!(arena.available(), 1);
        assert!(
            packets
                .try_send(|packet| Err(SendFailure::Full(packet)))
                .err()
                .expect("full returns the packet")
                == batch::Error::Full(1)
        );
        assert_eq!(packets.len(), 1);
        assert_eq!(arena.available(), 1);
        assert!(matches!(
            packets.try_send(|_| Ok(())),
            Ok(batch::Advance::Drained)
        ));
        assert_eq!(arena.available(), 2);
    });
    assert_eq!(allocs, (0, 0));
}

#[test]
fn retry_preserves_order() {
    let arena = Arena::try_new(3, 1200).expect("arena");
    let source = batch::Source::<3>::try_new(&arena, 8).expect("batch source");
    let mut writable = source.try_acquire().expect("three packets");
    for (index, payload) in writable.prefixes_mut().into_iter().enumerate() {
        payload.fill(index as u8);
    }
    let mut packets = writable.finish();
    let ((first, second), activity) = Tracker::counts(|| {
        let first = packets
            .try_send(|packet| {
                assert_eq!(packet.payload(), [0; 8]);
                Err(SendFailure::Full(packet))
            })
            .err()
            .expect("first backpressure");
        let second = packets
            .try_send(|packet| {
                assert_eq!(packet.payload(), [0; 8]);
                Err(SendFailure::Closed(packet))
            })
            .err()
            .expect("repeated rejection retains the first packet");
        (first, second)
    });
    assert!(matches!(first, batch::Error::Full(0)));
    assert!(matches!(second, batch::Error::Closed(0)));
    assert_eq!(activity, [0, 0]);
    assert_eq!(packets.len(), 3);
    assert_eq!(arena.available(), 0);
    let mut rest = packets.into_packets();
    let first = rest.next().expect("restored first packet");
    assert_eq!(first.payload(), [0; 8]);
    drop(first);
    let second = rest.next().expect("original second packet");
    assert_eq!(second.payload(), [1; 8]);
    drop(second);
    assert_eq!(arena.available(), 2);
    drop(rest);
    assert_eq!(arena.available(), 3);
}

#[test]
fn queue_retains_prefix() {
    use o3::depot::queue::pool;

    let arena = Arena::try_new(3, 1200).expect("arena");
    let source = batch::Source::<3>::try_new(&arena, 8).expect("batch source");
    let plan = pool::Plan::new(2, 1).expect("two slots and one lane");
    let mut lanes = pool::Lanes::<_>::try_new(plan).expect("queue allocation");
    let mut queue = lanes.try_bind_mut(0).expect("queue lane");
    let span = Tracker::begin();
    let mut packets = source.try_acquire().expect("three packets").finish();
    let cause = queue
        .try_extend(&mut packets)
        .expect_err("three packets cannot fit two slots");
    assert_eq!(cause.requested.get(), 3);
    assert_eq!(cause.available, 2);
    assert_eq!(packets.len(), 3);
    assert_eq!(arena.available(), 0);
    assert!(queue.is_empty());
    packets.try_send(|_| Ok(())).expect("first packet accepted");
    assert_eq!(packets.len(), 2);
    assert!(queue.try_extend(&mut packets).is_ok());
    assert_eq!(arena.available(), 1);
    for _ in 0..2 {
        drop(queue.pop_front().expect("queued packet"));
    }
    assert!(queue.is_empty());
    assert_eq!(arena.available(), 3);
    assert_eq!(span.finish().allocations, 0);
}
