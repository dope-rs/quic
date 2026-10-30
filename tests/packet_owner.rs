pub mod common;
use crate::common::peer;
use common::suite::{owners, peers::config};
use std::time::{Duration, Instant};

use dope_quic::conn::{self, output::transmit, wire::packet::Batch};
use dope_quic::errors::SendFailure;
use dope_quic::proto::datagram;
use dope_quic::security::qkdf;
use dope_quic::wire::packet::{self, encode, long};
use dope_test::alloc::Tracker;
use long::initial;
use o3::{alloc, buffer::pool::borrowed};
use peer::Config;
use peer::Pair;
use peer::Receiver as _;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn maximum_returns_owner() {
    let mut pair = config::try_packet().expect("established packet pair");
    let arena = datagram::Arena::try_new(1, 64).expect("packet arena");
    let mut packet = (arena.try_acquire(16)).expect("the original payload must fit its arena slot");
    packet.payload_mut().fill(0x42);
    let pointer = packet.payload().as_ptr();
    let now = Instant::now() + Duration::from_secs(1);
    let result = pair
        .client
        .with_scope(|mut scope| scope.output().try_packet(packet, now, 32));
    let (packet, cause) = match result
        .err()
        .expect("the complete packet must exceed the requested maximum")
    {
        SendFailure::Admission(packet, cause) => Some((packet, cause)),
        _ => None,
    }
    .expect("the complete packet must exceed the requested maximum");
    assert_eq!(
        cause,
        transmit::Admission::Datagram(datagram::Error::Maximum {
            bytes: 43,
            maximum: 32,
        })
    );
    assert_eq!(packet.payload().as_ptr(), pointer);
    assert_eq!(packet.payload(), [0x42; 16]);
    assert_eq!(arena.available(), 0);
    let result = pair
        .client
        .with_scope(|mut scope| scope.output().try_packet(packet, now, 1200));
    let sealed = result
        .as_ref()
        .map_err(owners::rejection)
        .expect("retry must seal the original packet");
    let mut wire = sealed.as_slice().to_vec();
    assert!(pair.server.receive(&mut pair.work, &mut wire, now).is_ok());
    assert_eq!(
        pair.server.with_scope(|mut scope| scope.datagrams().recv()),
        Some(vec![0x42; 16])
    );
    drop(result);
    assert_eq!(arena.available(), 1);
}

#[test]
fn storage_returns_owner() {
    let mut pair = config::try_packet().expect("established packet pair");
    let arena = datagram::Arena::try_new(1, 32).expect("packet arena");
    let mut packet =
        (arena.try_acquire(16)).expect("the payload and tag must fit before header admission");
    packet.payload_mut().fill(0x42);
    let pointer = packet.payload().as_ptr();
    let now = Instant::now() + Duration::from_secs(1);
    let result = pair
        .client
        .with_scope(|mut scope| scope.output().try_packet(packet, now, 1200));
    let (packet, cause) = match result
        .err()
        .expect("a slot without prefix room must return its original owner")
    {
        SendFailure::Admission(packet, cause) => Some((packet, cause)),
        _ => None,
    }
    .expect("a slot without prefix room must return its original owner");
    assert!(
        matches!(cause, transmit::Admission::Datagram(datagram::Error::Storage(
        borrowed::Error::Prefix { requested, available: 0 }
    )) if requested >= 11)
    );
    assert_eq!(packet.payload().as_ptr(), pointer);
    assert_eq!(packet.payload(), [0x42; 16]);
    assert_eq!(arena.available(), 0);
    drop(packet);
    assert_eq!(arena.available(), 1);
}

#[test]
fn padding_retains_slot() {
    use o3::depot::capacity;

    let mut pair = config::try_packet().expect("established packet pair");
    let arena = datagram::Arena::try_new(1, 64).expect("packet arena");
    let idle = pair
        .client
        .view()
        .recovery()
        .next_timer()
        .expect("the settled fixture has an idle deadline");
    let mut now = Instant::now() + Duration::from_secs(1);
    for (index, length) in [16, 0, 1, 2, 3, 16].into_iter().enumerate() {
        let mut packet =
            (arena.try_acquire(length)).expect("the previous sealed packet must release its slot");
        packet.payload_mut().fill(0x42);
        let pointer = packet.payload().as_ptr();
        if index == 0 {
            let before = pair.client.view().recovery().in_flight();
            assert_eq!(before, 0, "the fixture handshake must be settled");
            let (result, activity) = Tracker::counts(|| {
                Tracker::fail_after(0, || {
                    pair.client
                        .with_scope(|mut scope| scope.output().try_packet(packet, now, 1200))
                })
            });
            assert_eq!(activity, [0, 0]);
            let (rejected, cause) = match result
                .err()
                .expect("the first journal reservation must return its owner")
            {
                SendFailure::Admission(rejected, cause) => Some((rejected, cause)),
                _ => None,
            }
            .expect("the first journal reservation must return its owner");
            assert!(
                matches!(cause, transmit::Admission::Packet {
                    space: conn::Epoch::Application,
                    reason: capacity::Reason::Allocation(alloc::Error::Exhausted),
                    controls,
                    streams,
                    ..
                } if controls.get() == 0 && streams.get() == 0),
                "unexpected journal admission: {cause:?}"
            );
            assert_eq!(rejected.payload().as_ptr(), pointer);
            assert_eq!(rejected.payload(), [0x42; 16]);
            assert_eq!(arena.available(), 0);
            assert_eq!(pair.client.view().recovery().in_flight(), before);
            assert_eq!(pair.client.view().recovery().next_timer(), Some(idle));
            packet = rejected;
        }
        let (result, activity) = Tracker::counts(|| {
            pair.client
                .with_scope(|mut scope| scope.output().try_packet(packet, now, 1200))
        });
        if index == 0 {
            assert_eq!(
                activity,
                [1, 0],
                "the first packet reserves its demand journal"
            );
        } else {
            assert_eq!(
                activity,
                [0, 0],
                "packet protection must use the existing arena and journals"
            );
        }
        let sealed = result
            .as_ref()
            .map_err(owners::rejection)
            .expect("padding must retain the packet slot");
        if index == 0 {
            assert!(
                pair.client
                    .view()
                    .recovery()
                    .next_timer()
                    .is_some_and(|deadline| now < deadline && deadline < idle),
                "the pooled commit must arm a fresh PTO before the idle deadline"
            );
        }
        let wire = sealed.as_slice();
        assert!(
            wire.len() >= 29,
            "the nine-byte prefix must precede a full protection sample"
        );
        assert_eq!(wire[wire.len() - 16 - length..].as_ptr(), pointer);
        assert_eq!(arena.available(), 0);
        let mut received = wire.to_vec();
        assert!(
            pair.server
                .receive(&mut pair.work, &mut received, now)
                .is_ok()
        );
        assert_eq!(
            pair.server.with_scope(|mut scope| scope.datagrams().recv()),
            Some(vec![0x42; length])
        );
        drop(result);
        assert_eq!(arena.available(), 1);
        now += Duration::from_millis(25);
        assert!(
            pair.client
                .receive_from(&mut pair.work, &mut pair.server, now)
                .is_ok()
        );
    }
}

#[test]
fn long_header_padding() {
    let header = initial::Header {
        version: packet::QUIC_V1,
        dcid: Vec::new(),
        scid: Vec::new(),
        token: Vec::new(),
        packet_number: 0,
        pn_len: 1,
    };
    for length in [0, 1, 2, 3, 16] {
        let encoded = (header.encode(length))
            .expect("a validated Initial header must encode every short body");
        assert_eq!(
            encoded.as_bytes(),
            [
                0xc0,
                0,
                0,
                0,
                1,
                0,
                0,
                0,
                0x40,
                (length.max(3) + 17) as u8,
                0
            ]
        );
    }
}

#[test]
fn invalid_header() {
    let mut header = initial::Header {
        version: packet::QUIC_V1,
        dcid: Vec::new(),
        scid: Vec::new(),
        token: Vec::new(),
        packet_number: 0,
        pn_len: 1,
    };
    for width in [0, 5, 17, u8::MAX] {
        header.pn_len = width;
        assert!(matches!(header.encode(16), Err(encode::Error::Width {
            actual, minimum: 1, maximum: 4,
        }) if actual == width));
        assert_eq!(header.pn_len, width);
        assert_eq!(header.packet_number, 0);
    }
    header.pn_len = 1;
    for number in [1 << 62, u64::MAX] {
        header.packet_number = number;
        assert!(matches!(header.encode(16), Err(encode::Error::Number {
            actual, maximum,
        }) if actual == number && maximum == (1 << 62) - 1));
        assert_eq!(header.packet_number, number);
    }
}

#[test]
fn allocation_retry() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_open(
        Config::default().try_build().expect("server configuration"),
        Config::default().try_build().expect("client configuration"),
    )
    .expect("open packet pair");
    let now = Instant::now();
    let mut batch = Batch::default();
    let result = Tracker::fail_after(0, || {
        client.with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 32, 1200))
    });
    assert_eq!(
        result,
        Err(transmit::Error::Admission(transmit::Admission::Segments {
            error: alloc::Error::Exhausted,
            requested: 1,
        }))
    );
    assert!(batch.is_empty());
    assert_eq!(batch.byte_len(), 0);
    assert!(
        client
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 32, 1200))
            .is_ok()
    );
    assert_eq!(batch.packets(), 1);
    let wire = (batch.iter().next()).expect("the retry must emit the retained Initial");
    let open = qkdf::Initial::try_new(&[0x71; 8])
        .expect("initial derivation")
        .try_client()
        .expect("client key admission");
    let initial = match long::Parsed::parse(wire.to_vec())
        .expect("the retried packet must retain its Initial header")
    {
        long::Parsed::Initial(initial) => Some(initial),
        _ => None,
    }
    .expect("the retried packet must retain its Initial header");
    let opened = (initial.decrypt(&open, 0))
        .expect("the retained header and body must authenticate together");
    assert_eq!(
        opened.number(),
        0,
        "failed allocation must not consume the number reservation"
    );
    for wire in batch.iter_mut() {
        assert!(server.receive(&mut work, wire, now).is_ok());
    }
    let sent_at = now + Duration::from_millis(1);
    assert!(
        server
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, sent_at, 32, 1200))
            .is_ok()
    );
    assert!(
        batch.packets() >= 2,
        "the server must append both Initial and Handshake packets"
    );
    let mut tail = None;
    for wire in batch.iter() {
        if let Some(end) = tail {
            assert_eq!(
                wire.as_ptr() as usize,
                end,
                "later packets must share the same batch allocation"
            );
        }
        tail = Some(wire.as_ptr() as usize + wire.len());
    }
    for wire in batch.iter_mut() {
        assert!(
            client.receive(&mut work, wire, sent_at).is_ok(),
            "appending a later packet must preserve the earlier authenticated prefix"
        );
    }
    assert!(client.view().lifecycle().is_ready());
}

#[test]
fn timing_returns_owner() {
    let mut pair = config::try_packet().expect("established packet pair");
    let start = Instant::now() + Duration::from_secs(1);
    assert!(
        pair.server
            .with_scope(|mut scope| scope.datagrams().try_send(vec![7]))
            .is_ok()
    );
    let (mut received, result) = pair
        .server
        .with_scope(|mut scope| scope.output().send(start));
    result.expect("peer activity must be emitted");
    assert!(!received.is_empty());
    for wire in &mut received {
        assert!(pair.client.receive(&mut pair.work, wire, start).is_ok());
    }
    let arena = datagram::Arena::try_new(1, 64).expect("packet arena");
    let mut packet = arena.try_acquire(16).expect("original packet slot");
    packet.payload_mut().fill(0x42);
    let pointer = packet.payload().as_ptr();
    let before = pair.client.view().recovery().in_flight();
    let due = pair.client.view().recovery().next_timer();
    let mut now = start;
    for bit in (0..u64::BITS).rev() {
        if let Some(next) = now.checked_add(Duration::from_secs(1_u64 << bit)) {
            now = next;
        }
    }
    assert!(now.checked_add(Duration::from_secs(1)).is_none());
    let (packet, at, duration) = match pair
        .client
        .with_scope(|mut scope| scope.output().try_packet(packet, now, 1200))
        .err()
        .expect("the actual packet deadline must exceed the clock")
    {
        SendFailure::Admission(
            packet,
            transmit::Admission::Timing(conn::Timing::Deadline {
                at,
                duration_secs: secs,
                duration_nanos: nanos,
            }),
        ) => Some((packet, at, Duration::new(secs, nanos.get()))),
        _ => None,
    }
    .expect("the timing admission must retain the original packet");
    assert_eq!(at, now);
    assert!(!duration.is_zero());
    assert!(at.checked_add(duration).is_none());
    assert_eq!(packet.payload().as_ptr(), pointer);
    assert_eq!(packet.payload(), [0x42; 16]);
    assert_eq!(arena.available(), 0);
    assert_eq!(pair.client.view().recovery().in_flight(), before);
    assert!(pair.client.view().lifecycle().is_closed());
    assert!(!pair.client.view().lifecycle().is_ready());
    assert_eq!(pair.client.view().recovery().next_timer(), due);
    drop(packet);
    assert_eq!(arena.available(), 1);
}

#[test]
fn batch_keeps_both_errors() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_open(
        Config::default().try_build().expect("server configuration"),
        Config::default().try_build().expect("client configuration"),
    )
    .expect("open packet pair");
    let start = Instant::now();
    let mut batch = Batch::default();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, start, 1, 1200))
        .expect("one client Initial must warm the batch");
    assert_eq!(batch.packets(), 1);
    for wire in batch.iter_mut() {
        server
            .receive(&mut work, wire, start)
            .expect("client Initial");
    }
    let due = server.view().recovery().next_timer();
    let mut now = start;
    for bit in (0..u64::BITS).rev() {
        if let Some(next) = now.checked_add(Duration::from_secs(1_u64 << bit)) {
            now = next;
        }
    }
    assert!(now.checked_add(Duration::from_secs(1)).is_none());
    let error = Tracker::fail_after(1, || {
        server.with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 32, 1200))
    })
    .expect_err("the second packet admission and final timing must both fail");
    let (cause, at, duration) = match error {
        transmit::Error::Finalize {
            admission: cause,
            timing:
                conn::Timing::Deadline {
                    at,
                    duration_secs: secs,
                    duration_nanos: nanos,
                },
        } => Some((cause, at, Duration::new(secs, nanos.get()))),
        _ => None,
    }
    .expect("both the packet admission and exact deadline error must survive");
    assert_eq!(
        cause,
        transmit::Admission::Segments {
            error: alloc::Error::Exhausted,
            requested: 1,
        }
    );
    assert_eq!(at, now);
    assert!(at.checked_add(duration).is_none());
    assert_eq!(batch.packets(), 1);
    assert_eq!(server.view().recovery().unacked(conn::Epoch::Initial), 1);
    assert_eq!(server.view().recovery().unacked(conn::Epoch::Handshake), 0);
    assert_eq!(
        server.view().recovery().in_flight(),
        batch.byte_len() as u64
    );
    assert!(server.view().lifecycle().is_closed());
    assert_eq!(server.view().recovery().next_timer(), due);
    for wire in batch.iter_mut() {
        client
            .receive(&mut work, wire, start)
            .expect("committed server Initial");
    }
}
