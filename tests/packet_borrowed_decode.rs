pub mod common;

use common::suite::mux::retry;
use dope_quic::wire::packet::{self, QUIC_V1};
use dope_quic::{
    wire::frame::{self, Borrowed, Frame, View},
    wire::stream::Id,
    wire::varint::VarInt,
};
use dope_test::alloc::Tracker;
use long::{initial, retry::Ref};
use packet::{cid, long};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn ack_ranges_borrow() {
    let wire = [frame::TYPE_ACK, 10, 0, 1, 2, 0, 2];

    let span = Tracker::begin();
    let (frame, consumed) =
        Frame::decode_ref(&wire).expect("fixed ACK wire has valid range topology");
    let range = VarInt::new(2).expect("2 is a QUIC variable integer");
    assert!(matches!(
        frame.view(),
        View::Ack { additional_ranges, .. }
            if additional_ranges.clone().eq([(VarInt::ZERO, range)])
    ));
    let allocs = span.finish().allocations;

    assert_eq!(consumed, wire.len());
    assert_eq!(allocs, 0);
}

#[test]
fn ack_ecn_normalizes() {
    let wire = [frame::TYPE_ACK_ECN, 10, 0, 1, 2, 0, 2, 1, 2, 3];
    let (decoded, consumed) =
        Frame::decode_ref(&wire).expect("fixed ACK_ECN wire has valid ranges and counters");
    assert!(matches!(decoded.view(), View::Ack { .. }));
    assert_eq!(consumed, wire.len());

    let mut out = Vec::new();
    decoded.encode(&mut out).expect("wire encoding");
    assert_eq!(out, [frame::TYPE_ACK, 10, 0, 1, 2, 0, 2]);
}

#[test]
fn ack_pair_widths_replay() {
    let wire = b"\x02\x0a\x00\x02\x00\
                 \x40\x00\x80\x00\x00\x00\
                 \xc0\x00\x00\x00\x00\x00\x00\x00\x00\x01";
    let (decoded, consumed) = Frame::decode_ref(wire).expect("valid ACK pair widths");
    assert_eq!(&wire[consumed..], &[frame::TYPE_PING]);
    assert!(matches!(
        decoded.view(),
        View::Ack { additional_ranges, .. }
            if additional_ranges.clone().eq([(VarInt::ZERO, VarInt::ZERO); 2])
    ));
    let mut out = Vec::new();
    decoded.encode(&mut out).expect("ACK replay encoding");
    assert_eq!(out, [frame::TYPE_ACK, 10, 0, 2, 0, 0, 0, 0, 0]);
}

#[test]
fn ack_replays_body() {
    use common::peer::Scope as _;
    use common::suite::peers::packet::Pair;
    use dope_quic::conn::{Epoch, wire::packet::Batch};
    use std::time::{Duration, Instant};

    let clock = Instant::now();
    let mut pair = Pair::try_new(1, clock, |_| {}).expect("peers");
    pair.retired(clock).expect("settle handshake output");
    let stream = pair.server.send_streams().open_uni().expect("stream");
    let mut batch = Batch::default();
    let mut now = clock + Duration::from_secs(1);
    let mut numbers = [0; 3];
    for number in &mut numbers {
        pair.server.send_streams().send(stream, b"x").expect("send");
        now = pair.server.view().recovery().send_at(now);
        pair.server
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 1, 1200))
            .expect("packet");
        let packet = batch.iter_mut().next().expect("one packet");
        *number = pair.peer.open(packet).expect("authenticated packet").0;
    }

    let mut ack = vec![frame::TYPE_PING, frame::TYPE_PADDING];
    let gap = VarInt::try_from(numbers[2] - numbers[0] - 2).expect("gap");
    Borrowed::ack(
        VarInt::try_from(numbers[2]).expect("last number"),
        VarInt::ZERO,
        VarInt::ZERO,
        &[(gap, VarInt::ZERO)],
    )
    .expect("separate ACK ranges")
    .encode(&mut ack)
    .expect("encode");
    pair.receive(&ack, now)
        .expect("retire first and last packets");
    assert_eq!(pair.server.view().recovery().unacked(Epoch::Application), 1);

    ack.clear();
    Borrowed::ack(
        VarInt::try_from(numbers[1]).expect("middle number"),
        VarInt::ZERO,
        VarInt::ZERO,
        &[],
    )
    .expect("single ACK range")
    .encode(&mut ack)
    .expect("encode");
    pair.receive(&ack, now).expect("retire remaining packet");
    assert_eq!(pair.server.view().recovery().unacked(Epoch::Application), 0);
}

#[test]
fn outbound_borrows() {
    let payload = b"borrowed stream payload";
    let mut wire = Vec::with_capacity(64);

    let span = Tracker::begin();
    let id = Id::new(4).expect("stream ID 4 is a QUIC variable integer");
    let frame = Borrowed::stream(
        id,
        VarInt::ZERO,
        frame::Boundary::End,
        frame::Length::Explicit,
        payload,
    )
    .expect("fixed payload and zero offset satisfy STREAM bounds");
    frame.encode(&mut wire).expect("wire encoding");
    let allocs = span.finish().allocations;

    assert!(matches!(
        frame.view(),
        View::Stream { data, .. } if data.as_ptr() == payload.as_ptr()
    ));
    assert_eq!(allocs, 0);

    let (decoded, consumed) =
        Frame::decode_ref(&wire).expect("encoded borrowed STREAM frame decodes");
    assert!(matches!(
        decoded.view(),
        View::Stream { data, boundary, .. }
            if *data == payload && matches!(boundary, frame::Boundary::End)
    ));
    assert_eq!(consumed, wire.len());
}

#[test]
fn ack_topology_borrows() {
    let range = VarInt::new(2).expect("2 is a QUIC variable integer");
    let ranges = [(VarInt::ZERO, range)];
    let mut wire = Vec::with_capacity(32);

    let span = Tracker::begin();
    Borrowed::ack(
        VarInt::new(10).expect("10 is a QUIC variable integer"),
        VarInt::ZERO,
        range,
        &ranges,
    )
    .expect("largest 10, first range 2, and the gap pair form valid ACK topology")
    .encode(&mut wire)
    .expect("wire encoding");
    let allocs = span.finish().allocations;

    assert_eq!(allocs, 0);
    assert!(Frame::decode_ref(&wire).is_ok());
}

#[test]
fn long_header_borrows() {
    let wire = initial::Header {
        version: QUIC_V1,
        dcid: vec![0x11; 8],
        scid: vec![0x22; 8],
        token: vec![0x33; 32],
        packet_number: 0,
        pn_len: 1,
    }
    .encode(3)
    .expect("bounded CIDs, token, and one-byte packet number form an Initial");
    let mut packet = Vec::with_capacity(wire.as_bytes().len() + 19);
    packet.extend_from_slice(wire.as_bytes());
    packet.extend_from_slice(&[0; 19]);

    let span = Tracker::begin();
    let prefix =
        initial::Prefix::decode(&packet).expect("encoded Initial has a valid borrowed prefix");
    let owned = prefix.dcid.into_owned();
    let allocs = span.finish().allocations;

    assert!(prefix.dcid == [0x11; 8]);
    assert!(prefix.scid == [0x22; 8]);
    assert_eq!(prefix.token, [0x33; 32]);
    assert_eq!(prefix.dcid.as_ptr(), packet[6..].as_ptr());

    assert_eq!(owned.as_slice(), &[0x11; 8]);
    assert_eq!(allocs, 0);
}

#[test]
fn maximum_long_lengths() {
    use o3::buffer::write::consume;
    use packet::decode;
    use std::num::NonZero;

    for first in [0xc0, 0xd0, 0xe0] {
        let mut wire = vec![first, 0, 0, 0, 1, 0, 0];
        if first == 0xc0 {
            wire.push(0);
        }
        wire.extend_from_slice(&[u8::MAX; 8]);
        let required = NonZero::new(wire.len() + VarInt::MAX as usize).expect("nonempty packet");
        assert_eq!(
            long::Parsed::parse(wire.as_slice()).err(),
            Some(decode::Error::Packet(consume::Error::new(
                required,
                wire.len()
            )))
        );
        if first == 0xc0 {
            wire.remove(7);
            assert_eq!(
                initial::Prefix::decode(&wire).err(),
                Some(decode::Error::Underflow {
                    actual: wire.len(),
                    required: wire.len() + VarInt::MAX as usize,
                })
            );
        }
    }
}

#[test]
fn cid_obeys_wire_bound() {
    assert_eq!(std::mem::size_of::<cid::Id>(), 21);
    assert!(cid::Id::try_from(&[0; 20][..]).is_ok());
    let error = cid::Id::try_from(&[0; 21][..])
        .err()
        .expect("CID exceeds its wire bound");
    assert_eq!(
        error.into_parts(),
        (
            std::num::NonZero::new(21).expect("nonzero fixture length"),
            20
        )
    );
}

#[test]
fn retry_reuses_storage() {
    let original = [0x11; 8];
    let expected = [0x22; 8];
    let peer_cid = [0x33; 8];
    let token = [0x44; 48];
    let wire = retry::try_wire(&original, &expected, &peer_cid, &token)
        .expect("bounded Retry CIDs and token encode with their integrity tag");
    let mut storage = Vec::new();

    let span = Tracker::begin();
    let verified = Ref::decode(&wire)
        .expect("encoded Retry has a valid borrowed wire layout")
        .verify_into(
            cid::Ref::new(&original).expect("8-byte original DCID fits the wire bound"),
            cid::Ref::new(&expected).expect("8-byte expected DCID fits the wire bound"),
            &mut storage,
        )
        .expect("Retry integrity verification primitive succeeds")
        .expect("matching destination CID and generated tag verify the Retry");
    let peer = verified.scid().into_owned();
    let len = verified.token().len();
    let allocs = span.finish().allocations;

    assert_eq!(allocs, 1);
    assert_eq!(peer.as_slice(), peer_cid);
    assert_eq!(len, token.len());
    assert_eq!(storage, token);
}

#[test]
fn empty_retry_no_alloc() {
    let original = [0x11; 8];
    let expected = [0x22; 8];
    let wire = retry::try_wire(&original, &expected, &[0x33; 8], &[])
        .expect("empty-token Retry has a valid integrity tag");
    let packet = Ref::decode(&wire).expect("empty-token Retry layout");
    let original = cid::Ref::new(&original).expect("original CID");
    let expected = cid::Ref::new(&expected).expect("destination CID");
    let mut storage = Vec::new();

    let span = Tracker::begin();
    let verified = packet.verify_into(original, expected, &mut storage);
    let activity = span.finish();

    assert!(verified.expect("silent Retry rejection").is_none());
    assert_eq!(activity.allocations, 0);
    assert!(storage.is_empty());
}
