pub mod common;

use common::{peer::Scope as _, suite::peers::packet::Pair};
use dope_quic::{
    conn::{Epoch, wire::packet::Batch},
    wire::{frame, varint::VarInt},
};
use std::time::{Duration, Instant};

/// Earlier receive timestamps isolate packet-threshold loss from time-threshold loss.
#[test]
fn retains_wrapped() {
    let clock = Instant::now();
    let mut pair = Pair::try_new(1, clock, |_| {}).expect("peers");
    pair.retired(clock).expect("settle handshake output");
    assert_eq!(pair.server.view().recovery().unacked(Epoch::Application), 0);
    let stream = pair.server.send_streams().open_uni().expect("stream");
    let mut batch = Batch::default();
    let mut packets = Vec::new();
    let mut now = clock + Duration::from_secs(1);

    for count in [64, 32] {
        for _ in 0..count {
            pair.server.send_streams().send(stream, b"x").expect("send");
            now = pair.server.view().recovery().send_at(now);
            pair.server
                .with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 1, 1200))
                .expect("packet");
            assert_eq!(batch.packets(), 1);
            let wire = batch.iter_mut().next().expect("one packet");
            let bytes = wire.len() as u64;
            let (pn, _) = pair.peer.open(wire).expect("authenticated packet");
            packets.push((pn, bytes));
        }
        assert_eq!(
            pair.server.view().recovery().unacked(Epoch::Application),
            64
        );
        if count == 64 {
            let mut ack = Vec::new();
            frame::Borrowed::ack(
                VarInt::try_from(packets[31].0).expect("number"),
                VarInt::ZERO,
                VarInt::try_from(packets[31].0 - packets[0].0).expect("range"),
                &[],
            )
            .expect("ack")
            .encode(&mut ack)
            .expect("encode");
            pair.receive(&ack, clock).expect("prefix ACK");
            assert_eq!(
                pair.server.view().recovery().unacked(Epoch::Application),
                32
            );
            assert_eq!(
                pair.server.view().recovery().in_flight(),
                packets[32..].iter().map(|(_, bytes)| bytes).sum::<u64>(),
            );
        }
    }

    let retained = packets[32..].iter().map(|(_, bytes)| bytes).sum::<u64>() - packets[34].1;
    for (index, left, bytes) in [
        (34, 63, retained),
        (34, 63, retained),
        (95, 2, packets[93].1 + packets[94].1),
        (93, 1, packets[94].1),
        (94, 0, 0),
    ] {
        let mut ack = Vec::new();
        frame::Borrowed::ack(
            VarInt::try_from(packets[index].0).expect("number"),
            VarInt::ZERO,
            VarInt::ZERO,
            &[],
        )
        .expect("ack")
        .encode(&mut ack)
        .expect("encode");
        pair.receive(&ack, clock).expect("selective ACK");
        assert_eq!(
            pair.server.view().recovery().unacked(Epoch::Application),
            left,
        );
        assert_eq!(pair.server.view().recovery().in_flight(), bytes);
    }
}
