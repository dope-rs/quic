pub mod common;

use common::{peer::Scope as _, suite::peers::packet::Pair};
use dope_quic::{
    conn::wire::packet::Batch,
    wire::{frame, varint::VarInt},
};
use std::time::{Duration, Instant};

/// The peer's default exponent 3 encodes its 25 ms cap as 3125.
#[test]
fn overflow_uses_peer_max() {
    let clock = Instant::now();
    let [zero, capped, overflow] = [0, 3_125, 1_u64 << 61].map(|delay| {
        let mut pair = Pair::try_new(1, clock, |_| {}).expect("peers");
        pair.retired(clock).expect("settle handshake output");
        let stream = pair.server.send_streams().open_uni().expect("stream");
        let mut batch = Batch::default();
        let mut sent = clock + Duration::from_secs(1);

        for (elapsed, delay) in [(20, 0), (60, delay)] {
            pair.server.send_streams().send(stream, b"x").expect("send");
            sent = pair.server.view().recovery().send_at(sent);
            pair.server
                .with_scope(|mut scope| scope.output().send_batch(&mut batch, sent, 1, 1200))
                .expect("packet");
            let packet = batch.iter_mut().next().expect("one packet");
            let (number, _) = pair.peer.open(packet).expect("authenticated packet");
            let mut ack = Vec::new();
            frame::Borrowed::ack(
                VarInt::try_from(number).expect("number"),
                VarInt::try_from(delay).expect("delay"),
                VarInt::ZERO,
                &[],
            )
            .expect("ack")
            .encode(&mut ack)
            .expect("encode");
            pair.receive(&ack, sent + Duration::from_millis(elapsed))
                .expect("acknowledge packet");
            sent += Duration::from_secs(1);
        }

        let recovery = pair.server.view().recovery();
        (
            recovery.min_rtt().expect("minimum RTT"),
            recovery.smoothed_rtt().expect("smoothed RTT"),
        )
    });

    assert_eq!(overflow, capped);
    assert!(zero.1 > capped.1, "the admitted delay must adjust the RTT");
}
