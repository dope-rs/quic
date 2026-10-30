pub mod common;
use crate::common::peer;
use std::time::{Duration, Instant};

use dope_quic::conn::wire::packet::Batch;
use peer::Pair;
use peer::Receiver as _;

#[test]
fn preserves_packet_samples() {
    let mut pair = Pair::try_default().expect("the peers must establish");
    let lengths = [0, 1, 2, 3, 16, 64];
    for length in lengths {
        assert!(
            pair.client
                .with_scope(|mut scope| { scope.datagrams().try_send(vec![0x42; length]) })
                .is_ok()
        );
    }
    let mut batch = Batch::default();
    let now = Instant::now() + Duration::from_secs(1);
    assert!(
        pair.client
            .with_scope(|mut scope| { scope.output().send_batch(&mut batch, now, 8, 1200) })
            .is_ok()
    );
    assert!(batch.packets() >= lengths.len());
    assert_eq!(
        batch.iter().map(<[u8]>::len).sum::<usize>(),
        batch.byte_len()
    );
    for packet in batch.iter_mut() {
        assert!(packet.first().is_some_and(|first| first & 0x80 == 0));
        assert!(pair.server.receive(&mut pair.work, packet, now).is_ok());
    }
    for length in lengths {
        let payload = (pair.server.with_scope(|mut scope| scope.datagrams().recv()))
            .expect("each admitted datagram must authenticate and arrive");
        assert_eq!(payload, vec![0x42; length]);
    }
    assert!(
        pair.server
            .with_scope(|mut scope| scope.datagrams().recv())
            .is_none()
    );
}
