pub mod common;

use common::suite::peers::packet::Pair;
use dope_quic::wire::{
    frame::{Borrowed, Boundary, Length},
    stream::Id,
    varint::VarInt,
};
use std::time::Instant;

#[test]
fn prefix_reuses_full_gaps() {
    let now = Instant::now();
    let mut pair = Pair::try_new(256, now, |_| {}).expect("independent peer handshake");
    let id = Id::new(2).expect("negotiated stream");
    let mut frames = Vec::new();
    for batch in 0..2_usize {
        frames.clear();
        for index in batch * 128..(batch + 1) * 128 {
            Borrowed::stream(
                id,
                VarInt::try_from(index * 2 + 1).expect("bounded gap offset"),
                Boundary::More,
                Length::Explicit,
                b"x",
            )
            .expect("bounded gap frame")
            .encode(&mut frames)
            .expect("encode gap frame");
        }
        pair.receive(&frames, now).expect("buffered gaps");
    }

    let payload = [b'x'; 513];
    for (len, expected) in [(513, None), (512, Some(&payload[..512]))] {
        frames.clear();
        Borrowed::stream(
            id,
            VarInt::ZERO,
            Boundary::More,
            Length::Explicit,
            &payload[..len],
        )
        .expect("bounded prefix frame")
        .encode(&mut frames)
        .expect("encode prefix frame");
        pair.receive(&frames, now).expect("prefix admission");
        pair.server.with_scope(|mut conn| {
            let mut streams = conn.streams();
            let stream = streams
                .view()
                .resolve_recv(id)
                .expect("same receive stream");
            let bytes = streams
                .receive()
                .recv_owned(stream)
                .expect("bounded receive allocation");
            assert_eq!(bytes.as_deref(), expected);
        });
    }
}
