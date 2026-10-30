pub mod common;

use common::suite::peers::packet::Pair;
use dope_quic::conn::Error;
use dope_quic::wire::{
    frame::{self, Borrowed, Boundary, Length},
    stream::Id,
    varint::VarInt,
};
use std::time::Instant;

#[test]
fn fin_before_prefix() {
    let now = Instant::now();
    let mut certs = Vec::new();
    let pair = Pair::try_new(1, now, |error| certs.push(format!("{error:?}")));
    assert!(certs.is_empty(), "{certs:?}");
    let mut pair = pair.expect("independent peer handshake");
    let mut frames = Vec::new();
    Borrowed::stream(
        Id::new(2).expect("bounded stream identifier"),
        VarInt::from_u8(4),
        Boundary::End,
        Length::Explicit,
        b"ef",
    )
    .expect("bounded FIN tail")
    .encode(&mut frames)
    .expect("encode FIN tail");
    Borrowed::stream(
        Id::new(2).expect("bounded stream identifier"),
        VarInt::ZERO,
        Boundary::More,
        Length::Explicit,
        b"abcd",
    )
    .expect("bounded stream head")
    .encode(&mut frames)
    .expect("encode stream head");
    let mut packet = pair
        .peer
        .packet(&frames)
        .expect("encode application packet");
    let received = pair.server.with_scope(|mut scope| {
        scope
            .input(&mut pair.work)
            .recv_packet(&mut packet, now, |error| {
                certs.push(format!("{error:?}"));
            })
    });
    assert!(certs.is_empty(), "{certs:?}");
    received.expect("out-of-order single packet");
    pair.server.with_scope(|mut conn| {
        let mut streams = conn.streams();
        let stream = streams
            .view()
            .resolve_recv(Id::new(2).expect("bounded stream identifier"))
            .expect("one bound stream");
        assert!(streams.view().has_recv_fin(stream));
        assert_eq!(
            streams
                .receive()
                .recv_owned(stream)
                .expect("single peak gap slot")
                .expect("ordered owner"),
            b"abcdef"
        );
        assert!(streams.view().is_recv_eof(stream));
        assert!(
            streams
                .receive()
                .recv_owned(stream)
                .expect("drained receiver")
                .is_none()
        );
    });
}

#[test]
fn reuses_full_indices() {
    let now = Instant::now();
    let mut pair = Pair::try_new(3, now, |_| {}).expect("independent peer handshake");
    let mut frames = Vec::new();
    for index in 0..256 {
        let (id, data) = [(10, b"c"), (2, b"a"), (6, b"b")][index % 3];
        Borrowed::stream(
            Id::new(id).expect("negotiated stream"),
            VarInt::ZERO,
            Boundary::More,
            Length::Explicit,
            data,
        )
        .expect("bounded stream frame")
        .encode(&mut frames)
        .expect("encode stream frame");
    }
    pair.receive(&frames, now)
        .expect("full frame index capacity");
    pair.server.with_scope(|mut conn| {
        let mut streams = conn.streams();
        for (id, expected) in [(2, b"a"), (6, b"b"), (10, b"c")] {
            let stream = streams
                .view()
                .resolve_recv(Id::new(id).expect("negotiated stream"))
                .expect("grouped receive stream");
            assert_eq!(
                streams
                    .receive()
                    .recv_owned(stream)
                    .expect("bound receiver")
                    .expect("payload"),
                expected,
            );
        }
    });

    let id = Id::new(2).expect("negotiated stream");
    let mut short = Vec::new();
    Borrowed::stream(
        id,
        VarInt::from_u8(1),
        Boundary::End,
        Length::Explicit,
        b"d",
    )
    .expect("bounded stream suffix")
    .encode(&mut short)
    .expect("encode stream suffix");
    pair.receive(&short, now).expect("reused frame storage");
    pair.server.with_scope(|mut conn| {
        let mut streams = conn.streams();
        let stream = streams
            .view()
            .resolve_recv(id)
            .expect("same receive stream");
        assert_eq!(
            streams
                .receive()
                .recv_owned(stream)
                .expect("bound receiver")
                .expect("suffix"),
            b"d",
        );
    });

    frames.push(frame::TYPE_PING);
    let mut packet = pair.peer.packet(&frames).expect("encode excess frame");
    assert!(matches!(
        pair.server.with_scope(|mut scope| {
            scope
                .input(&mut pair.work)
                .recv_packet(&mut packet, now, |_| {})
        }),
        Err(Error::FrameLimit {
            actual: 257,
            maximum: 256,
        }),
    ));
}
