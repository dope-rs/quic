pub mod common;

use common::suite::peers::packet::{Pair, bytes};
use dope_quic::{
    conn::Error,
    wire::{
        frame::{Frame, View, close},
        stream::Id,
    },
};
use std::time::Instant;

#[test]
fn classifies_stream_frames() {
    for &(name, frames, expected) in bytes::STREAM_PROTOCOL_ERRORS {
        let now = Instant::now();
        let mut pair = Pair::try_new(1, now, |_| {}).expect("application packet fixture");
        pair.server.with_scope(|mut conn| {
            conn.streams()
                .send()
                .open_uni()
                .expect("send-only stream is open");
        });
        let mut packet = pair
            .peer
            .packet(frames)
            .expect("authenticated stream frame");
        let error = pair
            .server
            .with_scope(|mut conn| {
                conn.input(&mut pair.work)
                    .recv_packet(&mut packet, now, |_| {})
            })
            .expect_err(name);
        assert!(
            matches!(
                (expected, &error),
                (0x04, Error::StreamLimit) | (0x05, Error::StreamState)
            ),
            "{name}: {error:?}"
        );
        let mut packet = pair
            .server
            .with_scope(|mut conn| {
                let (packets, result) = conn.output().send(now);
                result.expect("transport close");
                packets
            })
            .into_iter()
            .next()
            .expect("close packet");
        let (_, body) = pair.peer.open(&mut packet).expect("authenticated close");
        let frames = Frame::decode_all(&body).expect("close frame");
        assert!(
            matches!(
                frames.first().map(Frame::view),
                Some(View::ConnectionClose {
                    code: close::Code::Transport { error_code, .. },
                    ..
                }) if error_code.get() == expected
            ),
            "{name}"
        );
    }
}

#[test]
fn accepts_last_stream() {
    let now = Instant::now();
    let mut pair = Pair::try_new(1, now, |_| {}).expect("application packet fixture");
    pair.receive(bytes::STREAM_AT_LIMIT, now)
        .expect("third peer unidirectional stream is permitted");
    pair.server.with_scope(|mut conn| {
        let mut streams = conn.streams();
        let id = streams
            .view()
            .resolve_recv(Id::new(10).expect("last permitted stream"))
            .expect("receive half");
        assert_eq!(
            streams
                .receive()
                .recv_owned(id)
                .expect("receive payload")
                .as_deref(),
            Some(bytes::RESIDENT_DATA)
        );
    });
}
