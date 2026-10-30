pub mod common;

use common::{
    receive::cancel::Proof,
    suite::peers::packet::{Pair, bytes},
};
use dope_quic::{
    conn::life::options::Options,
    errors::{
        Code,
        detail::{Diagnostic, Plan, Slot},
    },
    proto::param,
    wire::{
        frame::{Borrowed, Boundary, Length},
        stream::Id,
        varint::VarInt,
    },
};
use std::time::Instant;

#[test]
fn shares_one_resident() {
    for (control, stopped) in [
        (bytes::RESIDENT_CREDIT, None),
        (bytes::RESIDENT_STOP, Some(Code::from_u8(7))),
    ] {
        let now = Instant::now();
        let params = param::Set::builder()
            .initial_data(4)
            .local_bidi(1)
            .remote_bidi(1)
            .bidi_count(1)
            .try_build()
            .expect("one peer stream");
        let options = Options::builder()
            .transport(|net| net.params(params))
            .streams(|streams| streams.local_bidi(0).local_uni(0).recv_parts(1))
            .try_build()
            .expect("one resident slot");
        let mut pair = Pair::try_options(options, now, |_| {}).expect("peer handshake");
        let id = Id::new(0).expect("peer stream identifier");
        let mut frames = Vec::new();
        Borrowed::stream(
            id,
            VarInt::ZERO,
            Boundary::More,
            Length::Explicit,
            bytes::RESIDENT_DATA,
        )
        .expect("bounded stream")
        .encode(&mut frames)
        .expect("stream frame");
        frames.extend_from_slice(control);
        pair.receive(&frames, now).expect("both stream halves");
        pair.server.with_scope(|mut conn| {
            let mut streams = conn.streams();
            let stream = streams.view().resolve_bidi(id).expect("peer stream");
            assert_eq!(streams.view().stopped(stream.send()), stopped);
            assert_eq!(
                streams
                    .receive()
                    .recv_owned(stream.receive())
                    .expect("resident receiver")
                    .as_deref(),
                Some(bytes::RESIDENT_DATA),
            );
        });
    }
}

#[test]
fn waits_for_event_release() {
    let now = Instant::now();
    let params = param::Set::builder()
        .initial_data(4)
        .stream_uni(1)
        .uni_count(1)
        .try_build()
        .expect("one peer stream");
    let options = Options::builder()
        .transport(|net| net.params(params))
        .streams(|streams| streams.local_bidi(0).local_uni(0).recv_parts(1))
        .try_build()
        .expect("one resident slot");
    let mut pair = Pair::try_options(options, now, |_| {}).expect("peer handshake");
    let mut frames = Vec::new();
    Borrowed::stream(
        Id::new(2).expect("first peer stream identifier"),
        VarInt::ZERO,
        Boundary::More,
        Length::Explicit,
        bytes::RESIDENT_DATA,
    )
    .expect("bounded stream")
    .encode(&mut frames)
    .expect("stream frame");
    pair.receive(&frames, now).expect("first resident");
    pair.receive(bytes::RESIDENT_RESET, now)
        .expect("peer reset");
    pair.retired(now).expect("deliver additional stream credit");

    let id = Id::new(6).expect("next peer stream identifier");
    frames.clear();
    Borrowed::stream(
        id,
        VarInt::ZERO,
        Boundary::More,
        Length::Explicit,
        bytes::RESIDENT_DATA,
    )
    .expect("bounded stream")
    .encode(&mut frames)
    .expect("stream frame");
    let mut packet = pair.peer.packet(&frames).expect("new stream packet");
    let mut rejected = Proof(None, |_: &rustls::Error| {});
    pair.server
        .with_scope(|mut conn| {
            conn.input(&mut pair.work)
                .recv_with(&mut packet, now, &mut rejected)
        })
        .expect("resident capacity drop");
    assert!(matches!(
        rejected.0,
        Some(Diagnostic::Plan(Plan::Capacity {
            slot: Slot::Resident,
            needed: 1,
            available: 0,
        })),
    ));
    pair.server.with_scope(|mut conn| {
        let mut streams = conn.streams();
        assert!(streams.resident().handle(id).is_none());
        while streams.events().poll().is_some() {}
    });
    pair.receive(&frames, now)
        .expect("released resident capacity");
    pair.server.with_scope(|mut conn| {
        let mut streams = conn.streams();
        let stream = streams.view().resolve_recv(id).expect("new peer stream");
        assert_eq!(
            streams
                .receive()
                .recv_owned(stream)
                .expect("resident receiver")
                .as_deref(),
            Some(bytes::RESIDENT_DATA),
        );
    });
}
