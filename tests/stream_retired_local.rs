pub mod common;

use common::peer::{Config, Pair, Receiver, Scope as _};
use common::receive::retained::Commit;
use common::suite::peers::packet::{self, bytes};
use dope_quic::conn;
use dope_quic::errors::Code;
use dope_quic::stream::send::{self, admit};
use dope_quic::wire::{
    frame,
    stream::{Direction, Id},
};
use std::time::{Duration, Instant};

#[test]
fn retired_local_stays_done() {
    let (mut server, mut client, mut wire) =
        Pair::try_default().expect("connected peers").into_parts();
    let id = client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let handle = streams
            .send()
            .open_handle(Direction::Bidi)
            .expect("local stream");
        assert!(streams.binding().try_attach(handle).is_ok());
        let parts = send::Parts::new(send::Buffer::Owned(vec![1]), None, send::Boundary::End);
        assert!(matches!(
            streams.try_write(handle, parts, Commit),
            admit::Outcome::Retained(id) if id == handle.id()
        ));
        handle.id()
    });
    let sent = Instant::now() + Duration::from_secs(1);
    Receiver::receive_from(&mut server, &mut wire, &mut client, sent).expect("FIN delivery");
    let ack = server
        .view()
        .recovery()
        .send_at(sent + Duration::from_millis(30));
    Receiver::receive_from(&mut client, &mut wire, &mut server, ack).expect("FIN acknowledgement");

    client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let handle = streams.resident().handle(id).expect("retained binding");
        let send = streams.view().resolve_send(id).expect("retired send");
        assert!(!streams.view().is_send_open(send));
        streams.binding().try_prepare(handle).expect("retired send");
        let parts = send::Parts::new(send::Buffer::Owned(vec![2]), None, send::Boundary::End);
        assert!(matches!(
            streams.try_write(handle, parts, Commit),
            admit::Outcome::Discarded(cause)
                if cause.source().id() == id && cause.cause() == admit::Cause::Retired
        ));
        let mut release = None;
        streams
            .try_reset(handle, Code::ZERO, &mut |event| release = Some(event))
            .expect("retired reset");
        assert!(release.is_none());
    });
}

#[test]
fn split_merge_reuse() {
    let mut config = Config::new(1 << 20, 1 << 20, 0, 512);
    config.local = Some([0, 512]);
    let mut pair = Pair::try_new(
        config.try_build().expect("server stream capacity"),
        config.try_build().expect("client stream capacity"),
    )
    .expect("connected peers");
    let mut now = Instant::now() + Duration::from_secs(1);

    for _ in 0..2 {
        let ids: Vec<_> = (0..512)
            .map(|_| {
                let stream = pair
                    .client
                    .send_streams()
                    .open_uni()
                    .expect("stream credit");
                pair.client
                    .send_streams()
                    .send(stream, b"x")
                    .expect("payload");
                pair.client
                    .send_streams()
                    .finish(stream)
                    .expect("stream FIN");
                stream.id()
            })
            .collect();
        for _ in 0..8 {
            now += Duration::from_millis(30);
            pair.exchange(now, 1).expect("paced stream FINs");
        }

        for start in [1, 2] {
            for index in (start..512).step_by(2).chain((start == 2).then_some(0)) {
                assert_eq!(
                    pair.server
                        .recv()
                        .recv_owned(ids[index])
                        .expect("retire completed stream")
                        .as_deref(),
                    Some(&b"x"[..]),
                    "stream {index}",
                );
            }
            for (index, &id) in ids.iter().enumerate() {
                assert_eq!(
                    pair.server.stream_state().recv_eof(id),
                    Ok(start == 2 || index % 2 == 1),
                );
            }
        }
        now += Duration::from_millis(30);
        pair.exchange(now, 2)
            .expect("return stream credit and acknowledge FINs");
    }
}

#[test]
fn held_eof_stays_done() {
    for invalid in [false, true] {
        let now = Instant::now();
        let mut config = Config::new(5, 5, 1, 0);
        config.local = Some([0, 0]);
        let mut pair =
            packet::Pair::try_options(config.try_build().expect("one receive slot"), now, |_| {})
                .expect("authenticated packet fixture");
        let id = Id::new(0).expect("client bidirectional stream");
        pair.receive(bytes::HELD_FIN, now).expect("final payload");
        let held = pair
            .server
            .recv()
            .hold(id)
            .expect("receive half")
            .expect("held payload");
        assert_eq!(held.as_ref(), b"held!");
        assert_eq!(pair.server.stream_state().recv_eof(id), Ok(true));
        pair.server.with_scope(|mut scope| {
            let mut streams = scope.streams();
            let send = streams.view().resolve_send(id).expect("send half");
            streams.send().finish(send).expect("reply FIN");
        });
        let retired = pair
            .server
            .view()
            .recovery()
            .send_at(now + Duration::from_secs(1));
        pair.retired(retired)
            .expect("reply FIN and its authenticated ACK");
        pair.receive(bytes::HELD_FIN, retired)
            .expect("fresh-number retransmission");
        assert!(
            pair.server
                .recv()
                .hold(id)
                .expect("retained receive half")
                .is_none()
        );
        assert_eq!(pair.server.stream_state().recv_eof(id), Ok(true));
        assert_eq!(held.as_ref(), b"held!");
        if invalid {
            let mut packet = pair
                .peer
                .packet(bytes::HELD_BAD_RESET)
                .expect("wrong final size");
            let result = pair.server.with_scope(|mut scope| {
                scope
                    .input(&mut pair.work)
                    .recv_packet(&mut packet, retired, |_| {})
            });
            assert!(matches!(result, Err(conn::Error::FinalSize)));
        }
        let retained = pair
            .server
            .release_held(held)
            .map_err(|cause| cause.kind())
            .expect("original credit remains releasable");
        if !invalid {
            let at = pair
                .server
                .view()
                .recovery()
                .send_at(retired + Duration::from_millis(30));
            let (packets, send_result) =
                pair.server.with_scope(|mut scope| scope.output().send(at));
            send_result.expect("released receive credit");
            let mut limits = (None, None);
            for packet in packets {
                let Some(mut packet) = pair.peer.receive(&packet).expect("credit packet") else {
                    continue;
                };
                let (_, body) = pair.peer.open(&mut packet).expect("authenticated credit");
                for frame in frame::Frame::decode_all(&body).expect("credit frames") {
                    match frame.view() {
                        frame::View::MaxData { maximum_data: max } => limits.0 = Some(max.get()),
                        frame::View::MaxStreams {
                            direction: Direction::Bidi,
                            max_streams: max,
                        } => {
                            limits.1 = Some(max.get());
                        }
                        _ => {}
                    }
                }
            }
            assert_eq!(limits, (Some(10), Some(2)));
            pair.receive(bytes::HELD_FIN, at)
                .expect("closed stream retransmission");
            assert!(
                pair.server
                    .recv()
                    .hold(id)
                    .expect("closed receive half")
                    .is_none()
            );
            assert_eq!(pair.server.stream_state().recv_eof(id), Ok(true));
            while pair.server.poll().poll_event().is_some() {}
            pair.receive(bytes::HELD_NEXT, at)
                .expect("recycled slot starts at zero");
            let next = Id::new(4).expect("next client bidirectional stream");
            assert_eq!(
                pair.server
                    .recv()
                    .recv_owned(next)
                    .expect("replacement payload")
                    .as_deref(),
                Some(&b"next!"[..])
            );
        }
        drop(pair);
        assert_eq!(retained.as_slice(), b"held!");
    }
}
