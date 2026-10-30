use common::peer::Pair;
use common::peer::Receiver;
use common::peer::Scope as _;
use common::suite::peers::config;
pub mod common;

use std::time::{Duration, Instant};

#[test]
fn retains_high_water() {
    let (mut server, mut client, mut work) = Pair::try_new(
        config::try_ceiling().expect("server journal limits"),
        config::try_ceiling().expect("client journal limits"),
    )
    .expect("establish peers with journal limits")
    .into_parts();

    for backing in [client.view().journal(), server.view().journal()] {
        assert_eq!(backing.stream_bytes, 0);
        assert!(
            backing.total() < 128 * 1024,
            "an established idle connection retained {} bytes",
            backing.total()
        );
    }

    let now = Instant::now() + Duration::from_secs(1);
    let first = client
        .send_streams()
        .open_uni()
        .expect("first stream is within the configured limit");
    client
        .send_streams()
        .send(first, b"a")
        .expect("one byte fits the stream limit");
    client
        .send_streams()
        .finish(first)
        .expect("the live stream can finish");
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");

    let warmed = client.view().journal();
    assert_ne!(warmed.stream_bytes, 0);
    assert!(
        warmed.total() < 128 * 1024,
        "one live stream retained {} bytes",
        warmed.total()
    );

    Receiver::receive_from(
        &mut client,
        &mut work,
        &mut server,
        now + Duration::from_secs(1),
    )
    .expect("peer packet transfer");
    assert_eq!(
        client.view().journal().stream_bytes,
        warmed.stream_bytes,
        "ACK retirement must keep reusable connection-local backing"
    );

    let second = client
        .send_streams()
        .open_uni()
        .expect("second stream is within the configured limit");
    client
        .send_streams()
        .send(second, b"b")
        .expect("one byte fits the stream limit");
    client
        .send_streams()
        .finish(second)
        .expect("the live stream can finish");
    Receiver::receive_from(
        &mut server,
        &mut work,
        &mut client,
        now + Duration::from_secs(2),
    )
    .expect("peer packet transfer");
    assert_eq!(
        client.view().journal().stream_bytes,
        warmed.stream_bytes,
        "equal live concurrency must reuse the established high-water"
    );
}

#[test]
fn reuses_canceled_suffix() {
    use common::peer::Config;
    use common::suite::peers::packet;
    use dope_quic::{
        conn::{output::transmit, wire::packet::Batch},
        errors::Code,
        wire::{frame, varint::VarInt},
    };

    let options = Config::new(2, 128, 0, 34)
        .try_build()
        .expect("transport bounds")
        .into_builder()
        .streams(|streams| streams.local_bidi(0).local_uni(34).send_bytes(2))
        .journals(|journals| journals.stream::<33>())
        .try_build()
        .expect("journal bounds");
    let clock = Instant::now();
    let mut pair = packet::Pair::try_options(options, clock, |_| {}).expect("peers");
    pair.retired(clock).expect("settled handshake");
    let mut now = clock + Duration::from_secs(1);
    let mut batch = Batch::default();
    let mut backing = 0;

    for round in 0..33 {
        let stream = pair.server.send_streams().open_uni().expect("stream");
        let mut numbers = [0; 2];
        for (number, bytes) in numbers.iter_mut().zip([b"a", b"b"]) {
            pair.server
                .send_streams()
                .send(stream, bytes)
                .expect("send");
            now = pair.server.view().recovery().send_at(now);
            let effects = pair
                .server
                .with_scope(|mut scope| scope.output().send_effects(&mut batch, now, 1, 1200))
                .expect("stream packet");
            assert!(effects.contains(transmit::Effects::FRESH_STREAM));
            let wire = batch.iter_mut().next().expect("one stream packet");
            *number = pair.peer.open(wire).expect("authenticated packet").0;
        }

        let [prefix, suffix] = numbers;
        let mut acks = [Some(suffix), Some(prefix), None];
        for step in 0..acks.len() {
            let Some(number) = acks[step] else {
                break;
            };
            let mut ack = Vec::new();
            frame::Borrowed::ack(
                VarInt::try_from(number).expect("packet number"),
                VarInt::ZERO,
                VarInt::ZERO,
                &[],
            )
            .expect("ACK")
            .encode(&mut ack)
            .expect("encoded ACK");
            pair.receive(&ack, clock).expect("selected ACK");
            if number == suffix {
                assert_eq!(pair.server.stream_state().wire_bytes(), 2);
                pair.server
                    .send_streams()
                    .reset(stream, Code::ZERO)
                    .expect("reset");
                assert_eq!(pair.server.stream_state().wire_bytes(), 0);
                if round == 32 {
                    let next = pair.server.send_streams().open_uni().expect("fresh stream");
                    pair.server
                        .send_streams()
                        .send(next, b"c")
                        .expect("fresh byte");
                    now = pair.server.view().recovery().send_at(now);
                    let effects = pair
                        .server
                        .with_scope(|mut scope| {
                            scope.output().send_effects(&mut batch, now, 1, 1200)
                        })
                        .expect("fresh packet after node reclamation");
                    assert!(effects.contains(transmit::Effects::FRESH_STREAM));
                    let wire = batch.iter_mut().next().expect("one fresh packet");
                    acks[2] = Some(pair.peer.open(wire).expect("authenticated fresh packet").0);
                }
            }
            if round == 32 && step == 1 {
                assert_eq!(
                    pair.server.stream_state().wire_bytes(),
                    1,
                    "the late canceled ACK must retain the fresh byte",
                );
            }
            if step == 2 {
                assert_eq!(
                    pair.server.stream_state().wire_bytes(),
                    0,
                    "the fresh packet ACK must release its byte",
                );
            }
        }
        if round == 31 {
            backing = pair.server.view().journal().stream_bytes;
        }
    }

    assert_eq!(
        pair.server.view().journal().stream_bytes,
        backing,
        "canceled suffixes must reuse the full journal backing",
    );
}
