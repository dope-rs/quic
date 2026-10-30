use crate::common::peer;
use common::suite::peers::config::Parameters as _;
pub mod common;
use dope_quic::conn::life::options::Options;
use std::time::{Duration, Instant};

use dope_test::alloc::Tracker;
use peer::Bind as _;
use peer::Scope as _;
use peer::{Pair, Receiver as _, warm::send::Batches};

#[test]
fn first_state() {
    let pair = Pair::try_default();
    let mut client = pair.expect("test precondition").client;

    let sample = Tracker::begin();
    let stream = client
        .send_streams()
        .open_uni()
        .expect("fixture client must retain its first send-stream slot");
    let activity = sample.finish();

    assert_eq!(
        activity.allocations, 0,
        "first send-stream state allocation size {}",
        activity.allocated_bytes
    );
    client
        .send_streams()
        .finish(stream)
        .expect("new send stream must finish once");
}

#[test]
fn delayed_ack() {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_new(
        Options::try_send().expect("fixture configuration bounds"),
        Options::try_send().expect("fixture configuration bounds"),
    )
    .expect("test precondition");
    let mut batches = Batches::default();
    let mut received = Vec::with_capacity(4_096);
    let start = Instant::now() + Duration::from_secs(6);
    let streams = [
        client
            .send_streams()
            .open_uni()
            .expect("first warm send-stream slot must be available"),
        client
            .send_streams()
            .open_uni()
            .expect("second warm send-stream slot must be available"),
    ];
    for &stream in &streams {
        client
            .send_streams()
            .send(stream, &[0x60; 4_096])
            .expect("warm stream credit must admit its payload");
        client
            .send_streams()
            .finish(stream)
            .expect("warm send stream must finish once");
    }
    let mut done = start;
    for turn in 0..16 {
        let now = start + Duration::from_millis(turn * 10);
        server
            .receive_from(&mut work, &mut client, now)
            .expect("warm stream packets must pass server ingress");
        client
            .receive_from(&mut work, &mut server, now)
            .expect("warm stream acknowledgements must pass client ingress");
        done = now;
    }
    for stream in streams {
        let peer = stream.bind(&server).expect("warm peer stream must resolve");
        received.clear();
        assert_eq!(server.recv().recv(peer, &mut received), Ok(4_096));
        assert!(
            server
                .stream_state()
                .recv_eof(peer)
                .expect("completed warm receive stream must retain state")
        );
    }
    let mut sent_at = done + Duration::from_secs(1);
    for round in 0..2 {
        let sample = (round == 1).then(Tracker::begin);
        let victim = client
            .send_streams()
            .open_uni()
            .expect("victim send-stream slot must be available");
        let anchor = client
            .send_streams()
            .open_uni()
            .expect("anchor send-stream slot must be available");
        client
            .send_streams()
            .send(victim, &[0x61; 64])
            .expect("victim stream credit must admit its payload");
        client
            .send_streams()
            .finish(victim)
            .expect("victim send stream must finish once");
        client
            .send_streams()
            .send(anchor, &[0x62; 4_096])
            .expect("anchor stream credit must admit its payload");

        client
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.original, sent_at, 1, 1_200)
            })
            .expect("warmed client journals must admit the original stream packet");
        assert_eq!(batches.original.packets(), 1);
        server
            .receive_all(&mut work, &mut batches.original, sent_at)
            .expect("original stream packet must pass server ingress");
        let ack_at = server
            .view()
            .recovery()
            .send_at(sent_at + Duration::from_millis(1));
        server
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.first_ack, ack_at, 1, 1_200)
            })
            .expect("warmed server journals must admit the first stream acknowledgement");
        assert!(!batches.first_ack.is_empty());

        let deadline = client
            .view()
            .recovery()
            .next_timer()
            .expect("unacknowledged stream packet must arm PTO");
        let probe_at = deadline + Duration::from_millis(1);
        assert_eq!(
            client.with_scope(|mut scope| scope.recovery().try_loss(probe_at)),
            Ok(())
        );
        client
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.probe, probe_at, 1, 1_200)
            })
            .expect("warmed client journals must admit the stream probe");
        assert_eq!(batches.probe.packets(), 1);
        server
            .receive_all(&mut work, &mut batches.probe, probe_at)
            .expect("stream probe must pass server ingress");
        let late_at = server
            .view()
            .recovery()
            .send_at(probe_at + Duration::from_millis(30));
        server
            .with_scope(|mut scope| {
                scope
                    .output()
                    .send_batch(&mut batches.late_ack, late_at, 1, 1_200)
            })
            .expect("warmed server journals must admit the late stream acknowledgement");
        assert!(!batches.late_ack.is_empty());

        let retire = late_at + Duration::from_millis(1);
        client
            .receive_all(&mut work, &mut batches.first_ack, retire)
            .expect("first stream acknowledgement must pass client ingress");
        let next = client
            .send_streams()
            .open_uni()
            .expect("victim slot must be reusable while the anchor remains live");
        client
            .send_streams()
            .send(next, &[0x63; 128])
            .expect("replacement stream credit must admit its payload");
        client
            .send_streams()
            .finish(next)
            .expect("replacement send stream must finish once");
        client
            .receive_all(&mut work, &mut batches.late_ack, retire)
            .expect("late stream acknowledgement must pass client ingress");
        client
            .send_streams()
            .finish(anchor)
            .expect("anchor send stream must finish once");

        let mut done = retire;
        for turn in 1..=16 {
            done = batches
                .drain
                .try_exchange(
                    &mut client,
                    &mut server,
                    &mut work,
                    retire + Duration::from_millis(turn * 10),
                )
                .expect("drain flight");
        }

        for (stream, byte, length) in [(victim, 0x61, 64), (anchor, 0x62, 4_096), (next, 0x63, 128)]
        {
            let peer = stream
                .bind(&server)
                .expect("completed peer stream must resolve");
            received.clear();
            assert_eq!(server.recv().recv(peer, &mut received), Ok(length));
            assert_eq!(received.len(), length);
            assert!(received.iter().all(|&value| value == byte));
            assert!(
                server
                    .stream_state()
                    .recv_eof(peer)
                    .expect("completed receive stream must retain state")
            );
        }
        assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
        if let Some(sample) = sample {
            let activity = sample.finish();
            assert_eq!(
                activity.allocations, 0,
                "delayed-ACK send-schedule reuse allocation size {}",
                activity.allocated_bytes
            );
        }
        sent_at = done + Duration::from_secs(1);
    }
}

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();
