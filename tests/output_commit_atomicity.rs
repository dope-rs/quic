use crate::common::peer;
pub mod common;
use common::suite::peers::config::Parameters as _;
use dope_quic::conn::life::options::Options;
use std::array;
use std::time::{Duration, Instant};

use dope_quic::conn::wire::packet::Batch;
use peer::Config;
use peer::Pair;

#[test]
fn retains_pending_journal() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_new(
        Options::try_journal().expect("fixture configuration bounds"),
        Options::try_journal().expect("fixture configuration bounds"),
    )
    .expect("constrained peers must establish");
    let now = Instant::now() + Duration::from_secs(1);

    client.with_scope(|mut scope| {
        let mut out = scope.datagrams();
        out.try_send(vec![0x31; 1_150])
            .expect("first datagram fits the queue");
        out.try_send(vec![0x32; 1_150])
            .expect("second datagram fits the queue");
    });

    let (mut first, result) = client.with_scope(|mut scope| scope.output().send(now));
    result.expect("the journal must admit its remaining packet");
    assert_eq!(
        first.len(),
        1,
        "one tracked packet must consume the only currently admissible journal slot"
    );
    let (blocked, result) =
        client.with_scope(|mut scope| scope.output().send(now + Duration::from_millis(1)));
    result.expect("the reserved PTO slot defers data before journal admission");
    assert!(
        blocked.is_empty(),
        "ordinary data must leave the PTO slot available"
    );

    let packet = (first.first_mut()).expect("the committed flight must retain its packet");
    assert!(
        server
            .with_scope(|mut scope| scope.input(&mut work).recv_packet(packet, now, |_| {}))
            .is_ok(),
        "the first datagram must reach the peer"
    );
    let ack_at = now + Duration::from_millis(30);
    let (packets, result) = server.with_scope(|mut scope| scope.output().send(ack_at));
    result.expect("the server must admit the capacity-restoring ACK");
    for mut packet in packets {
        let result = client.with_scope(|mut scope| {
            scope
                .input(&mut work)
                .recv_packet(&mut packet, ack_at, |_| {})
        });
        assert!(
            result.is_ok(),
            "the acknowledgement must restore journal capacity"
        );
    }

    let resume = ack_at + Duration::from_millis(1);
    let (resumed, result) = client.with_scope(|mut scope| scope.output().send(resume));
    result.expect("returned capacity must admit the pending datagram");
    assert_eq!(
        resumed.len(),
        1,
        "the uncommitted datagram must remain pending until journal capacity returns"
    );
    for mut packet in resumed {
        let result = server.with_scope(|mut scope| {
            scope
                .input(&mut work)
                .recv_packet(&mut packet, resume, |_| {})
        });
        assert!(result.is_ok(), "the preserved datagram must reach the peer");
    }
    for byte in [0x31, 0x32] {
        let payload = server
            .with_scope(|mut scope| scope.datagrams().recv())
            .expect("journal backpressure preserves each queued datagram");
        assert_eq!(payload, vec![byte; 1_150]);
    }
    assert!(
        server
            .with_scope(|mut scope| scope.datagrams().recv())
            .is_none()
    );
}

#[test]
fn control_full_is_atomic() {
    const CONTROL_CAPACITY: usize = 32;
    let options = || {
        (Config::default()
            .try_build()
            .expect("fixture configuration must satisfy its declared bounds")
            .into_builder()
            .journals(|journals| journals.control::<CONTROL_CAPACITY>())
            .try_build())
        .expect("fixture configuration must satisfy its declared bounds")
    };
    let config = options();
    let delay = Duration::from_millis(u64::from(config.params().timing().ack_ms()));
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_new(config, options()).expect("the constrained fixture pair must establish");
    let tokens: [[u8; 8]; CONTROL_CAPACITY + 1] =
        array::from_fn(|index| (index as u64).to_ne_bytes());
    for token in tokens {
        client
            .with_scope(|mut scope| scope.path().try_probe(token))
            .expect("the path queue must retain every challenge");
    }

    let now = Instant::now() + Duration::from_secs(1);
    let (mut packets, result) = client.with_scope(|mut scope| scope.output().send(now));
    result.expect("available control capacity must admit the first flight");
    assert!(!packets.is_empty());
    let (blocked, result) = client.with_scope(|mut scope| scope.output().send(now + delay));
    result.expect("control backpressure preserves queued work");
    assert!(
        blocked.is_empty(),
        "a full journal must publish no new packet"
    );
    assert!(
        tokens
            .iter()
            .all(|token| !client.view().path().has_token(token))
    );

    let mut at = now + delay;
    for _ in 0..CONTROL_CAPACITY {
        for packet in &mut packets {
            assert!(
                server
                    .with_scope(|mut scope| scope.input(&mut work).recv_packet(packet, at, |_| {}))
                    .is_ok(),
                "admitted challenges must reach the peer"
            );
        }
        at += delay;
        let (replies, result) = server.with_scope(|mut scope| scope.output().send(at));
        result.expect("responses must return control capacity");
        for mut reply in replies {
            let result = client
                .with_scope(|mut scope| scope.input(&mut work).recv_packet(&mut reply, at, |_| {}));
            assert!(
                result.is_ok(),
                "responses must retire their original challenge"
            );
        }
        if tokens
            .iter()
            .all(|token| client.view().path().has_token(token))
        {
            break;
        }
        at = client.view().recovery().send_at(at + delay);
        let (next, result) = client.with_scope(|mut scope| scope.output().send(at));
        result.expect("returned capacity must admit the preserved challenges");
        packets = next;
        assert!(!packets.is_empty(), "unvalidated challenges must resume");
    }
    assert!(
        tokens
            .iter()
            .all(|token| client.view().path().has_token(token))
    );
}

#[test]
fn small_probe_keeps_cursor() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_default().expect("probe peers must establish");
    client.with_scope(|mut client| {
        server.with_scope(|mut server| {
            let sent_at = Instant::now() + Duration::from_secs(1);
            let stream = (client.streams().send().open_uni())
                .expect("the default credit must open one stream");
            let peer = (server.streams().view().resolve_recv(stream.id()))
                .expect("the peer must accept this stream direction");
            client
                .streams()
                .send()
                .send(stream, &[0x5a; 900])
                .expect("the probe payload fits stream credit");
            client
                .streams()
                .send()
                .finish(stream)
                .expect("the stream must finish once");

            let mut dropped = Batch::default();
            client
                .output()
                .send_batch(&mut dropped, sent_at, 1, 1_200)
                .expect("the initial flight fits the journal");
            assert_eq!(dropped.packets(), 1);

            let deadline = (client.view().recovery().next_timer())
                .expect("the dropped stream packet must arm PTO");
            let probe_at = deadline + Duration::from_millis(1);
            assert_eq!(client.recovery().try_loss(probe_at), Ok(()));

            let mut small = Batch::default();
            client
                .output()
                .send_batch(&mut small, probe_at, 1, 128)
                .expect("the small probe fits the journal");
            assert_eq!(
                small.packets(),
                1,
                "the first PTO allowance emits a non-stream probe"
            );

            let mut fitting = Batch::default();
            client
                .output()
                .send_batch(&mut fitting, probe_at, 1, 1_200)
                .expect("the fitting probe retains the pending payload");
            assert_eq!(
                fitting.packets(),
                1,
                "the unencoded stream probe must remain selected for the next fitting packet"
            );
            for packet in fitting.iter_mut() {
                assert!(
                    server
                        .input(&mut work)
                        .recv_packet(packet, probe_at, |_| {})
                        .is_ok(),
                    "the fitting probe must reach the peer"
                );
            }

            let mut received = Vec::new();
            let len = (server.streams().receive().recv(peer, &mut received))
                .expect("the stream probe must resolve at the server");
            assert_eq!(len, 900);
            assert_eq!(received, vec![0x5a; 900]);
        })
    });
}
