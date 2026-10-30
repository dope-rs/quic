use crate::common::peer;
use common::suite::peers::config::Parameters as _;
use common::suite::peers::tls;
use dope_quic::conn::life::options::Options;
pub mod common;
use dope_quic::runtime::routing::Plain;
use dope_quic::wire::frame;
use o3::buffer::storage;
use std::time::{Duration, Instant};

use dope_quic::conn::Epoch;
use dope_quic::conn::life::accept;
use dope_quic::conn::wire::packet::Batch;
use dope_quic::wire::packet::cid;
use dope_quic::{conn, conn::Connection};
use dope_test::alloc::Tracker;
use peer::Initial;
use peer::Pair;
use peer::Scope as _;

#[test]
fn warmed_paths() {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_new(
        Options::try_steady().expect("allocation fixture transport parameters"),
        Options::try_steady().expect("allocation fixture transport parameters"),
    )
    .expect("test precondition");
    let payload = vec![0x5a; 4096];
    let stream = client
        .send_streams()
        .open_bidi()
        .expect("fixture client must retain one bidirectional stream slot");
    client
        .send_streams()
        .send(stream, &payload)
        .expect("fixture flow credit must admit the warmed payload");
    let mut batch = Batch::default();
    let now = Instant::now() + Duration::from_secs(1);
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 1, 1200))
        .expect("warmed client journals must admit the first stream packet");
    assert_eq!(batch.packets(), 1);

    let sample = Tracker::begin();
    client
        .with_scope(|mut scope| {
            scope
                .output()
                .send_batch(&mut batch, now + Duration::from_secs(1), 1, 1200)
        })
        .expect("warmed client journals must admit the measured stream packet");
    let activity = sample.finish();

    assert_eq!(batch.packets(), 1);
    assert_eq!(
        activity.allocations, 0,
        "last allocation size {}",
        activity.allocated_bytes
    );

    let at = now + Duration::from_secs(2);
    let mut packet = client
        .with_scope(|mut scope| {
            let (packets, result) = scope.output().send(at);
            result.expect("warmed client journals must admit the queued stream packet");
            packets
        })
        .into_iter()
        .next()
        .expect("warmed connection must emit its queued stream packet");
    let mut copy = packet.clone();
    assert!(
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut packet, at, |_: &rustls::Error| {})
            })
            .is_ok(),
        "first stream packet must pass server ingress"
    );

    let sample = Tracker::begin();
    assert!(
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut copy, at, |_: &rustls::Error| {})
            })
            .is_ok(),
        "duplicate authenticated packet must be discarded cleanly"
    );
    let activity = sample.finish();

    assert_eq!(
        activity.allocations, 0,
        "last allocation size {}",
        activity.allocated_bytes
    );
}

#[test]
fn maximal_receive() {
    const INITIAL_DCID: [u8; 8] = [0x81; 8];
    const CLIENT_SCID: [u8; 8] = [0x82; 8];
    const SERVER_CID: [u8; 8] = [0x83; 8];

    let (signing, _) = peer::raw(0x84).expect("fixture server identity");
    let config = signing.server().expect("fixture server TLS configuration");
    let mut server = accept::Authority::<0>::new(
        config,
        Options::try_steady().expect("allocation fixture transport parameters"),
    )
    .expect("fixture key and options must form a server authority")
    .accept::<storage::Shared>(accept::Ids::initial(
        cid::Id::try_from(INITIAL_DCID).expect("initial DCID must be valid"),
        cid::Id::try_from(SERVER_CID).expect("server CID must be valid"),
        cid::Id::try_from(CLIENT_SCID).expect("client CID must be valid"),
    ))
    .expect("three valid fixture IDs must start a server connection");
    let mut work = conn::Workspace::try_new().expect("receive workspace allocation");
    let now = Instant::now();
    let warm = Initial::new(&INITIAL_DCID, &CLIENT_SCID, 0).seal(&[frame::TYPE_PING]);
    let mut warm = (warm).expect("test precondition");
    assert!(
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut warm, now, |_: &rustls::Error| {})
            })
            .is_ok(),
        "warm Initial PING must pass server ingress"
    );

    let frames = [frame::TYPE_PING; 256];
    let packet = Initial::new(&INITIAL_DCID, &CLIENT_SCID, 1).seal(&frames);
    let mut packet = (packet).expect("test precondition");
    let sample = Tracker::begin();
    assert!(
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut packet, now, |_: &rustls::Error| {})
            })
            .is_ok(),
        "maximal validated Initial plan must pass server ingress"
    );
    let activity = sample.finish();

    assert_eq!(
        activity.allocations, 0,
        "maximal receive plan allocation size {}",
        activity.allocated_bytes
    );
}

#[test]
fn initial_pto() {
    let cid = cid::Id::try_from([0x72; 8]).expect("eight-byte fixture CID must be valid");
    let (_, key) = peer::raw(0x38).expect("fixture server identity");
    let mut client = tls::client(key)
        .expect("fixture client authority")
        .connect::<0, Vec<u8>, storage::Shared>(
            cid,
            cid,
            Options::try_steady().expect("allocation fixture transport parameters"),
            Plain,
        )
        .expect("fixture peer key, IDs, and options must start a client connection");
    let mut batch = Batch::default();
    let sent_at = Instant::now();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, sent_at, 1, 1_200))
        .expect("fresh client journals must admit Initial CRYPTO");
    assert_eq!(batch.packets(), 1);
    let deadline = client
        .view()
        .recovery()
        .next_timer()
        .expect("unacknowledged Initial CRYPTO must arm PTO");

    let sample = Tracker::begin();
    assert_eq!(
        client.with_scope(|mut scope| scope.recovery().try_loss(deadline)),
        Ok(())
    );
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, deadline, 1, 1_200))
        .expect("warmed client journals must admit the Initial CRYPTO probe");
    let activity = sample.finish();

    assert_eq!(batch.packets(), 1);
    assert_eq!(
        activity.allocations, 0,
        "Initial CRYPTO PTO allocation size {}",
        activity.allocated_bytes
    );
}

#[test]
fn application_pto() {
    let cid = cid::Id::try_from([0x73; 8]).expect("eight-byte fixture CID must be valid");
    let (signing, key) = peer::raw(0x37).expect("fixture server identity");
    let options = Options::try_steady().expect("allocation fixture transport parameters");
    let mut config = signing.server().expect("fixture server TLS configuration");
    config.send_tls13_tickets = 1;
    let mut server = accept::Authority::<0>::new(config, options)
        .expect("fixture key and ticket options must form a server authority")
        .accept::<storage::Shared>(accept::Ids::initial(cid, cid, cid))
        .expect("three valid fixture IDs must start a server connection");
    let mut client: Connection = tls::client(key)
        .expect("fixture client authority")
        .connect::<0, Vec<u8>, storage::Shared>(
            cid,
            cid,
            Options::try_steady().expect("allocation fixture transport parameters"),
            Plain,
        )
        .expect("fixture peer key, IDs, and options must start a client connection");
    let mut work = conn::Workspace::try_new().expect("receive workspace allocation");
    let mut batch = Batch::default();
    let sent_at = Instant::now();

    for _ in 0..6 {
        for mut packet in client.with_scope(|mut scope| {
            let (packets, result) = scope.output().send(sent_at);
            result.expect("fixture client journals must admit handshake CRYPTO");
            packets
        }) {
            assert!(
                server
                    .with_scope(|mut scope| {
                        scope.input(&mut work).recv_packet(
                            &mut packet,
                            sent_at,
                            |_: &rustls::Error| {},
                        )
                    })
                    .is_ok(),
                "client handshake packet must pass server ingress"
            );
        }
        server
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, sent_at, 4, 1200))
            .expect("fixture server journals must admit handshake CRYPTO");
        for packet in batch.iter_mut() {
            if packet.first().is_some_and(|byte| byte & 0x80 == 0) {
                continue;
            }
            assert!(
                client
                    .with_scope(|mut scope| {
                        scope
                            .input(&mut work)
                            .recv_packet(packet, sent_at, |_: &rustls::Error| {})
                    })
                    .is_ok(),
                "server handshake packet must pass client ingress"
            );
        }
    }
    assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
    assert_ne!(server.view().recovery().unacked(Epoch::Application), 0);
    let deadline = server
        .view()
        .recovery()
        .next_timer()
        .expect("unacknowledged application CRYPTO must arm PTO");
    let probe_at = deadline + Duration::from_millis(1);

    let sample = Tracker::begin();
    assert_eq!(
        server.with_scope(|mut scope| scope.recovery().try_loss(probe_at)),
        Ok(())
    );
    server
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, probe_at, 4, 1200))
        .expect("warmed server journals must admit the application CRYPTO probe");
    let activity = sample.finish();

    assert!(!batch.is_empty());
    assert_eq!(
        activity.allocations, 0,
        "Application CRYPTO PTO allocation size {}",
        activity.allocated_bytes
    );
    for packet in batch.iter_mut() {
        assert!(
            client
                .with_scope(|mut scope| {
                    scope
                        .input(&mut work)
                        .recv_packet(packet, probe_at, |_: &rustls::Error| {})
                })
                .is_ok(),
            "application CRYPTO probe must pass client ingress"
        );
    }
    for mut packet in client.with_scope(|mut scope| {
        let (packets, result) = scope.output().send(probe_at);
        result.expect("warmed client journals must admit the application CRYPTO acknowledgement");
        packets
    }) {
        assert!(
            server
                .with_scope(|mut scope| {
                    scope.input(&mut work).recv_packet(
                        &mut packet,
                        probe_at,
                        |_: &rustls::Error| {},
                    )
                })
                .is_ok(),
            "client CRYPTO acknowledgement must pass server ingress"
        );
    }
}

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();
