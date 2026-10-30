use crate::common::peer;
use dope_quic::conn;
use dope_quic::runtime::mux::builder::{Builder, Plan};
pub mod common;
use common::runtime::gso::{self, Capture};
use dope_quic::wire::packet::cid;
use dope_test::harness::observe::VecCellExt as _;
use peer::Receiver as _;
use std::{
    pin::Pin,
    time::{Duration, Instant},
};

#[test]
fn same_destination_shares() {
    const CONNECTIONS: usize = 4;

    let (signing, key) = peer::raw(0x47).expect("raw identity");
    let options = || gso::options().expect("fixture connection options must be valid");
    let capture = gso::Capture::default();
    let peer = capture.events.clone();
    let mut server = Capture::server(capture, signing.server().expect("server TLS"), options())
        .expect("fixture server must initialize");
    let capture = gso::Capture::default();
    let local = capture.events.clone();
    let limits = Plan::try_new(CONNECTIONS, 64, 1 << 20).expect("route fixture limits are valid");
    let mut client = Builder::client(capture)
        .limits(limits)
        .build()
        .expect("fixture client router has valid limits");

    let mut now = Instant::now();
    for ordinal in 0..CONNECTIONS {
        assert!(
            Capture::connect(
                &mut client,
                gso::SERVER,
                key,
                options(),
                (ordinal as u64 + 1).to_be_bytes().to_vec(),
                now,
            )
            .is_ok(),
            "fixture connection must initialize"
        );
    }
    for _ in 0..16 {
        now += Duration::from_millis(1);
        Capture::deliver(
            &mut server,
            gso::CLIENT,
            Capture::output(&mut client, now).expect("fixture output"),
        )
        .expect("fixture packet delivery");
        Capture::deliver(
            &mut client,
            gso::SERVER,
            Capture::output(&mut server, now).expect("fixture output"),
        )
        .expect("fixture packet delivery");
    }
    assert_eq!(local.established.len(), CONNECTIONS);
    assert_eq!(peer.established.len(), CONNECTIONS);

    Capture::settle_pair(&mut client, &mut server, gso::CLIENT, gso::SERVER, &mut now)
        .expect("fixture pair settlement");

    assert!(
        Pin::new(&mut client).config().enable_gso().is_ok(),
        "fixture client supports GSO configuration"
    );
    let ready = local.established.take();
    let handles = ready.clone();
    local.established.set(ready);
    for lengths in [[1_150; CONNECTIONS], [0, 1, 2, 0]] {
        for (ordinal, handle) in handles.iter().copied().enumerate() {
            assert_eq!(
                client.inspect(handle, |_, _, conn| conn.inspection().tx_queued()),
                Some(0)
            );
            Capture::send(
                &mut client,
                handle,
                vec![ordinal as u8; lengths[ordinal]],
                now,
            )
            .expect("fixture datagram admission");
            assert_eq!(
                client.inspect(handle, |_, _, conn| conn.inspection().tx_queued()),
                Some(1)
            );
        }
        now = Capture::release_at(&client, &handles, now).expect("active fixture handle");

        let mut burst = Capture::output(&mut client, now).expect("fixture output");
        assert!(handles.iter().all(|&handle| {
            client.inspect(handle, |_, _, conn| conn.inspection().tx_queued()) == Some(0)
        }));
        assert_eq!(
            burst.len(),
            1,
            "equal protected sizes share one mux-owned flight"
        );
        assert_eq!(burst[0].packet_count().get(), CONNECTIONS);
        assert!(burst[0].is_segmented());
        for segment in burst[0].segments_mut() {
            if lengths[0] == 0 {
                assert_eq!(segment.len(), 29);
            }
            Capture::receive(&mut server, gso::CLIENT, segment, now).expect("fixture ingress");
            assert_eq!(segment[0] & 3, 0, "fixture uses one-byte packet numbers");
        }
        Pin::new(&mut server).observe(now, |mut turn| {
            assert!(
                turn.output().drive().is_ok(),
                "fixture server connections must admit routed datagram output"
            )
        });

        let mut seen = peer.datagrams.take();
        assert_eq!(seen.len(), CONNECTIONS);
        for (ordinal, &length) in lengths.iter().enumerate() {
            let index = seen
                .iter()
                .position(|(_, payload)| {
                    payload.len() == length && payload.iter().all(|byte| *byte == ordinal as u8)
                })
                .expect("each admitted payload must authenticate and arrive");
            seen.swap_remove(index);
        }
        peer.datagrams.set(seen);
        for flight in burst {
            Pin::new(&mut client).output().recycle(flight);
        }
        Capture::settle_pair(&mut client, &mut server, gso::CLIENT, gso::SERVER, &mut now)
            .expect("fixture pair settlement");
    }

    for (ordinal, handle) in handles.iter().copied().enumerate() {
        let bytes = if ordinal == 0 { 64 } else { 1_150 };
        Capture::send(&mut client, handle, vec![0xa0 + ordinal as u8; bytes], now)
            .expect("fixture datagram admission");
    }
    now = Capture::release_at(&client, &handles, now).expect("active fixture handle");
    let mut first = Capture::output(&mut client, now)
        .expect("fixture output")
        .into_iter()
        .next()
        .expect("the queued front must produce output");
    assert_eq!(first.packet_count().get(), 1);
    for segment in first.segments_mut() {
        Capture::receive(&mut server, gso::CLIENT, segment, now).expect("fixture ingress");
    }
    Pin::new(&mut server).observe(now, |mut turn| {
        turn.output()
            .drive()
            .expect("fixture datagram notification");
    });
    let seen = peer.datagrams.take();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].1.as_slice(),
        &[0xa0; 64],
        "an unmatched GSO front must retain its scalar turn"
    );
}

#[test]
fn mixed_cid_padding() {
    let cids = [vec![0x10; 8], vec![0x20; 7], vec![0x30; 6], vec![0x40; 5]];
    let lengths = [0, 3, 4, 5];
    let (signing, key) = peer::raw(0x47).expect("raw identity");
    let mut server = Capture::server(
        Capture::default(),
        signing.server().expect("server TLS"),
        gso::options().expect("fixture server options"),
    )
    .expect("fixture server must initialize");
    let mut now = Instant::now();
    let mut clients = Vec::new();
    for (ordinal, local) in cids.iter().enumerate() {
        let initial =
            cid::Id::try_from((ordinal as u64 + 1).to_be_bytes()).expect("eight-byte initial CID");
        let local = cid::Id::try_from(local.as_slice()).expect("fixture local CID");
        let client = Capture::connect_peer(
            &mut server,
            key,
            gso::options().expect("fixture client options"),
            initial,
            local,
            &mut now,
        )
        .expect("fixture direct client must establish");
        assert!(client.view().lifecycle().is_ready());
        clients.push(client);
    }
    let handles = server.handler().events.established.take();
    assert_eq!(handles.len(), clients.len());
    Pin::new(&mut server)
        .config()
        .enable_gso()
        .expect("fixture server supports GSO");
    for (ordinal, handle) in handles.iter().copied().enumerate() {
        Capture::send(
            &mut server,
            handle,
            vec![ordinal as u8; lengths[ordinal]],
            now,
        )
        .expect("fixture datagram admission");
    }
    now = Capture::release_at(&server, &handles, now).expect("active fixture handle");
    let mut burst = Capture::output(&mut server, now).expect("fixture output");
    assert_eq!(burst.len(), 1, "equal padded sizes share one flight");
    assert_eq!(burst[0].packet_count().get(), clients.len());
    assert!(burst[0].is_segmented());
    let mut work = conn::Workspace::try_new().expect("fixture receive workspace");
    let mut seen = [false; 4];
    for segment in burst[0].segments_mut() {
        assert_eq!(segment.len(), 29);
        let ordinal = cids
            .iter()
            .position(|cid| segment[1..].starts_with(cid))
            .expect("packet carries the admitted peer CID");
        assert!(!seen[ordinal]);
        seen[ordinal] = true;
        clients[ordinal]
            .receive(&mut work, segment, now)
            .expect("each segment must authenticate");
        assert_eq!(segment[0] & 3, 0, "fixture uses one-byte packet numbers");
        let payload = clients[ordinal]
            .with_scope(|mut scope| scope.datagrams().recv())
            .expect("each admitted datagram must arrive");
        assert_eq!(payload, vec![ordinal as u8; lengths[ordinal]]);
    }
    assert!(seen.into_iter().all(|present| present));
    assert!(handles.iter().all(|&handle| {
        server.inspect(handle, |_, _, conn| conn.inspection().tx_queued()) == Some(0)
    }));
}
