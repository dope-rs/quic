pub mod common;

use common::peer::Receiver;
use common::suite::peers::path::{self, MTU_CID};
use dope_quic::conn::Epoch;
use dope_quic::conn::wire::packet::Batch;
use dope_quic::errors::SendFailure;
use dope_quic::proto::datagram::Arena;
use std::time::{Duration, Instant};

#[test]
fn pre_handshake_unknown() {
    let (_server, mut client, _work) = path::try_mtu(65535, 65535)
        .expect("PMTU peers")
        .into_parts();
    assert!(
        client
            .with_scope(|mut scope| scope.datagrams().max_payload())
            .is_none()
    );
    let payload = b"x".to_vec();
    assert_eq!(
        client.with_scope(|mut scope| scope.datagrams().try_send(payload)),
        Err(SendFailure::Unsupported(b"x".to_vec()))
    );
}

#[test]
fn payload_tracks_mtu() {
    let mut pair = path::try_mtu(65535, 65535).expect("PMTU peers");
    pair.exchange(Instant::now(), 2)
        .expect("handshake transfer");
    let (_server, mut client, _work) = pair.into_parts();
    let max = client
        .with_scope(|mut scope| scope.datagrams().max_payload())
        .expect("post-handshake limit");
    let bytes = usize::try_from(client.view().path().mtu()).expect("path MTU must fit usize");
    let expected = Arena::payload_max(bytes, MTU_CID.len()).expect("routed datagram capacity");
    assert_eq!(max, expected);
}

#[test]
fn probes_raise_mtu() {
    let mut pair = path::try_mtu(65_535, 65_535).expect("PMTU peers");
    let start = Instant::now();
    pair.exchange(start, 2).expect("handshake transfer");
    let (mut server, mut client, mut work) = pair.into_parts();

    for step in 1..=16 {
        let now = start + Duration::from_millis(step * 10);
        Receiver::receive_from(&mut server, &mut work, &mut client, now)
            .expect("peer packet transfer");
        Receiver::receive_from(&mut client, &mut work, &mut server, now)
            .expect("peer packet transfer");
        if client.view().path().mtu() > 1_200 && server.view().path().mtu() > 1_200 {
            break;
        }
    }

    for conn in [&mut client, &mut server] {
        let mtu = conn.view().path().mtu();
        assert!(mtu > 1_200, "a protected probe ACK must advance PMTU");
        assert!(
            mtu <= 1_500,
            "discovery must preserve the configured ceiling"
        );
        let expected =
            Arena::payload_max(mtu as usize, MTU_CID.len()).expect("routed datagram capacity");
        assert_eq!(
            conn.with_scope(|mut scope| scope.datagrams().max_payload())
                .expect("negotiated DATAGRAM support"),
            expected,
            "the public payload limit and the congestion-owned PMTU cannot diverge",
        );
    }
}

#[test]
fn probe_loss() {
    let (mut server, mut client, mut work) = path::try_mtu(65_535, 65_535)
        .expect("PMTU peers")
        .into_parts();
    let start = Instant::now();
    let mut batch = Batch::default();
    for turn in 0..8 {
        let now = start + Duration::from_millis(turn * 100);
        client
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 64, 1_200))
            .expect("client handshake within base MTU");
        server
            .receive_all(&mut work, &mut batch, now)
            .expect("client flight");
        server
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 64, 1_200))
            .expect("server handshake within base MTU");
        client
            .receive_all(&mut work, &mut batch, now)
            .expect("server flight");
    }
    assert!(client.view().lifecycle().is_ready());
    assert_eq!(client.view().recovery().in_flight(), 0);

    for attempt in 0..4 {
        let probe_at = start + Duration::from_secs(2 + attempt * 2);
        let window = client.view().recovery().window();
        let (packets, send_result) = client.with_scope(|mut scope| scope.output().send(probe_at));
        send_result.expect("PMTU probe");
        assert_eq!(packets.len(), 1);
        let probe = packets[0].len() as u64;
        assert_eq!(probe, if attempt < 3 { 1_350 } else { 1_274 });

        let sent_at = probe_at + Duration::from_secs(1);
        let lost = if attempt == 3 {
            client
                .with_scope(|mut scope| scope.datagrams().try_send(vec![0; 32]))
                .expect("ordinary loss payload");
            client
                .with_scope(|mut scope| scope.output().send_batch(&mut batch, sent_at, 1, 1_200))
                .expect("ordinary lost packet");
            assert_eq!(batch.packets(), 1);
            batch.iter_mut().next().expect("one lost packet").len() as u64
        } else {
            0
        };
        for value in 0..3 {
            client
                .with_scope(|mut scope| scope.datagrams().try_send(vec![value; 32]))
                .expect("delivered payload");
        }
        let now = sent_at + Duration::from_millis(10);
        client
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 3, 1_200))
            .expect("packets beyond the probe loss threshold");
        assert_eq!(batch.packets(), 3);
        let passed: u64 = batch.iter_mut().map(|packet| packet.len() as u64).sum();
        assert_eq!(client.view().recovery().in_flight(), probe + lost + passed,);
        server
            .receive_all(&mut work, &mut batch, now)
            .expect("ordinary packets");

        let ack_at = now + Duration::from_millis(25);
        server
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, ack_at, 64, 1_200))
            .expect("ACK within base MTU");
        assert!(!batch.is_empty());
        client
            .receive_all(&mut work, &mut batch, ack_at)
            .expect("loss feedback");
        let expected = if lost == 0 {
            window + passed
        } else {
            (window + passed) / 2
        };
        assert!(
            expected > 2_400,
            "ordinary loss must not collapse to the minimum window",
        );
        assert_eq!(client.view().recovery().window(), expected);
        assert_eq!(client.view().recovery().in_flight(), 0);
        assert_eq!(client.view().recovery().unacked(Epoch::Application), 0);
        assert_eq!(client.view().path().mtu(), 1_200);
    }
}

/// The final server handshake flight contains its first PMTU probe. At the
/// delayed-ACK deadline the client acknowledges that probe and emits its own
/// probe, leaving the server with one pending ACK and a new search step.
#[test]
fn ack_reuses_probe() {
    let mut pair = path::try_mtu(65_535, 65_535).expect("PMTU peers");
    let start = Instant::now() + Duration::from_secs(1);
    pair.exchange(start, 2).expect("handshake transfer");
    let (mut server, mut client, mut work) = pair.into_parts();

    let now = start + Duration::from_millis(30);
    Receiver::receive_from(&mut server, &mut work, &mut client, now).expect("peer packet transfer");
    assert!(
        client.view().recovery().unacked(Epoch::Application) > 0,
        "the client PMTU probe must be awaiting its peer ACK",
    );

    let (mut output, send_result) = server.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("warmed server journals must admit its PMTU probe");
    assert_eq!(
        output.len(),
        1,
        "pending ACK debt must consume probe padding, not another datagram",
    );
    assert!(
        output[0].len() > 1_200,
        "the single output must be the next PMTU search probe",
    );
    client
        .with_scope(|mut scope| {
            scope
                .input(&mut work)
                .recv_packet(&mut output[0], now, |_: &rustls::Error| {})
        })
        .expect("client must receive the emitted server probe");
    assert_eq!(
        client.view().recovery().unacked(Epoch::Application),
        0,
        "the probe must carry the exact pending ACK on the wire",
    );
}

#[test]
fn payload_respects_peer() {
    let mut pair = path::try_mtu(65535, 100).expect("PMTU peers");
    pair.exchange(Instant::now(), 2)
        .expect("handshake transfer");
    let (_server, mut client, _work) = pair.into_parts();
    let max = client
        .with_scope(|mut scope| scope.datagrams().max_payload())
        .expect("post-handshake limit");
    assert_eq!(max, 99);
    assert!(
        client
            .with_scope(|mut scope| scope.datagrams().try_send(vec![0; 99]))
            .is_ok()
    );
    let payload = vec![0; 100];
    assert_eq!(
        client.with_scope(|mut scope| scope.datagrams().try_send(payload)),
        Err(SendFailure::TooLarge(vec![0; 100]))
    );
}

#[test]
fn zero_peer_limit_rejects() {
    let mut pair = path::try_mtu(65535, 0).expect("PMTU peers");
    pair.exchange(Instant::now(), 2)
        .expect("handshake transfer");
    let (_server, mut client, _work) = pair.into_parts();
    let payload = vec![0; 10];
    assert_eq!(
        client.with_scope(|mut scope| scope.datagrams().try_send(payload)),
        Err(SendFailure::Unsupported(vec![0; 10]))
    );
}

#[test]
fn cwnd_tracks_flight() {
    let (mut server, mut client, mut work) = path::try_mtu(65535, 65535)
        .expect("PMTU peers")
        .into_parts();
    let t0 = Instant::now();

    let (emitted_packets, send_result) = client.with_scope(|mut scope| scope.output().send(t0));
    send_result.expect("fresh client journals must admit its Initial");
    for mut p in emitted_packets {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut p, t0, |_: &rustls::Error| {})
            })
            .expect("server must receive the emitted client Initial");
    }
    assert!(
        client.view().recovery().in_flight() >= 1200,
        "Initial in flight"
    );

    let (emitted_packets, send_result) = server.with_scope(|mut scope| scope.output().send(t0));
    send_result.expect("fresh server journals must admit its handshake flight");
    for mut p in emitted_packets {
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(&mut p, t0, |_: &rustls::Error| {})
            })
            .expect("client must receive the emitted server flight");
    }
    assert_eq!(
        client.view().recovery().unacked(Epoch::Initial),
        0,
        "client Initial acked or discarded"
    );
}
