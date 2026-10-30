use crate::common::peer;
use common::suite::mux::Ignore;
use common::suite::mux::dispatch::{CID, Capture, SERVER};
use common::suite::peers::tls;
pub mod common;
use common::suite::peers::{config::Parameters as _, life};
use dope_quic::conn::life::options::Options;
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::runtime::routing;
use o3::buffer::storage;
use peer::Pair;
use peer::Receiver as _;

use std::{
    pin::Pin,
    time::{Duration, Instant},
};

use dope_quic::conn::wire::packet::Batch;
use dope_quic::conn::{Epoch, Error, Timing};
use dope_quic::wire::packet::cid;

#[test]
fn pto_full() {
    let opts = Options::builder()
        .journals(|limits| limits.packet::<2>())
        .try_build()
        .expect("two packet rows");
    let mut mux = Builder::client(Ignore).build().expect("client router");
    let now = Instant::now();
    let handle = Capture::connect(&mut mux, SERVER, [7; 32], opts, CID.to_vec(), now)
        .expect("client connection");
    let sent = Capture::output(&mut mux, now).expect("Initial output");
    assert_eq!(sent.len(), 1);
    let view = mux.conn(handle).expect("retained client").view();
    assert_eq!(view.recovery().unacked(Epoch::Initial), 1);
    let at = view.recovery().next_timer().expect("Initial PTO") + Duration::from_nanos(1);
    let probe = Capture::output(&mut mux, at).expect("reserved PTO output");
    assert_eq!(probe.len(), 1);
    let view = mux.conn(handle).expect("retained client").view();
    assert_eq!(view.recovery().unacked(Epoch::Initial), 2);
    assert!(
        Pin::new(&mut mux)
            .observe(at, |turn| turn.deadline())
            .is_none_or(|due| due > at),
        "a full packet journal must not retain immediate PTO work"
    );
    let rest = Capture::output(&mut mux, at).expect("blocked PTO output");
    assert!(rest.is_empty());
    let view = mux.conn(handle).expect("retained client").view();
    assert_eq!(view.recovery().unacked(Epoch::Initial), 2);
}

#[test]
fn pto_retries_initial() {
    let t0 = Instant::now();
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_open(
        Options::try_pto().expect("PTO fixture transport parameters"),
        Options::try_pto().expect("PTO fixture transport parameters"),
    )
    .expect("fixture peers must open");

    let (dropped, send_result) = client.with_scope(|mut scope| scope.output().send(t0));
    send_result.expect("fresh client journals must admit its Initial");
    assert_eq!(dropped.len(), 1);
    assert_eq!(
        client.view().recovery().unacked(Epoch::Initial),
        1,
        "client Initial in flight"
    );

    let deadline = (client.view().recovery().next_timer()).expect("PTO armed after sending");
    assert!(deadline > t0);

    let t1 = deadline + Duration::from_millis(1);
    assert_eq!(
        client.with_scope(|mut scope| scope.recovery().try_loss(t1)),
        Ok(())
    );
    let (mut probes, send_result) = client.with_scope(|mut scope| scope.output().send(t1));
    send_result.expect("warmed client journals must admit its Initial probes");
    assert_eq!(probes.len(), 2, "PTO produced two probes");
    assert_eq!(
        client.view().recovery().unacked(Epoch::Initial),
        3,
        "original and probes remain tracked"
    );

    assert!(
        server
            .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                &mut probes[0],
                t1,
                |_: &rustls::Error| {}
            ))
            .is_ok(),
        "server processes retransmitted Initial"
    );
    let (mut s_pkts, send_result) = server.with_scope(|mut scope| scope.output().send(t1));
    send_result.expect("fresh server journals must admit its handshake flight");
    for p in &mut s_pkts {
        assert!(
            client
                .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                    p,
                    t1,
                    |_: &rustls::Error| {}
                ))
                .is_ok(),
            "client must receive the emitted server handshake packet"
        );
    }
    let (mut c_pkts, send_result) = client.with_scope(|mut scope| scope.output().send(t1));
    send_result.expect("warmed client journals must admit its handshake flight");
    for p in &mut c_pkts {
        assert!(
            server
                .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                    p,
                    t1,
                    |_: &rustls::Error| {}
                ))
                .is_ok(),
            "server must receive the emitted client handshake packet"
        );
    }

    assert!(
        client.view().lifecycle().is_ready(),
        "client established after retransmit"
    );
    assert!(
        server.view().lifecycle().is_ready(),
        "server established after retransmit"
    );
}

#[test]
fn server_crypto_uses_pto() {
    let t0 = Instant::now();
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_open(
        Options::try_pto().expect("PTO fixture transport parameters"),
        Options::try_pto().expect("PTO fixture transport parameters"),
    )
    .expect("fixture peers must open");

    let (packets, send_result) = client.with_scope(|mut scope| scope.output().send(t0));
    send_result.expect("fresh client journals must admit its Initial");
    for mut packet in packets {
        assert!(
            server
                .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                    &mut packet,
                    t0,
                    |_: &rustls::Error| {}
                ))
                .is_ok(),
            "server must receive the emitted client Initial"
        );
    }
    let (mut dropped, send_result) = server.with_scope(|mut scope| scope.output().send(t0));
    send_result.expect("fresh server journals must admit its CRYPTO flight");
    assert!(
        dropped.len() >= 2,
        "server produced Initial and Handshake CRYPTO"
    );
    assert!(
        client
            .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                &mut dropped[0],
                t0,
                |_: &rustls::Error| {}
            ))
            .is_ok(),
        "client must receive the retained server Initial"
    );
    let (packets, send_result) = client.with_scope(|mut scope| scope.output().send(t0));
    send_result.expect("warmed client journals must admit its handshake packet");
    for mut packet in packets {
        assert!(
            server
                .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                    &mut packet,
                    t0,
                    |_: &rustls::Error| {}
                ))
                .is_ok(),
            "server must receive the emitted client handshake packet"
        );
    }
    assert_eq!(server.view().recovery().unacked(Epoch::Initial), 0);
    assert_ne!(server.view().recovery().unacked(Epoch::Handshake), 0);
    let deadline = (server.view().recovery().next_timer()).expect("server CRYPTO PTO");
    let probe_at = deadline + Duration::from_millis(1);
    assert_eq!(
        server.with_scope(|mut scope| scope.recovery().try_loss(probe_at)),
        Ok(())
    );
    let (mut probes, send_result) = server.with_scope(|mut scope| scope.output().send(probe_at));
    send_result.expect("warmed server journals must admit its CRYPTO probes");
    assert!(
        !probes.is_empty(),
        "PTO retransmits the dropped CRYPTO flight"
    );

    for packet in &mut probes {
        assert!(
            client
                .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                    packet,
                    probe_at,
                    |_: &rustls::Error| {}
                ))
                .is_ok(),
            "client must receive the server CRYPTO probe"
        );
    }
    let mut now = probe_at;
    for _ in 0..8 {
        let (packets, send_result) = client.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("fixture client journals must admit handshake progress");
        for mut packet in packets {
            assert!(
                server
                    .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                        &mut packet,
                        now,
                        |_: &rustls::Error| {}
                    ))
                    .is_ok(),
                "server must receive the emitted client packet"
            );
        }
        let (packets, send_result) = server.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("fixture server journals must admit handshake progress");
        for mut packet in packets {
            assert!(
                client
                    .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                        &mut packet,
                        now,
                        |_: &rustls::Error| {}
                    ))
                    .is_ok(),
                "client must receive the emitted server packet"
            );
        }
        if client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready() {
            break;
        }
        if Epoch::ALL
            .into_iter()
            .any(|space| server.view().recovery().unacked(space) != 0)
        {
            let deadline = (server.view().recovery().next_timer()).expect("next server CRYPTO PTO");
            now = deadline + Duration::from_millis(1);
            assert_eq!(
                server.with_scope(|mut scope| scope.recovery().try_loss(now)),
                Ok(())
            );
        }
        if Epoch::ALL
            .into_iter()
            .any(|space| client.view().recovery().unacked(space) != 0)
        {
            let deadline = (client.view().recovery().next_timer()).expect("next client CRYPTO PTO");
            now = now.max(deadline + Duration::from_millis(1));
            assert_eq!(
                client.with_scope(|mut scope| scope.recovery().try_loss(now)),
                Ok(())
            );
        }
    }

    assert!(client.view().lifecycle().is_ready());
    assert!(server.view().lifecycle().is_ready());
}

#[test]
fn pto_backoff_grows() {
    let (_, key) = peer::raw(0x39).expect("raw identity");
    let id = (cid::Id::try_from([0x42; 8])).expect("fixture CID must fit");
    let t0 = Instant::now();
    let mut client = (tls::client(key)
        .expect("client TLS authority")
        .connect::<0, Vec<u8>, storage::Shared>(
            id,
            id,
            Options::try_pto().expect("PTO fixture transport parameters"),
            routing::Plain,
        ))
    .expect("fixture client must open");

    assert!(
        matches!(client
            .with_scope(|mut scope| scope.output().send(t0)), (packets, Ok(())) if !packets.is_empty()),
        "fresh client journals must admit its Initial"
    );
    let pto1 = (client.view().recovery().next_timer()).expect("first PTO");

    let t1 = pto1 + Duration::from_millis(1);
    assert_eq!(
        client.with_scope(|mut scope| scope.recovery().try_loss(t1)),
        Ok(())
    );
    assert!(
        matches!(client
            .with_scope(|mut scope| scope.output().send(t1)), (packets, Ok(())) if !packets.is_empty()),
        "warmed client journals must admit its first PTO probes"
    );
    let pto2 = (client.view().recovery().next_timer()).expect("second PTO");
    let span1 = pto1.saturating_duration_since(t0);
    let span2 = pto2.saturating_duration_since(t1);
    assert!(
        span2 >= span1,
        "PTO backoff non-decreasing: {span1:?} -> {span2:?}"
    );

    let t2 = pto2 + Duration::from_millis(1);
    assert_eq!(
        client.with_scope(|mut scope| scope.recovery().try_loss(t2)),
        Ok(())
    );
    assert!(
        matches!(client
            .with_scope(|mut scope| scope.output().send(t2)), (packets, Ok(())) if !packets.is_empty()),
        "warmed client journals must admit its second PTO probes"
    );
    let pto3 = (client.view().recovery().next_timer()).expect("third PTO");
    let span3 = pto3.saturating_duration_since(t2);
    assert!(
        span3 > span2,
        "PTO backoff strictly increases: {span2:?} -> {span3:?}"
    );
}

#[test]
fn loss_collapses_window() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_new(
        Options::try_pto().expect("PTO fixture transport parameters"),
        Options::try_pto().expect("PTO fixture transport parameters"),
    )
    .expect("the congestion fixture must complete its handshake");
    let base = Instant::now() + Duration::from_secs(1);
    for step in 0..4 {
        let now = base + Duration::from_millis(step);
        assert!(server.receive_from(&mut work, &mut client, now).is_ok());
        assert!(client.receive_from(&mut work, &mut server, now).is_ok());
    }

    for sequence in 0..7u8 {
        assert!(
            client
                .with_scope(|mut scope| scope.datagrams().try_send(vec![sequence; 32]))
                .is_ok(),
            "established test client must accept every DATAGRAM"
        );
    }
    let mut last: Option<Vec<u8>> = None;
    for sequence in 0..7u64 {
        let sent_at = base + Duration::from_millis(100 + sequence * 400);
        let mut batch = Batch::default();
        assert!(
            client
                .with_scope(|mut scope| scope.output().send_batch(&mut batch, sent_at, 1, 1_200))
                .is_ok(),
            "warmed client journals must admit each spaced datagram"
        );
        assert_eq!(batch.packets(), 1, "one spaced packet at step {sequence}");
        if sequence == 6 {
            last = batch.iter_mut().next().map(|packet| packet.to_vec());
        }
    }

    let at = base + Duration::from_millis(2_500);
    let mut last = (last).expect("final spaced packet must be emitted");
    assert!(
        server
            .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                &mut last,
                at,
                |_: &rustls::Error| {}
            ))
            .is_ok(),
        "server must receive the final spaced packet"
    );
    let ack_at = at + Duration::from_millis(50);
    let (mut acks, send_result) = server.with_scope(|mut scope| scope.output().send(ack_at));
    send_result.expect("warmed server journals must admit the final acknowledgement");
    assert!(!acks.is_empty());
    for packet in &mut acks {
        assert!(
            client
                .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                    packet,
                    ack_at,
                    |_: &rustls::Error| {}
                ))
                .is_ok(),
            "client must receive the final acknowledgement"
        );
    }

    let mtu = client.view().path().mtu();
    assert_eq!(
        client.view().recovery().window(),
        mtu * 2,
        "a contiguous lost interval longer than 3 PTOs enters persistent congestion"
    );
}

#[test]
fn huge_ack_retains_losses() {
    let mut pair = life::try_pair(0).expect("idle-free peers");
    let start = Instant::now();
    pair.exchange(start, 6).expect("handshake");
    for turn in 0..4 {
        pair.exchange(start + Duration::from_millis(turn * 100), 1)
            .expect("settle handshake");
    }
    let (mut server, mut client, mut work) = pair.into_parts();
    assert_eq!(client.view().recovery().unacked(Epoch::Application), 0);
    let mut batch = Batch::default();
    let mut bytes = [0_u64; 4];
    for (ordinal, bytes) in bytes.iter_mut().enumerate() {
        client
            .with_scope(|mut scope| scope.datagrams().try_send(vec![0x42; 16 + (1 << ordinal)]))
            .expect("datagram");
        let sent = start + Duration::from_millis(1_000 + ordinal as u64 * 100);
        client
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, sent, 1, 1200))
            .expect("one flight packet");
        assert_eq!(batch.packets(), 1);
        *bytes = batch.byte_len() as u64;
        if ordinal == 3 {
            server
                .receive_all(&mut work, &mut batch, sent)
                .expect("last packet");
        }
    }
    assert_eq!(client.view().recovery().unacked(Epoch::Application), 4);
    let ack = start + Duration::from_secs(2);
    server
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, ack, 64, 1200))
        .expect("ACK flight");
    assert_eq!(batch.packets(), 1);
    let due = client.view().recovery().next_timer();
    let mut now = start;
    for bit in (0..u64::BITS).rev() {
        if let Some(next) = now.checked_add(Duration::from_secs(1_u64 << bit)) {
            now = next;
        }
    }
    let error = client
        .receive_all(&mut work, &mut batch, now)
        .expect_err("the real ACK must expose its timing horizon");
    let timing = match error {
        peer::Transfer::Input(Error::Timing(timing)) => Some(timing),
        _ => None,
    }
    .expect("the ACK must preserve its exact timing error");
    let (retained, flight) = match timing {
        Timing::Mul {
            duration,
            factor: 3,
        } => {
            assert!(duration.checked_mul(3).is_none());
            Some((3, bytes[..3].iter().sum::<u64>()))
        }
        Timing::Deadline {
            at,
            duration_secs,
            duration_nanos,
        } => {
            let duration = Duration::new(duration_secs, duration_nanos.get());
            assert_eq!(at, start + Duration::from_millis(1_100));
            assert!(at.checked_add(duration).is_none());
            Some((2, bytes[1] + bytes[2]))
        }
        _ => None,
    }
    .expect("the native horizon must fail period admission or the retained loss deadline");
    assert_eq!(
        client.view().recovery().unacked(Epoch::Application),
        retained
    );
    assert_eq!(client.view().recovery().in_flight(), flight);
    assert!(client.view().lifecycle().is_closed());
    assert!(!client.view().lifecycle().is_ready());
    assert_eq!(client.view().recovery().next_timer(), due);
}
