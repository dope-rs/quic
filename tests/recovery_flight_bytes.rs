pub mod common;

use common::peer::{Pair, Receiver, flight::PAYLOAD};
use dope_quic::conn::Epoch;
use dope_quic::conn::wire::packet::Batch;
use std::time::{Duration, Instant};

#[test]
fn accounts_flight() {
    let Pair {
        mut client,
        mut server,
        mut work,
    } = Pair::try_default().expect("peers");
    let start = Instant::now() + Duration::from_secs(1);
    for turn in 0..4 {
        let now = start + Duration::from_millis(turn * 100);
        assert!(server.receive_from(&mut work, &mut client, now).is_ok());
        assert!(client.receive_from(&mut work, &mut server, now).is_ok());
    }
    assert_eq!(client.view().recovery().in_flight(), 0);
    let mut batch = Batch::default();
    for turn in 1..=4 {
        for _ in 0..8 {
            client
                .with_scope(|mut scope| scope.datagrams().try_send(PAYLOAD.to_vec()))
                .expect("datagram");
        }
        let now = start + Duration::from_secs(turn);
        client
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 64, 1200))
            .expect("flight");
        let bytes: u64 = batch.iter_mut().map(|packet| packet.len() as u64).sum();
        assert_ne!(bytes, 0);
        assert_eq!(client.view().recovery().in_flight(), bytes);
        for packet in batch.iter_mut() {
            assert!(server.receive(&mut work, packet, now).is_ok());
        }
        let ack = now + Duration::from_millis(25);
        server
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, ack, 64, 1200))
            .expect("ack");
        for packet in batch.iter_mut() {
            assert!(client.receive(&mut work, packet, ack).is_ok());
        }
        assert_eq!(client.view().recovery().in_flight(), 0);
    }
}

#[test]
fn cutoff_before_clock() {
    let mut pair = Pair::try_default().expect("peers");
    let start = Instant::now();
    for turn in 0..4 {
        let now = start
            .checked_add(Duration::from_millis(turn * 100))
            .expect("handshake time");
        pair.exchange(now, 1).expect("settle handshake");
    }
    let (mut server, mut client, mut work) = pair.into_parts();
    assert_eq!(client.view().recovery().in_flight(), 0);
    assert_eq!(client.view().recovery().unacked(Epoch::Application), 0);

    let mut minimum = start;
    let steps = (0..u64::BITS)
        .rev()
        .map(|bit| Duration::from_secs(1_u64 << bit))
        .chain(
            (0..u64::BITS)
                .rev()
                .map(|bit| Duration::from_nanos(1_u64 << bit)),
        );
    for step in steps {
        if let Some(prior) = minimum.checked_sub(step) {
            minimum = prior;
        }
    }
    assert!(minimum.checked_sub(Duration::from_nanos(1)).is_none());

    let mut batch = Batch::default();
    let mut bytes = [0_u64; 7];
    for (ordinal, bytes) in bytes.iter_mut().enumerate() {
        client
            .with_scope(|mut scope| scope.datagrams().try_send(vec![0x42; 16 + (1 << ordinal)]))
            .expect("datagram");
        let sent = start
            .checked_add(Duration::from_millis(1_000 + ordinal as u64 * 100))
            .expect("packet time");
        client
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, sent, 1, 1_200))
            .expect("flight");
        assert_eq!(batch.packets(), 1);
        let packet = batch.iter_mut().next().expect("one packet");
        *bytes = packet.len() as u64;
        if ordinal == 6 {
            server
                .receive(&mut work, packet, sent)
                .expect("last packet");
        }
    }
    assert_eq!(client.view().recovery().unacked(Epoch::Application), 7);
    assert_eq!(
        client.view().recovery().in_flight(),
        bytes.iter().sum::<u64>()
    );
    let ack = start.checked_add(Duration::from_secs(2)).expect("ACK time");
    server
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, ack, 64, 1_200))
        .expect("ACK flight");
    assert!(!batch.is_empty());
    client
        .receive_all(&mut work, &mut batch, minimum)
        .expect("ACK before the clock origin");
    assert_eq!(client.view().recovery().unacked(Epoch::Application), 2);
    assert_eq!(client.view().recovery().in_flight(), bytes[4] + bytes[5]);
}

#[test]
fn scales_representable_rtt() {
    let mut pair = Pair::try_default().expect("peers");
    let start = Instant::now();
    for turn in 0..4 {
        pair.exchange(start + Duration::from_millis(turn * 100), 1)
            .expect("handshake");
    }
    let (mut server, mut client, mut work) = pair.into_parts();
    assert!(client.view().recovery().smoothed_rtt().is_some());

    let sent = start + Duration::from_secs(1);
    let mut sample = Duration::from_secs(u64::MAX / 9 + 1);
    let received = loop {
        if let Some(received) = sent.checked_add(sample) {
            break received;
        }
        sample /= 2;
    };
    client
        .with_scope(|mut scope| scope.datagrams().try_send(PAYLOAD.to_vec()))
        .expect("datagram");
    let mut batch = Batch::default();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, sent, 1, 1_200))
        .expect("flight");
    assert_eq!(client.view().recovery().unacked(Epoch::Application), 1);
    server
        .receive_all(&mut work, &mut batch, sent)
        .expect("packet");

    let ack = sent + Duration::from_millis(25);
    server
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, ack, 64, 1_200))
        .expect("ack");
    assert!(!batch.is_empty());
    client
        .receive_all(&mut work, &mut batch, received)
        .expect("large sample");
    assert_eq!(client.view().recovery().in_flight(), 0);
    assert_eq!(client.view().recovery().unacked(Epoch::Application), 0);
}
