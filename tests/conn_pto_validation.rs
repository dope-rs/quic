pub mod common;

use common::peer::{Initial, Receiver as _, sealer::Raw};
use common::suite::peers::life;
use dope_quic::conn::{Epoch, wire::packet::Batch};
use dope_quic::wire::{
    frame,
    packet::long::{self, initial},
    varint::VarInt,
};
use std::time::{Duration, Instant};

#[test]
fn initial_ack_arms_probe() {
    let pair = life::try_pair(0).expect("fixture must disable both idle timers");
    let (mut server, mut client, mut work) = pair.into_parts();
    let now = Instant::now();
    let (mut sent, send_result) = client.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("client must emit its complete Initial flight");
    assert!(!sent.is_empty());
    assert_eq!(client.view().recovery().unacked(Epoch::Initial), sent.len());
    let prefix = initial::Prefix::decode(sent.first().expect("Initial packet"))
        .expect("client Initial prefix");
    let mut seal = Raw::initial(prefix.dcid.into_slice(), rustls::Side::Server, 0)
        .expect("server Initial keys");
    let last = VarInt::try_from(sent.len() - 1).expect("emitted Initial packet number");
    let mut frames = Vec::new();
    frame::Borrowed::ack(last, VarInt::ZERO, last, &[])
        .expect("ACK must cover exactly the emitted Initial flight")
        .encode(&mut frames)
        .expect("ACK frame allocation");
    let mut ack = Initial::new(prefix.scid.into_slice(), prefix.dcid.into_slice(), 0)
        .seal_with(&frames, &mut seal)
        .expect("server must authenticate its Initial ACK");
    let mut repeat = Initial::new(prefix.scid.into_slice(), prefix.dcid.into_slice(), 1)
        .seal_with(&frames, &mut seal)
        .expect("server must authenticate the same ACK in a fresh packet");
    for packet in &mut sent {
        server
            .receive(&mut work, packet, now)
            .expect("server must authenticate the acknowledged Initial");
    }

    let ack_at = now + Duration::from_millis(10);
    client
        .receive(&mut work, &mut ack, ack_at)
        .expect("client must authenticate the ACK-only Initial");
    assert!(!client.view().lifecycle().is_ready());
    assert!(!client.view().lifecycle().is_confirmed());
    for epoch in [Epoch::Initial, Epoch::Handshake, Epoch::Application] {
        assert_eq!(client.view().recovery().unacked(epoch), 0);
    }
    assert_eq!(client.view().recovery().in_flight(), 0);
    assert_eq!(
        client.view().recovery().smoothed_rtt(),
        Some(Duration::from_millis(10))
    );
    let due = ack_at + Duration::from_millis(30);
    assert_eq!(
        client.view().recovery().next_timer(),
        Some(due),
        "unvalidated client must arm fallback from the current ACK time"
    );
    client
        .receive(&mut work, &mut repeat, ack_at + Duration::from_millis(5))
        .expect("client must authenticate the fresh packet with duplicate ACK");
    assert_eq!(
        client.view().recovery().smoothed_rtt(),
        Some(Duration::from_millis(10))
    );
    assert_eq!(
        client.view().recovery().next_timer(),
        Some(due),
        "duplicate Initial ACK must preserve the fallback deadline"
    );
    assert!(
        {
            let (emitted_packets, send_result) =
                client.with_scope(|mut scope| scope.output().send(due - Duration::from_nanos(1)));
            send_result.expect("no output before fallback expires");
            emitted_packets
        }
        .is_empty()
    );
    client
        .with_scope(|mut scope| scope.recovery().try_loss(due))
        .expect("fallback must arm an Initial probe");
    let mut batch = Batch::default();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, due, 1, 1200))
        .expect("fallback must emit its Initial probe");
    assert_eq!(batch.packets(), 1);
    assert_eq!(client.view().recovery().unacked(Epoch::Initial), 1);
    for packet in batch.iter_mut() {
        assert!(
            long::Parsed::parse(&*packet)
                .expect("probe must be a valid long packet")
                .kind()
                == long::Type::Initial
        );
        server
            .receive(&mut work, packet, due)
            .expect("server must authenticate the fallback probe");
    }
}

#[test]
fn initial_ack_backoff() {
    let pair = life::try_pair(0).expect("fixture must disable both idle timers");
    let (mut server, mut client, mut work) = pair.into_parts();
    let now = Instant::now();
    let (sent, send_result) = client.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("client must emit its Initial packet");
    assert_eq!(sent.len(), 1);
    let prefix = initial::Prefix::decode(sent.first().expect("Initial packet"))
        .expect("client Initial prefix");
    let mut seal = Raw::initial(prefix.dcid.into_slice(), rustls::Side::Server, 0)
        .expect("server Initial keys");
    let mut ack = Vec::new();
    frame::Borrowed::ack(VarInt::from_u8(1), VarInt::ZERO, VarInt::ZERO, &[])
        .expect("ACK must cover only the first probe packet")
        .encode(&mut ack)
        .expect("ACK frame allocation");
    let mut ack = Initial::new(prefix.scid.into_slice(), prefix.dcid.into_slice(), 0)
        .seal_with(&ack, &mut seal)
        .expect("server must authenticate its Initial ACK");
    let fired = client
        .view()
        .recovery()
        .next_timer()
        .expect("original Initial must arm PTO")
        + Duration::from_millis(1);
    client
        .with_scope(|mut scope| scope.recovery().try_loss(fired))
        .expect("Initial PTO must arm probes");
    let (mut probes, send_result) = client.with_scope(|mut scope| scope.output().send(fired));
    send_result.expect("client must emit both Initial probes");
    assert_eq!(probes.len(), 2);
    assert_eq!(client.view().recovery().unacked(Epoch::Initial), 3);
    for packet in &probes {
        assert!(
            long::Parsed::parse(packet.as_slice())
                .expect("probe must be a valid long packet")
                .kind()
                == long::Type::Initial
        );
    }
    server
        .receive(
            &mut work,
            probes.first_mut().expect("first Initial probe"),
            fired,
        )
        .expect("server must authenticate the acknowledged first probe");

    let ack_at = fired + Duration::from_millis(10);
    client
        .receive(&mut work, &mut ack, ack_at)
        .expect("client must authenticate the ACK-only Initial");
    assert!(!client.view().lifecycle().is_ready());
    assert!(!client.view().lifecycle().is_confirmed());
    assert_eq!(client.view().recovery().unacked(Epoch::Initial), 1);
    assert_eq!(client.view().recovery().unacked(Epoch::Handshake), 0);
    assert_eq!(client.view().recovery().unacked(Epoch::Application), 0);
    assert_eq!(
        client.view().recovery().smoothed_rtt(),
        Some(Duration::from_millis(10))
    );
    assert_eq!(
        client.view().recovery().next_timer(),
        Some(fired + Duration::from_millis(60)),
        "Initial ACK must preserve PTO backoff until server validation"
    );
}
