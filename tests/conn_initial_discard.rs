pub mod common;

use common::{
    peer::{Initial, Receiver as _, sealer::Raw},
    suite::{mux::retry, peers::life},
};
use dope_quic::{
    conn::wire::packet::Batch,
    security::qkdf,
    wire::{
        frame,
        packet::{
            self,
            long::{Parsed, Type, initial::Prefix},
        },
    },
};
use rustls::Side;
use std::time::{Duration, Instant};

#[test]
fn server_initial_loss() {
    for deliver in [false, true] {
        let mut pair = life::try_pair(0).expect("fixture must disable both idle timers");
        let now = Instant::now();
        let (mut initial, send_result) =
            pair.client.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("client Initial");
        let prefix = Prefix::decode(initial.first().expect("client Initial packet"))
            .expect("client Initial prefix");
        let opener = qkdf::Initial::try_new(prefix.dcid.into_slice())
            .expect("initial derivation")
            .try_server()
            .expect("server key admission");
        for packet in &mut initial {
            pair.server
                .receive(&mut pair.work, packet, now)
                .expect("server must receive the client Initial");
        }
        let mut first = Batch::default();
        pair.server
            .with_scope(|mut scope| scope.output().send_batch(&mut first, now, 2, 1200))
            .expect("server must emit its first flight");
        assert_eq!(first.packets(), 2);
        let mut first: Vec<_> = first.iter().map(|packet| packet.to_vec()).collect();
        for packet in &mut first {
            if deliver
                && packet[0] & packet::FORM_LONG != 0
                && Parsed::parse(packet.as_slice())
                    .expect("server long packet")
                    .kind()
                    == Type::Handshake
            {
                pair.client
                    .receive(&mut pair.work, packet, now)
                    .expect("client must ignore Handshake packets before the server Initial");
            }
        }
        let mut at = pair
            .server
            .view()
            .recovery()
            .next_timer()
            .expect("server PTO");
        pair.server
            .with_scope(|mut scope| scope.recovery().try_loss(at))
            .expect("server must arm its retransmission");
        let (retry, send_result) = pair.server.with_scope(|mut scope| scope.output().send(at));
        send_result.expect("server must retransmit the lost first flight");
        for (phase, flight) in [("first flight", &first), ("PTO", &retry)] {
            let mut elicits = false;
            for packet in flight {
                if packet[0] & packet::FORM_LONG == 0 {
                    continue;
                }
                let Parsed::Initial(initial) =
                    Parsed::parse(packet.clone()).expect("server long packet")
                else {
                    continue;
                };
                let opened = initial
                    .decrypt(&opener, 0)
                    .expect("server Initial must authenticate");
                if frame::Frame::decode_all(opened.body())
                    .expect("server Initial frames")
                    .iter()
                    .any(|frame| {
                        matches!(frame.view(), frame::View::Crypto { .. } | frame::View::Ping)
                    })
                {
                    assert!(packet.len() >= 1200, "{phase}: ack-eliciting Initial floor");
                    elicits = true;
                }
            }
            assert!(elicits, "{phase} must contain CRYPTO or PING Initial");
        }
        for mut packet in retry {
            pair.client
                .receive(&mut pair.work, &mut packet, at)
                .expect("client must receive the server retransmission");
        }
        for _ in 0..8 {
            pair.exchange(at, 1)
                .expect("recovered handshake must advance");
            if pair.try_ready().is_ok() {
                break;
            }
            at = [
                pair.client.view().recovery().next_timer(),
                pair.server.view().recovery().next_timer(),
            ]
            .into_iter()
            .flatten()
            .min()
            .expect("incomplete handshake must retain a timer")
            .max(at);
            for conn in [&mut pair.client, &mut pair.server] {
                conn.with_scope(|mut scope| scope.recovery().try_loss(at))
                    .expect("handshake recovery must advance");
            }
        }
        pair.try_ready()
            .expect("lost server Initial must not stall the handshake");
    }
}

#[test]
fn padded_ack_in_flight() {
    let (_, mut client, mut work) = life::try_pair(0)
        .expect("fixture must disable both idle timers")
        .into_parts();
    let now = Instant::now();
    let (initial, send_result) = client.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("client Initial");
    let prefix = Prefix::decode(initial.first().expect("client Initial packet"))
        .expect("client Initial prefix");
    let mut seal =
        Raw::initial(prefix.dcid.into_slice(), Side::Server, 0).expect("server Initial keys");
    let opener = qkdf::Initial::try_new(prefix.dcid.into_slice())
        .expect("initial derivation")
        .try_client()
        .expect("client key admission");
    let pto = client
        .view()
        .recovery()
        .next_timer()
        .expect("outstanding client CRYPTO must retain PTO");
    let window = client.view().recovery().window();
    let mut at = now;
    let mut ack = Batch::default();
    let mut blocked = false;
    for number in 0..=window / 1200 {
        at = client
            .view()
            .recovery()
            .send_at(at + Duration::from_millis(1));
        assert!(at < pto, "ACK fixture must not expire the CRYPTO PTO");
        let mut ping = Initial::new(prefix.scid.into_slice(), prefix.dcid.into_slice(), number)
            .seal_with(&[frame::TYPE_PING], &mut seal)
            .expect("fresh authenticated server Initial PING");
        client
            .receive(&mut work, &mut ping, at)
            .expect("client must authenticate the PING without CRYPTO");
        let before = client.view().recovery().in_flight();
        client
            .with_scope(|mut scope| scope.output().send_batch(&mut ack, at, 1, 1200))
            .expect("client ACK admission");
        assert_eq!(client.view().recovery().next_timer(), Some(pto));
        if window.saturating_sub(before) < 1200 {
            assert!(ack.is_empty(), "padding must obey the congestion window");
            assert_eq!(client.view().recovery().in_flight(), before);
            blocked = true;
            break;
        }
        let bytes = ack.byte_len() as u64;
        let packet = ack.iter_mut().next().expect("padded ACK must be emitted");
        assert!(packet.len() >= 1200);
        let packet = match Parsed::parse(packet).expect("client Initial ACK") {
            Parsed::Initial(packet) => Some(packet),
            _ => None,
        }
        .expect("client ACK must remain Initial");
        let opened = packet
            .decrypt(&opener, 0)
            .expect("client Initial ACK must authenticate");
        let mut body = opened.body();
        let mut has_ack = false;
        let mut has_pad = false;
        while !body.is_empty() {
            let (frame, used) = frame::Frame::decode_ref(body).expect("client ACK frames");
            let view = frame.view();
            assert!(matches!(
                view,
                frame::View::Ack { .. } | frame::View::Padding
            ));
            has_ack |= matches!(view, frame::View::Ack { .. });
            has_pad |= matches!(view, frame::View::Padding);
            body = &body[used..];
        }
        assert!(has_ack && has_pad);
        assert_eq!(client.view().recovery().in_flight(), before + bytes);
    }
    assert!(blocked, "repeated padded ACKs must fill the window");
}

#[test]
fn retry_ack_no_pad() {
    let (_, mut client, mut work) = life::try_pair(0)
        .expect("fixture must disable both idle timers")
        .into_parts();
    let now = Instant::now();
    let (initial, send_result) = client.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("client Initial");
    let prefix = Prefix::decode(initial.first().expect("client Initial packet"))
        .expect("client Initial prefix");
    let token = [0x91; 1151];
    let mut wire = retry::try_wire(
        prefix.dcid.into_slice(),
        prefix.scid.into_slice(),
        &retry::CLIENT_CID,
        &token,
    )
    .expect("authenticated Retry");
    client
        .receive(&mut work, &mut wire, now)
        .expect("client must accept the fitting Retry");
    let window = client.view().recovery().window();
    let mut at = now;
    let mut batch = Batch::default();
    for _ in 0..window / 1200 {
        at = client
            .view()
            .recovery()
            .send_at(at + Duration::from_millis(1));
        client
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, at, 1, 1200))
            .expect("retried CRYPTO must fill the window");
        assert_eq!(batch.byte_len(), 1200);
    }
    assert_eq!(client.view().recovery().in_flight(), window);
    let pto = client
        .view()
        .recovery()
        .next_timer()
        .expect("retried CRYPTO must retain PTO");
    at = client
        .view()
        .recovery()
        .send_at(at + Duration::from_millis(1));
    assert!(at < pto);
    let mut seal = Raw::initial(&retry::CLIENT_CID, Side::Server, 0).expect("retried server keys");
    let mut ping = Initial::new(prefix.scid.into_slice(), &retry::CLIENT_CID, 0)
        .seal_with(&[frame::TYPE_PING], &mut seal)
        .expect("authenticated server PING after Retry");
    client
        .receive(&mut work, &mut ping, at)
        .expect("client must authenticate the PING");
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, at, 1, 1200))
        .expect("unpadded ACK must pass a full window");
    assert_eq!(batch.byte_len(), 1200);
    assert_eq!(client.view().recovery().in_flight(), window);
    assert_eq!(client.view().recovery().next_timer(), Some(pto));
    let packet = batch.iter_mut().next().expect("client Initial ACK");
    let head = Prefix::decode(packet).expect("retried Initial prefix");
    assert_eq!(head.token, token);
    assert_eq!(head.dcid.len(), 8);
    assert_eq!(head.scid.len(), 8);
    let packet = match Parsed::parse(packet).expect("retried Initial ACK") {
        Parsed::Initial(packet) => Some(packet),
        _ => None,
    }
    .expect("ACK must remain Initial");
    let opener = qkdf::Initial::try_new(&retry::CLIENT_CID)
        .expect("initial derivation")
        .try_client()
        .expect("client key admission");
    let opened = packet
        .decrypt(&opener, 0)
        .expect("retried client ACK must authenticate");
    let (_, packet, body) = opened.into_parts();
    assert_eq!(packet[0] & 3, 0);
    let body = &packet[body];
    let (frame, used) = frame::Frame::decode_ref(body).expect("minimal ACK frame");
    assert!(matches!(frame.view(), frame::View::Ack { .. }));
    assert_eq!(used, 5);
    assert_eq!(body.len(), used);
}

#[test]
fn probe_discards_initial() {
    let (mut server, mut client, mut work) = life::try_pair(0)
        .expect("fixture must disable both idle timers")
        .into_parts();
    let now = Instant::now();
    let (mut initial, send_result) = client.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("client Initial");
    let prefix = Prefix::decode(initial.first().expect("client Initial packet"))
        .expect("client Initial prefix");
    let mut seal =
        Raw::initial(prefix.dcid.into_slice(), Side::Server, 1).expect("server Initial keys");
    let mut ping = Initial::new(prefix.scid.into_slice(), prefix.dcid.into_slice(), 1)
        .seal_with(&[frame::TYPE_PING], &mut seal)
        .expect("fresh server Initial PING");
    for packet in &mut initial {
        server
            .receive(&mut work, packet, now)
            .expect("client Initial delivery");
    }
    let (reply, send_result) = server.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("server first flight");
    for mut packet in reply {
        if packet[0] & packet::FORM_LONG != 0
            && Parsed::parse(packet.as_slice())
                .expect("server long packet")
                .kind()
                == Type::Initial
        {
            client
                .receive(&mut work, &mut packet, now)
                .expect("server Initial delivery");
        }
    }
    let at = client
        .view()
        .recovery()
        .next_timer()
        .expect("client Handshake fallback PTO");
    client
        .with_scope(|mut scope| scope.recovery().try_loss(at))
        .expect("Handshake PTO");
    let mut probe = Batch::default();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut probe, at, 1, 1200))
        .expect("first Handshake must fit one PTO packet");
    assert_eq!(probe.packets(), 1);
    for packet in probe.iter_mut() {
        assert!(
            packet[0] & packet::FORM_LONG != 0
                && Parsed::parse(&*packet).expect("probe long packet").kind() == Type::Handshake
        );
    }
    client
        .receive(&mut work, &mut ping, at)
        .expect("retired Initial must be ignored");
    let (after, send_result) = client.with_scope(|mut scope| scope.output().send(at));
    send_result.expect("remaining Handshake probe");
    assert!(
        after.iter().all(|packet| {
            packet[0] & packet::FORM_LONG == 0
                || Parsed::parse(packet.as_slice())
                    .expect("client long packet")
                    .kind()
                    != Type::Initial
        }),
        "first Handshake PTO output must retire Initial keys and ACK state"
    );
}
