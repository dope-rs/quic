use crate::common::peer;
use common::suite::peers::tls;
pub mod common;
use common::suite::peers::config::Parameters as _;
use dope_quic::conn::life::options::Options;
use dope_quic::runtime::routing;
use o3::buffer::storage;

use std::time::{Duration, Instant};

use dope_quic::conn::Epoch;
use dope_quic::conn::output::transmit;
use dope_quic::wire::packet::cid;
use o3::depot::capacity;
use peer::Pair;

#[test]
fn crypto_slot_probes() {
    let options = (Options::try_pto()
        .expect("PTO fixture transport parameters")
        .into_builder()
        .journals(|limits| limits.crypto::<1>())
        .try_build())
    .expect("one CRYPTO slot is a valid journal capacity");
    let (_, key) = peer::raw(0x39).expect("raw identity");
    let id = (cid::Id::try_from([0x42; 8])).expect("fixture CID must fit");
    let mut client = (tls::client(key)
        .expect("client TLS authority")
        .connect::<0, Vec<u8>, storage::Shared>(id, id, options, routing::Plain))
    .expect("fixture client must open");
    let now = Instant::now();
    let (first, send_result) = client.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("one fresh CRYPTO record must fit one vacant slot");
    assert_eq!(first.len(), 1);
    let deadline =
        (client.view().recovery().next_timer()).expect("the in-flight Initial must arm PTO");
    let at = deadline + Duration::from_millis(1);
    assert_eq!(
        client.with_scope(|mut scope| scope.recovery().try_loss(at)),
        Ok(())
    );
    let (probes, send_result) = client.with_scope(|mut scope| scope.output().send(at));
    send_result.expect("existing CRYPTO carriers need no vacant slot");
    assert_eq!(probes.len(), 2);
    assert_eq!(client.view().recovery().unacked(Epoch::Initial), 3);
}

#[test]
fn crypto_full_keeps_bytes() {
    let options = (Options::try_pto()
        .expect("PTO fixture transport parameters")
        .into_builder()
        .journals(|limits| limits.crypto::<1>())
        .try_build())
    .expect("one CRYPTO slot is a valid journal capacity");
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_open(
        options,
        Options::try_pto().expect("PTO fixture transport parameters"),
    )
    .expect("fixture peers must open");
    let now = Instant::now();
    let (initial, send_result) = client.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("the client Initial must fit");
    for mut packet in initial {
        assert!(
            server
                .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                    &mut packet,
                    now,
                    |_: &rustls::Error| {}
                ))
                .is_ok()
        );
    }
    let (packets, send_result) = server.with_scope(|mut scope| scope.output().send(now));
    let cause = send_result.expect_err("second CRYPTO epoch must exceed the single journal slot");
    assert_eq!(
        cause,
        transmit::Error::Admission(transmit::Admission::Crypto {
            needed: 1,
            reason: capacity::Reason::Full
        })
    );
    assert!(
        !packets.is_empty(),
        "the first epoch was committed before the second admission"
    );
    assert!(
        server
            .view()
            .recovery()
            .next_timer()
            .is_some_and(|deadline| deadline < now + Duration::from_secs(30)),
        "the committed first epoch must arm PTO before the idle deadline"
    );
    for mut packet in packets {
        assert!(
            client
                .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                    &mut packet,
                    now,
                    |_: &rustls::Error| {}
                ))
                .is_ok()
        );
    }
    let at = now + Duration::from_millis(1);
    let (acks, send_result) = client.with_scope(|mut scope| scope.output().send(at));
    send_result.expect("the committed first epoch must be acknowledgeable");
    assert!(!acks.is_empty());
    for mut packet in acks {
        assert!(
            server
                .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                    &mut packet,
                    at,
                    |_: &rustls::Error| {}
                ))
                .is_ok()
        );
    }
    let (packets, send_result) = server.with_scope(|mut scope| scope.output().send(at));
    send_result.expect("reclaimed capacity must admit the untouched handshake bytes");
    assert!(!packets.is_empty());
    for mut packet in packets {
        assert!(
            client
                .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                    &mut packet,
                    at,
                    |_: &rustls::Error| {}
                ))
                .is_ok()
        );
    }
    assert!(client.view().lifecycle().is_ready());
}

#[test]
fn ack_releases_crypto() {
    for probe in [false, true] {
        let options = (Options::try_pto()
            .expect("PTO fixture transport parameters")
            .into_builder()
            .journals(|limits| limits.crypto::<1>())
            .try_build())
        .expect("one CRYPTO slot is a valid journal capacity");
        let Pair {
            mut server,
            mut client,
            mut work,
        } = Pair::try_open(
            Options::try_pto().expect("PTO fixture transport parameters"),
            options,
        )
        .expect("fixture peers must open");
        let now = Instant::now();
        let (initial, send_result) = client.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("the original Initial must fit the sole CRYPTO slot");
        assert_eq!(initial.len(), 1);
        for mut packet in initial {
            assert!(
                server
                    .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                        &mut packet,
                        now,
                        |_: &rustls::Error| {}
                    ))
                    .is_ok()
            );
        }
        let (reply, send_result) = server.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("the server must acknowledge the original Initial");
        assert!(!reply.is_empty());
        let at = if probe {
            let deadline = (client.view().recovery().next_timer())
                .expect("the unacknowledged Initial must arm PTO");
            let at = deadline + Duration::from_millis(1);
            assert_eq!(
                client.with_scope(|mut scope| scope.recovery().try_loss(at)),
                Ok(())
            );
            let (probes, send_result) = client.with_scope(|mut scope| scope.output().send(at));
            send_result.expect("both probes must reuse the occupied CRYPTO slot");
            assert_eq!(probes.len(), 2);
            assert_eq!(client.view().recovery().unacked(Epoch::Initial), 3);
            at
        } else {
            now + Duration::from_micros(200)
        };
        for mut packet in reply {
            assert!(
                client
                    .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                        &mut packet,
                        at,
                        |_: &rustls::Error| {}
                    ))
                    .is_ok()
            );
        }
        assert_eq!(
            client.view().recovery().unacked(Epoch::Initial),
            if probe { 2 } else { 0 },
            "data acknowledgement does not acknowledge unsent-to-peer probe packets"
        );
        assert!(client.view().lifecycle().is_ready());
        let (finished, send_result) = client.with_scope(|mut scope| scope.output().send(at));
        send_result.expect(
            "the original carrier ACK must free the slot for Handshake bytes after probing",
        );
        assert!(!finished.is_empty());
        assert_eq!(
            client.view().recovery().unacked(Epoch::Initial),
            0,
            "sending the first Handshake packet discards Initial recovery state"
        );
        for mut packet in finished {
            assert!(
                server
                    .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                        &mut packet,
                        at,
                        |_: &rustls::Error| {}
                    ))
                    .is_ok()
            );
        }
        assert!(server.view().lifecycle().is_ready());
    }
}
