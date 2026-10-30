use common::suite::mux::dispatch;
pub mod common;

use common::peer::Initial;
use common::suite::{mux::retry, retry::Capture};
use dope_quic::conn::{self, Epoch, Error, life::options};
use dope_quic::proto::param;
use dope_quic::runtime::mux::builder;
use dope_quic::wire::packet::long::{initial, retry::Ref};
use std::{net::SocketAddr, time::Instant};

#[test]
fn rfc9001_a4_round_trip() {
    let derived = retry::try_tag(&retry::RFC_DCID, &retry::RFC_HEADER)
        .expect("the RFC 9001 A.4 vector must admit an integrity tag");
    assert_eq!(
        derived,
        retry::RFC_TAG,
        "RFC 9001 A.4 integrity tag mismatch"
    );
}

#[test]
fn initial_triggers_retry() {
    let secret = [0xA1u8; 32];
    let mut mux = retry::try_required(secret).expect("retry server");

    let dcid = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let scid = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x99];
    let mut initial = Initial::new(&dcid, &scid, 0)
        .seal(&[0x01])
        .expect("fixture Initial seals");

    let from = SocketAddr::from(([127, 0, 0, 1], 55_001));
    Capture::receive(&mut mux, from, &mut initial, Instant::now())
        .expect("fixture Initial reaches Retry policy");

    let outgoing = dispatch::Capture::output(&mut mux, Instant::now()).expect("retry output");
    assert_eq!(outgoing.len(), 1, "exactly one Retry should be emitted");
    let (dst, wire) = (outgoing[0].addr(), outgoing[0].payload());
    assert_eq!(dst, from);
    let retry = Ref::decode(wire).expect("the server output must decode as Retry");
    assert!(retry.dcid() == scid, "retry DCID echoes client's SCID");
    let mut token = Vec::new();
    let verified = retry::try_verify(wire, &dcid, &scid, &mut token)
        .expect("Retry prefix and integrity")
        .expect("Retry integrity and destination binding");
    assert!(
        !verified.token().is_empty(),
        "retry must carry a server token"
    );
}

#[test]
fn token_avoids_retry() {
    let secret = [0xA2u8; 32];
    let mut mux = retry::try_required(secret).expect("retry server");

    let dcid = [0x77u8; 8];
    let scid = [0x44u8; 8];
    let from = SocketAddr::from(([127, 0, 0, 1], 55_002));

    let mut first = Initial::new(&dcid, &scid, 0)
        .seal(&[0x01])
        .expect("fixture Initial seals");
    Capture::receive(&mut mux, from, &mut first, Instant::now())
        .expect("fixture Initial reaches Retry policy");
    let sent = dispatch::Capture::output(&mut mux, Instant::now()).expect("retry output");
    let mut store = Vec::new();
    let retry = retry::try_verify(sent[0].payload(), &dcid, &scid, &mut store)
        .expect("Retry prefix and integrity")
        .expect("Retry integrity and destination binding");
    let token = retry.token().to_vec();
    let new_dcid = retry.scid();

    let mut second = Initial::new(new_dcid.into_slice(), &scid, 0)
        .token(&token)
        .seal(&[0x01])
        .expect("retried fixture Initial seals");
    Capture::receive(&mut mux, from, &mut second, Instant::now())
        .expect("fixture Initial reaches Retry policy");
    let sent2 = dispatch::Capture::output(&mut mux, Instant::now()).expect("retry output");
    for out in &sent2 {
        let wire = out.payload();
        let is_retry = matches!(wire.first(), Some(b) if b & 0xF0 == 0xF0);
        assert!(
            !is_retry,
            "second Initial with token must not produce another Retry"
        );
    }
}

#[test]
fn wrong_addr_rejected() {
    let secret = [0xA3u8; 32];
    let mut mux = retry::try_required(secret).expect("retry server");

    let dcid = [0x88u8; 8];
    let scid = [0x99u8; 8];
    let from_a = SocketAddr::from(([127, 0, 0, 1], 55_003));
    let from_b = SocketAddr::from(([127, 0, 0, 1], 55_004));

    let mut first = Initial::new(&dcid, &scid, 0)
        .seal(&[0x01])
        .expect("fixture Initial seals");
    Capture::receive(&mut mux, from_a, &mut first, Instant::now())
        .expect("fixture Initial reaches Retry policy");
    let packet = Capture::take(&mut mux, Instant::now())
        .expect("retry take")
        .expect("the first Initial must produce a Retry packet");
    let mut store = Vec::new();
    let retry = retry::try_verify(packet.payload(), &dcid, &scid, &mut store)
        .expect("Retry prefix and integrity")
        .expect("Retry integrity and destination binding");
    let token = retry.token().to_vec();
    let new_dcid = retry.scid();

    let mut second = Initial::new(new_dcid.into_slice(), &scid, 0)
        .token(&token)
        .seal(&[0x01])
        .expect("retried fixture Initial seals");
    Capture::receive(&mut mux, from_b, &mut second, Instant::now())
        .expect("fixture Initial reaches Retry policy");
    let out = dispatch::Capture::output(&mut mux, Instant::now()).expect("retry output");
    assert!(
        out.is_empty(),
        "address-bound token mismatch must drop the packet silently"
    );
}

#[test]
fn token_binds_retry_cid() {
    let secret = [0xA4u8; 32];
    let mut mux = retry::try_required(secret).expect("retry server");
    let orig = [0x31u8; 8];
    let scid = [0x42u8; 8];
    let from = SocketAddr::from(([127, 0, 0, 1], 55_006));

    let mut first = Initial::new(&orig, &scid, 0)
        .seal(&[0x01])
        .expect("fixture Initial seals");
    Capture::receive(&mut mux, from, &mut first, Instant::now())
        .expect("fixture Initial reaches Retry policy");
    let packet = Capture::take(&mut mux, Instant::now())
        .expect("retry take")
        .expect("the first Initial must produce a Retry packet");
    let mut store = Vec::new();
    let retry = retry::try_verify(packet.payload(), &orig, &scid, &mut store)
        .expect("Retry prefix and integrity")
        .expect("Retry integrity and destination binding");
    let token = retry.token().to_vec();
    let mut wrong = retry.scid().into_slice().to_vec();
    wrong[0] ^= 0x80;

    let mut replay = Initial::new(&wrong, &scid, 0)
        .token(&token)
        .seal(&[0x01])
        .expect("replayed fixture Initial seals");
    Capture::receive(&mut mux, from, &mut replay, Instant::now())
        .expect("fixture Initial reaches Retry policy");
    assert_eq!(mux.active_conns(), 0);
    assert!(
        Capture::take(&mut mux, Instant::now())
            .expect("retry take")
            .is_none()
    );
}

#[test]
fn retry_defaults_off() {
    let mut mux = retry::try_server(options::Options::default(), builder::Plan::standard())
        .expect("server fixture");

    let mut initial = Initial::new(&[0; 8], &[1; 8], 0)
        .seal(&[0x01])
        .expect("fixture Initial seals");
    let from = SocketAddr::from(([127, 0, 0, 1], 55_005));
    Capture::receive(&mut mux, from, &mut initial, Instant::now())
        .expect("fixture Initial reaches Retry policy");
    let out = dispatch::Capture::output(&mut mux, Instant::now()).expect("retry output");
    for o in &out {
        let wire = o.payload();
        let is_retry = matches!(wire.first(), Some(b) if b & 0xF0 == 0xF0);
        assert!(!is_retry, "off-by-default: no Retry should be emitted");
    }
}

#[test]
fn client_accepts_retry() {
    let orig = vec![0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let params = param::Set::builder()
        .idle_ms(0)
        .try_build()
        .expect("transport parameters");
    let options = options::Options::builder()
        .transport(|path| path.params(params))
        .try_build()
        .expect("connection options");
    let mut client = retry::try_client(&orig, options).expect("client fixture");
    let mut space = conn::Workspace::try_new().expect("receive workspace allocation");

    let (first, send_result) = client.with_scope(|mut scope| scope.output().send(Instant::now()));
    send_result.expect("fresh client journals must admit its first Initial");
    assert!(!first.is_empty(), "client must emit its first Initial");
    assert!(client.view().recovery().unacked(Epoch::Initial) > 0);
    assert_eq!(client.view().recovery().unacked(Epoch::Application), 0);
    assert!(client.view().recovery().next_timer().is_some());

    let new_scid = vec![0xF0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5];
    let token = b"server-issued-retry-token".to_vec();
    for (scid, token) in [
        (new_scid.as_slice(), &[][..]),
        (orig.as_slice(), token.as_slice()),
    ] {
        let mut wire = retry::try_wire(&orig, &retry::CLIENT_CID, scid, token)
            .expect("Retry fixture has a valid integrity tag");
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut space)
                    .recv_packet(&mut wire, Instant::now(), |_| {})
            })
            .expect("empty-token and original-ID Retries must be discarded cleanly");
    }

    let mut wire = retry::try_wire(&orig, &retry::CLIENT_CID, &new_scid, &token)
        .expect("Retry packet encoding");

    let result = client.with_scope(|mut scope| {
        scope
            .input(&mut space)
            .recv_packet(&mut wire, Instant::now(), |_| {})
    });
    assert!(
        result.is_ok(),
        "the valid Retry must enter the client after discarded Retries"
    );
    assert_eq!(client.view().recovery().unacked(Epoch::Initial), 0);
    assert_eq!(client.view().recovery().next_timer(), None);

    let (second, send_result) = client.with_scope(|mut scope| scope.output().send(Instant::now()));
    send_result.expect("warmed client journals must admit its retried Initial");
    assert!(!second.is_empty(), "client must resend Initial after Retry");
    let prefix = initial::Prefix::decode(&second[0]).expect("decode reissued initial");
    assert!(
        prefix.dcid == new_scid,
        "client must swap DCID to retry.scid"
    );
    assert_eq!(prefix.token, token, "client must attach the retry token");
    assert!(prefix.scid == retry::CLIENT_CID, "client SCID is preserved");
}

#[test]
fn client_rejects_bad_tag() {
    let orig = vec![0xAAu8; 8];
    let mut client = retry::try_client(&orig, options::Options::default()).expect("client fixture");
    let mut space = conn::Workspace::try_new().expect("receive workspace allocation");
    assert!(
        !{
            let (emitted_packets, send_result) =
                client.with_scope(|mut scope| scope.output().send(Instant::now()));
            send_result.expect("fresh client journals must admit its Initial");
            emitted_packets
        }
        .is_empty()
    );

    let new_scid = vec![0x55u8; 8];
    let token = b"tok".to_vec();
    let mut wire = retry::try_wire(&orig, &retry::CLIENT_CID, &new_scid, &token)
        .expect("Retry packet encoding");
    let n = wire.len();
    wire[n - 1] ^= 0xFF;

    let result = client.with_scope(|mut scope| {
        scope
            .input(&mut space)
            .recv_packet(&mut wire, Instant::now(), |_| {})
    });
    assert!(
        result.is_ok(),
        "an invalid Retry tag must be discarded without a receive failure"
    );

    let (next, send_result) = client.with_scope(|mut scope| scope.output().send(Instant::now()));
    send_result.expect("warmed client journals must admit output after the rejected Retry");
    for w in &next {
        let prefix = initial::Prefix::decode(w).expect("decode");
        assert!(prefix.dcid != new_scid, "rejected Retry must not swap DCID");
        assert!(
            prefix.token.is_empty(),
            "rejected Retry must not attach token"
        );
    }
}

#[test]
fn client_checks_retry_dst() {
    let orig = vec![0xA5; 8];
    let mut client = retry::try_client(&orig, options::Options::default()).expect("client fixture");
    let mut space = conn::Workspace::try_new().expect("receive workspace allocation");
    assert!(
        !{
            let (emitted_packets, send_result) =
                client.with_scope(|mut scope| scope.output().send(Instant::now()));
            send_result.expect("fresh client journals must admit its Initial");
            emitted_packets
        }
        .is_empty()
    );

    let new_scid = vec![0x5A; 8];
    let token = b"valid-tag-wrong-destination".to_vec();
    let mut wire =
        retry::try_wire(&orig, &[0x99; 8], &new_scid, &token).expect("Retry packet encoding");

    let result = client.with_scope(|mut scope| {
        scope
            .input(&mut space)
            .recv_packet(&mut wire, Instant::now(), |_| {})
    });
    assert!(
        result.is_ok(),
        "a Retry for another client must be discarded cleanly"
    );

    let (emitted_packets, send_result) =
        client.with_scope(|mut scope| scope.output().send(Instant::now()));
    send_result.expect("warmed client journals must admit output after the foreign Retry");
    for wire in emitted_packets {
        let prefix =
            initial::Prefix::decode(&wire).expect("each client output must decode as Initial");
        assert!(prefix.dcid != new_scid);
        assert!(prefix.token.is_empty());
    }
}

#[test]
fn client_ignores_retry_two() {
    let orig = vec![0xCCu8; 8];
    let mut client = retry::try_client(&orig, options::Options::default()).expect("client fixture");
    let mut space = conn::Workspace::try_new().expect("receive workspace allocation");
    assert!(
        !{
            let (emitted_packets, send_result) =
                client.with_scope(|mut scope| scope.output().send(Instant::now()));
            send_result.expect("fresh client journals must admit its Initial");
            emitted_packets
        }
        .is_empty()
    );

    let scid_a = vec![0x10u8; 8];
    let scid_b = vec![0x20u8; 8];
    let token_a = b"first-token".to_vec();
    let token_b = b"second-token".to_vec();

    let mut retry_a = retry::try_wire(&orig, &retry::CLIENT_CID, &scid_a, &token_a)
        .expect("Retry packet encoding");
    let result = client.with_scope(|mut scope| {
        scope
            .input(&mut space)
            .recv_packet(&mut retry_a, Instant::now(), |_| {})
    });
    assert!(
        result.is_ok(),
        "the first valid Retry must enter the client"
    );

    let mut retry_b = retry::try_wire(&orig, &retry::CLIENT_CID, &scid_b, &token_b)
        .expect("Retry packet encoding");
    let result = client.with_scope(|mut scope| {
        scope
            .input(&mut space)
            .recv_packet(&mut retry_b, Instant::now(), |_| {})
    });
    assert!(
        result.is_ok(),
        "the second valid Retry must be ignored cleanly"
    );

    let (next, send_result) = client.with_scope(|mut scope| scope.output().send(Instant::now()));
    send_result.expect("warmed client journals must admit output after the duplicate Retry");
    let prefix = initial::Prefix::decode(&next[0]).expect("decode");
    assert!(
        prefix.dcid == scid_a,
        "first Retry's scid must remain in effect"
    );
    assert_eq!(prefix.token, token_a, "first Retry's token must remain");
}

#[test]
fn retry_token_fills_floor() {
    for len in [1109, 1110] {
        let orig = [0xce; 8];
        let scid = [0x44; 8];
        let token = vec![0x91; len];
        let mut client = retry::try_client(&orig, retry::try_ceiling().expect("client MTU"))
            .expect("client fixture");
        let mut space = conn::Workspace::try_new().expect("receive workspace allocation");
        let now = Instant::now();
        assert!(
            !{
                let (emitted_packets, send_result) =
                    client.with_scope(|mut scope| scope.output().send(now));
                send_result.expect("client must emit its first Initial");
                emitted_packets
            }
            .is_empty()
        );
        let mut wire = retry::try_wire(&orig, &retry::CLIENT_CID, &scid, &token)
            .expect("Retry fixture has a valid integrity tag");
        client
            .with_scope(|mut scope| scope.input(&mut space).recv_packet(&mut wire, now, |_| {}))
            .expect("client must accept the fitting Retry token");
        let (sent, send_result) = client.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("client must emit its retried Initial");
        assert!(!sent.is_empty());
        for packet in sent {
            assert_eq!(packet.len(), 1200, "Retry token length {len}");
            let prefix = initial::Prefix::decode(&packet).expect("retried Initial prefix");
            assert_eq!(prefix.token, token);
        }
    }
}

#[test]
fn oversize_token_closes() {
    let orig = vec![0xceu8; 8];
    let mut client = retry::try_client(&orig, retry::try_ceiling().expect("client MTU"))
        .expect("client fixture");
    let mut space = conn::Workspace::try_new().expect("receive workspace allocation");
    assert_eq!(
        {
            let (emitted_packets, send_result) =
                client.with_scope(|mut scope| scope.output().send(Instant::now()));
            send_result.expect("fresh client journals must admit its Initial");
            emitted_packets
        }
        .len(),
        1
    );

    let mut retry = retry::try_wire(&orig, &retry::CLIENT_CID, &[0x44; 8], &vec![0x91; 1200])
        .expect("Retry packet encoding");
    assert!(matches!(
        client.with_scope(|mut scope| scope.input(&mut space).recv_packet(
            &mut retry,
            Instant::now(),
            |_| {}
        )),
        Err(Error::PacketCeiling)
    ));
    assert!(client.view().lifecycle().is_closed());
}
