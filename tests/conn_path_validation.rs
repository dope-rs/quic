pub mod common;

use common::peer::Receiver as _;
use common::suite::peers::path;
use dope_quic::conn;
use std::time::{Duration, Instant};

#[test]
fn challenge_round_trip() {
    use dope_quic::wire::frame::{self, Frame, View};
    let data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    let mut buf = vec![frame::TYPE_PATH_CHALLENGE];
    buf.extend_from_slice(&data);
    let (decoded, n) = Frame::decode(&buf).expect("test PATH_CHALLENGE frame must decode");
    assert!(matches!(decoded.view(), View::PathChallenge { data: found } if found == &data));
    assert_eq!(n, buf.len());
}

#[test]
fn path_response_round_trip() {
    use dope_quic::wire::frame::{self, Frame, View};
    let data = [0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
    let mut buf = vec![frame::TYPE_PATH_RESPONSE];
    buf.extend_from_slice(&data);
    let (decoded, n) = Frame::decode(&buf).expect("test PATH_RESPONSE frame must decode");
    assert!(matches!(decoded.view(), View::PathResponse { data: found } if found == &data));
    assert_eq!(n, buf.len());
}

#[test]
fn challenge_validates_path() {
    let (mut server, mut client, mut work) = path::try_pair::<8_192>()
        .expect("path-validation peers")
        .into_parts();
    assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
    let token = [0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF];

    assert_eq!(
        server.with_scope(|mut scope| scope.path().try_probe(token)),
        Ok(())
    );
    assert_eq!(
        server.with_scope(|mut scope| scope.path().try_probe(token)),
        Err(conn::wire::path::probe::Error::Duplicate { data: token })
    );
    assert!(
        !server.view().path().has_token(&token),
        "not yet validated — RESPONSE hasn't come back",
    );

    client
        .receive_from(&mut work, &mut server, Instant::now())
        .expect("peer packet transfer");
    server
        .receive_from(&mut work, &mut client, Instant::now())
        .expect("peer packet transfer");

    assert!(
        server.view().path().has_token(&token),
        "server should have validated the path after RESPONSE round-trip",
    );
}

#[test]
fn unsolicited_is_invalid() {
    let (server, client, _work) = path::try_pair::<8_192>()
        .expect("path-validation peers")
        .into_parts();
    assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
    assert!(
        !server.view().path().has_token(&[0xFFu8; 8]),
        "never-issued token must not be reported validated",
    );
}

#[test]
fn pre_handshake_is_noop() {
    let mut client = path::try_initial().expect("initial path-validation client");
    assert!(client.view().lifecycle().is_opening());
    let token = [0x01u8; 8];
    assert_eq!(
        client.with_scope(|mut scope| scope.path().try_probe(token)),
        Err(conn::wire::path::probe::Error::State {
            state: conn::State::Handshaking,
            data: token
        })
    );
    let (flight, send_result) = client.with_scope(|mut scope| scope.output().send(Instant::now()));
    send_result.expect("initial handshake output remains available after rejection");
    assert!(!flight.is_empty(), "the ClientHello is still pending");
    assert!(flight.iter().all(|packet| packet[0] & 0x80 != 0));
    assert!(client.view().lifecycle().is_opening());
    assert!(!client.view().path().has_token(&token));
}

#[test]
fn challenges_independent() {
    let (mut server, mut client, mut work) = path::try_pair::<8_192>()
        .expect("path-validation peers")
        .into_parts();
    assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
    let a = [0xAAu8; 8];
    let b = [0xBBu8; 8];
    assert_eq!(
        server.with_scope(|mut scope| scope.path().try_probe(a)),
        Ok(())
    );
    assert_eq!(
        server.with_scope(|mut scope| scope.path().try_probe(b)),
        Ok(())
    );
    client
        .receive_from(&mut work, &mut server, Instant::now())
        .expect("peer packet transfer");
    server
        .receive_from(&mut work, &mut client, Instant::now())
        .expect("peer packet transfer");
    assert!(server.view().path().has_token(&a));
    assert!(server.view().path().has_token(&b));
}

#[test]
fn backpressure_keeps() {
    const TOKENS: usize = 64;
    const CONTROL_CAPACITY: usize = 32;
    let (mut server, mut client, mut work) = path::try_pair::<CONTROL_CAPACITY>()
        .expect("bounded path-validation peers")
        .into_parts();
    assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
    let cli_set: Vec<_> = (0..TOKENS)
        .map(|token| (token as u64).to_ne_bytes())
        .collect();
    let srv_set: Vec<_> = (TOKENS..TOKENS * 2)
        .map(|token| (token as u64).to_ne_bytes())
        .collect();

    for &token in &cli_set {
        assert_eq!(
            client.with_scope(|mut scope| scope.path().try_probe(token)),
            Ok(())
        );
    }
    for &token in &srv_set {
        assert_eq!(
            server.with_scope(|mut scope| scope.path().try_probe(token)),
            Ok(())
        );
    }

    for _ in 0..32 {
        server
            .receive_from(&mut work, &mut client, Instant::now())
            .expect("peer packet transfer");
        client
            .receive_from(&mut work, &mut server, Instant::now())
            .expect("peer packet transfer");
        server
            .receive_from(&mut work, &mut client, Instant::now())
            .expect("peer packet transfer");
        client
            .receive_from(&mut work, &mut server, Instant::now())
            .expect("peer packet transfer");
        if cli_set
            .iter()
            .all(|token| client.view().path().has_token(token))
            && srv_set
                .iter()
                .all(|token| server.view().path().has_token(token))
        {
            break;
        }
    }

    assert!(
        cli_set
            .iter()
            .all(|token| client.view().path().has_token(token)),
        "client challenges and server responses survive control pressure",
    );
    assert!(
        srv_set
            .iter()
            .all(|token| server.view().path().has_token(token)),
        "server challenges and client responses survive control pressure",
    );
}

#[test]
fn stale_ack_keeps_slot() {
    const CONTROL_CAPACITY: usize = 32;
    let (mut server, mut client, mut work) = path::try_pair::<CONTROL_CAPACITY>()
        .expect("bounded path-validation peers")
        .into_parts();
    assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
    let first = 0x51_u64.to_ne_bytes();
    let next = 0x52_u64.to_ne_bytes();
    let sent_at = Instant::now() + Duration::from_secs(1);

    assert_eq!(
        client.with_scope(|mut scope| scope.path().try_probe(first)),
        Ok(())
    );
    let (mut original, send_result) = client.with_scope(|mut scope| scope.output().send(sent_at));
    send_result.expect("warmed client journals must admit the original path challenge");
    assert!(!original.is_empty(), "the first generation is encrypted");
    for packet in &mut original {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, sent_at, |_: &rustls::Error| {})
            })
            .expect("server must receive the first control generation");
    }
    let (mut ack1, send_result) =
        server.with_scope(|mut scope| scope.output().send(sent_at + Duration::from_millis(1)));
    send_result.expect("warmed server journals must admit the first carrier acknowledgement");
    assert!(
        !ack1.is_empty(),
        "the first carrier has a separately delayed ACK"
    );

    let deadline = client
        .view()
        .recovery()
        .next_timer()
        .expect("control PTO is armed");
    let probe_at = deadline + Duration::from_millis(1);
    assert_eq!(
        client.with_scope(|mut scope| scope.recovery().try_loss(probe_at)),
        Ok(())
    );
    let (mut probes, send_result) = client.with_scope(|mut scope| scope.output().send(probe_at));
    send_result.expect("warmed client journals must admit the control PTO probe");
    assert!(!probes.is_empty(), "PTO emits another control carrier");
    server
        .with_scope(|mut scope| {
            scope
                .input(&mut work)
                .recv_packet(&mut probes[0], probe_at, |_: &rustls::Error| {})
        })
        .expect("server must receive the control PTO probe");
    let (mut old_ack, send_result) =
        server.with_scope(|mut scope| scope.output().send(probe_at + Duration::from_millis(1)));
    send_result.expect("warmed server journals must admit the probe carrier acknowledgement");
    assert!(
        !old_ack.is_empty(),
        "the probe carrier has an independently deliverable ACK"
    );

    for packet in &mut ack1 {
        client
            .with_scope(|mut scope| {
                scope.input(&mut work).recv_packet(
                    packet,
                    probe_at + Duration::from_millis(2),
                    |_: &rustls::Error| {},
                )
            })
            .expect("client must receive the first control acknowledgement");
    }
    assert!(
        client.view().path().has_token(&first),
        "the first ACK retires the original control owner"
    );

    assert_eq!(
        client.with_scope(|mut scope| scope.path().try_probe(next)),
        Ok(())
    );
    let next_at = probe_at + Duration::from_millis(3);
    let (mut next_out, send_result) = client.with_scope(|mut scope| scope.output().send(next_at));
    send_result.expect("warmed client journals must admit the replacement path challenge");
    assert!(
        !next_out.is_empty(),
        "the freed slot is reused and committed before the old ACK arrives"
    );

    for packet in &mut old_ack {
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, next_at, |_: &rustls::Error| {})
            })
            .expect("client must receive the delayed probe acknowledgement");
    }
    assert!(
        !client.view().path().has_token(&next),
        "a stale ACK cannot fabricate path validation"
    );

    for packet in &mut next_out {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, next_at, |_: &rustls::Error| {})
            })
            .expect("server must receive the replacement control generation");
    }
    let reply_at = next_at + Duration::from_millis(1);
    let (mut reply, send_result) = server.with_scope(|mut scope| scope.output().send(reply_at));
    send_result.expect("warmed server journals must admit the replacement response");
    assert!(!reply.is_empty());
    for packet in &mut reply {
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, reply_at, |_: &rustls::Error| {})
            })
            .expect("client must receive the replacement response");
    }
    for step in 1..=4 {
        if client.view().path().has_token(&next) {
            break;
        }
        let now = reply_at + Duration::from_millis(step);
        let (emitted_packets, send_result) =
            client.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("warmed client journals must admit replacement control traffic");
        for mut packet in emitted_packets {
            server
                .with_scope(|mut scope| {
                    scope
                        .input(&mut work)
                        .recv_packet(&mut packet, now, |_: &rustls::Error| {})
                })
                .expect("server must receive the emitted client packet");
        }
        let (emitted_packets, send_result) =
            server.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("warmed server journals must admit replacement control traffic");
        for mut packet in emitted_packets {
            client
                .with_scope(|mut scope| {
                    scope
                        .input(&mut work)
                        .recv_packet(&mut packet, now, |_: &rustls::Error| {})
                })
                .expect("client must receive the emitted server packet");
        }
        assert_eq!(
            client.with_scope(|mut scope| scope.recovery().try_loss(now)),
            Ok(())
        );
        assert_eq!(
            server.with_scope(|mut scope| scope.recovery().try_loss(now)),
            Ok(())
        );
    }

    assert!(
        client.view().path().has_token(&next),
        "the replacement generation survives the delayed old ACK end to end"
    );
    assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
}
