pub mod common;

use common::peer::Receiver as _;
use common::suite::peers::life;
use dope_quic::conn::Epoch;
use dope_quic::errors::Code;
use std::time::{Duration, Instant};

#[test]
fn handshake_confirms() {
    let pair = life::try_pair(30_000).expect("lifecycle fixture must open");
    let t0 = Instant::now();
    let (mut server, mut client, mut work) = pair.into_parts();

    server
        .receive_from(&mut work, &mut client, t0)
        .expect("peer packet accepted");
    client
        .receive_from(&mut work, &mut server, t0)
        .expect("peer packet accepted");
    server
        .receive_from(&mut work, &mut client, t0)
        .expect("peer packet accepted");
    assert!(client.view().lifecycle().is_ready());
    assert!(server.view().lifecycle().is_ready());
    assert!(
        !client.view().lifecycle().is_confirmed(),
        "client not yet confirmed"
    );

    client
        .receive_from(&mut work, &mut server, t0)
        .expect("peer packet accepted");
    assert!(
        client.view().lifecycle().is_confirmed(),
        "HANDSHAKE_DONE received"
    );
    assert_eq!(client.view().recovery().unacked(Epoch::Initial), 0);
    assert_eq!(client.view().recovery().unacked(Epoch::Handshake), 0);
}

#[test]
fn close_closes_peer() {
    let mut pair = life::try_pair(30_000).expect("lifecycle fixture must open");
    let t0 = Instant::now();
    pair.exchange(t0, 2).expect("fixture handshake flights");
    let (mut server, mut client, mut work) = pair.into_parts();
    assert!(client.view().lifecycle().is_ready());
    assert!(server.view().lifecycle().is_ready());

    client.with_scope(|mut scope| {
        scope
            .lifecycle()
            .close(Code::from_u8(7), b"goodbye".to_vec())
    });
    assert!(client.view().lifecycle().is_closing());
    assert!(!client.view().lifecycle().is_closed());
    server
        .receive_from(&mut work, &mut client, t0)
        .expect("peer packet accepted");

    assert!(
        client.view().lifecycle().is_closed(),
        "client closed after sending CLOSE"
    );
    assert!(
        server.view().lifecycle().is_closed(),
        "server closed after receiving CLOSE"
    );
}

#[test]
fn idle_timeout_closes() {
    let mut pair = life::try_pair(50).expect("lifecycle fixture must open");
    let t0 = Instant::now();
    pair.exchange(t0, 2).expect("fixture handshake flights");
    let (mut server, mut client, _) = pair.into_parts();

    let t1 = t0 + Duration::from_millis(100);
    assert_eq!(
        client.with_scope(|mut scope| scope.recovery().try_loss(t1)),
        Ok(())
    );
    assert_eq!(
        server.with_scope(|mut scope| scope.recovery().try_loss(t1)),
        Ok(())
    );
    assert!(client.view().lifecycle().is_closed(), "client idle-closed");
    assert!(server.view().lifecycle().is_closed(), "server idle-closed");
}

#[test]
fn activity_resets_idle() {
    let mut pair = life::try_pair(100).expect("lifecycle fixture must open");
    let t0 = Instant::now();
    pair.exchange(t0, 2).expect("fixture handshake flights");
    let (mut server, mut client, mut work) = pair.into_parts();

    let t1 = t0 + Duration::from_millis(80);
    client
        .with_scope(|mut scope| scope.datagrams().try_send(b"keepalive".to_vec()))
        .expect("established test client must accept a keepalive DATAGRAM");
    server
        .receive_from(&mut work, &mut client, t1)
        .expect("peer packet accepted");
    assert!(!client.view().lifecycle().is_closed());
    assert!(!server.view().lifecycle().is_closed());

    let t2 = t1 + Duration::from_millis(50);
    assert_eq!(
        client.with_scope(|mut scope| scope.recovery().try_loss(t2)),
        Ok(())
    );
    assert_eq!(
        server.with_scope(|mut scope| scope.recovery().try_loss(t2)),
        Ok(())
    );
    assert!(
        !client.view().lifecycle().is_closed(),
        "datagram refreshed client idle"
    );
    assert!(
        !server.view().lifecycle().is_closed(),
        "datagram refreshed server idle"
    );
}

#[test]
fn sends_do_not_defer_idle() {
    let mut pair = life::try_pair(100).expect("lifecycle fixture must open");
    let t0 = Instant::now();
    pair.exchange(t0, 2).expect("fixture handshake flights");
    let mut client = pair.client;

    let first = t0 + Duration::from_millis(80);
    client
        .with_scope(|mut scope| scope.datagrams().try_send(b"first".to_vec()))
        .expect("established test client must accept the first DATAGRAM");
    assert!(
        !{
            let (emitted_packets, send_result) =
                client.with_scope(|mut scope| scope.output().send(first));
            send_result.expect("warmed client journals must admit the first datagram");
            emitted_packets
        }
        .is_empty()
    );

    let later = t0 + Duration::from_millis(150);
    client
        .with_scope(|mut scope| scope.datagrams().try_send(b"second".to_vec()))
        .expect("established test client must accept the second DATAGRAM");
    assert!(
        !{
            let (emitted_packets, send_result) =
                client.with_scope(|mut scope| scope.output().send(later));
            send_result.expect("warmed client journals must admit the second datagram");
            emitted_packets
        }
        .is_empty()
    );

    client.with_scope(|mut scope| {
        assert_eq!(
            scope
                .recovery()
                .try_loss(first + Duration::from_millis(101)),
            Ok(())
        );
    });
    assert!(
        client.view().lifecycle().is_closed(),
        "only the first ack-eliciting send after a receive may restart idle timeout",
    );
}

#[test]
fn server_discards_keys() {
    let mut pair = life::try_pair(30_000).expect("lifecycle fixture must open");
    let t0 = Instant::now();
    pair.exchange(t0, 2).expect("fixture handshake flights");
    assert_eq!(pair.server.view().recovery().unacked(Epoch::Handshake), 0);
}
