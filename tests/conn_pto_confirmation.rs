pub mod common;

use common::peer::Receiver as _;
use common::suite::peers::life;
use dope_quic::conn::Epoch;
use dope_quic::wire::packet::long;
use std::time::Instant;

#[test]
fn pto_waits_for_confirm() {
    let pair = life::try_pair(0).expect("fixture must disable both idle timers");
    let now = Instant::now();
    let (mut server, mut client, mut work) = pair.into_parts();
    server
        .receive_from(&mut work, &mut client, now)
        .expect("server must accept client Initial");
    client
        .receive_from(&mut work, &mut server, now)
        .expect("client must accept server handshake flight");
    server
        .receive_from(&mut work, &mut client, now)
        .expect("server must accept client Finished");
    assert!(client.view().lifecycle().is_ready());
    assert!(!client.view().lifecycle().is_confirmed());
    assert_eq!(client.view().recovery().unacked(Epoch::Initial), 0);
    assert_ne!(client.view().recovery().unacked(Epoch::Handshake), 0);
    assert!(client.view().recovery().next_timer().is_some());

    let (packets, send_result) = server.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("server must emit handshake ACK and confirmation");
    let mut confirm = Vec::new();
    for mut packet in packets {
        let head = *packet.first().expect("server output must not be empty");
        if head & 0x80 != 0 {
            assert!(
                long::Parsed::parse(packet.as_slice())
                    .expect("server long packet must parse")
                    .kind()
                    == long::Type::Handshake
            );
            client
                .receive(&mut work, &mut packet, now)
                .expect("client must authenticate server handshake ACK");
        } else {
            confirm.push(packet);
        }
    }
    assert!(!confirm.is_empty());
    assert!(!client.view().lifecycle().is_confirmed());
    assert_eq!(client.view().recovery().unacked(Epoch::Initial), 0);
    assert_eq!(client.view().recovery().unacked(Epoch::Handshake), 0);

    client
        .with_scope(|mut scope| scope.datagrams().try_send(b"pending".to_vec()))
        .expect("ready client must admit application DATAGRAM");
    let at = client.view().recovery().send_at(now);
    let (held, send_result) = client.with_scope(|mut scope| scope.output().send(at));
    send_result.expect("client must emit application packet");
    assert!(!held.is_empty());
    assert_eq!(client.inspection().tx_queued(), 0);
    assert_ne!(client.view().recovery().unacked(Epoch::Application), 0);
    assert_eq!(
        client.view().recovery().next_timer(),
        None,
        "unconfirmed application flight must not arm PTO"
    );

    for mut packet in confirm {
        client
            .receive(&mut work, &mut packet, at)
            .expect("client must authenticate retained HANDSHAKE_DONE");
    }
    assert!(client.view().lifecycle().is_confirmed());
    assert_ne!(client.view().recovery().unacked(Epoch::Application), 0);
    assert!(
        client
            .view()
            .recovery()
            .next_timer()
            .expect("confirmed application flight must arm PTO")
            > at
    );
}
