pub mod common;

use common::peer::{Pair, Receiver as _};
use common::suite::peers::receive::datagram;
use dope_quic::conn::{Epoch, wire::packet::Batch};
use std::time::{Duration, Instant};

#[test]
fn old_flight_reduces_once() {
    let mut pair = Pair::try_default().expect("established peers");
    let base = datagram::try_settle(&mut pair, Instant::now() + Duration::from_secs(1))
        .expect("settled acknowledgments")
        + Duration::from_secs(1);
    let Pair {
        mut client,
        mut server,
        mut work,
    } = pair;
    assert_eq!(client.view().recovery().unacked(Epoch::Application), 0);
    let original = client.view().recovery().window();
    let mut packets = Vec::new();
    let mut batch = Batch::default();
    for sequence in 0..5 {
        client
            .with_scope(|mut scope| scope.datagrams().try_send(vec![0x41; 128]))
            .expect("old flight datagram");
        let at = base + Duration::from_millis(sequence);
        client
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, at, 1, 1_200))
            .expect("old flight packet");
        assert_eq!(batch.packets(), 1);
        packets.push(batch.iter_mut().next().expect("one packet").to_vec());
    }

    server
        .receive(&mut work, &mut packets[3], base + Duration::from_millis(90))
        .expect("first acknowledged packet");
    client
        .receive_from(&mut work, &mut server, base + Duration::from_millis(100))
        .expect("first congestion event");
    let reduced = client.view().recovery().window();
    assert!(reduced < original);
    assert_eq!(client.view().recovery().unacked(Epoch::Application), 3);

    server
        .receive(
            &mut work,
            &mut packets[4],
            base + Duration::from_millis(101),
        )
        .expect("second acknowledged packet");
    client
        .receive_from(&mut work, &mut server, base + Duration::from_millis(126))
        .expect("later loss from the old flight");
    assert_eq!(client.view().recovery().unacked(Epoch::Application), 1);
    assert_eq!(client.view().recovery().window(), reduced);

    for sequence in 0..4 {
        client
            .with_scope(|mut scope| scope.datagrams().try_send(vec![0x42; 128]))
            .expect("new flight datagram");
        let at = base + Duration::from_millis(200 + sequence);
        client
            .with_scope(|mut scope| scope.output().send_batch(&mut batch, at, 1, 1_200))
            .expect("new flight packet");
        assert_eq!(batch.packets(), 1);
    }
    server
        .receive_all(&mut work, &mut batch, base + Duration::from_millis(290))
        .expect("new flight's final packet");
    client
        .receive_from(&mut work, &mut server, base + Duration::from_millis(300))
        .expect("new congestion event");
    assert_eq!(
        client.view().recovery().window(),
        (reduced / 2).max(client.view().path().mtu() * 2),
        "a loss transmitted after recovery began starts a new recovery period",
    );
}
