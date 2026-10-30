pub mod common;

use common::suite::peers::path::{self, ACK_DELAY};
use dope_quic::conn::Epoch;
use dope_quic::conn::wire::packet::Batch;
use dope_quic::proto::datagram::Arena;
use std::time::Duration;

#[test]
fn waits_for_deadline() {
    let (pair, now) = path::try_ack().expect("settled ACK peers");
    let (mut server, mut client, mut work) = pair.into_parts();
    assert_eq!(client.view().recovery().unacked(Epoch::Application), 0);
    assert_eq!(server.view().recovery().unacked(Epoch::Application), 0);
    let mut stimulus = path::try_packets(&mut server, now, 1).expect("delayed-ACK stimulus");
    assert_eq!(stimulus.packets(), 1);
    for packet in stimulus.iter_mut() {
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, now, |_: &rustls::Error| {})
            })
            .expect("client accepts the delayed-ACK stimulus");
    }

    let mut ack = Batch::default();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut ack, now, 1, 1_200))
        .expect("warmed client journals must remain admissible before the ACK deadline");
    assert!(ack.is_empty());
    client
        .with_scope(|mut scope| {
            scope.output().send_batch(
                &mut ack,
                now + ACK_DELAY - Duration::from_nanos(1),
                1,
                1_200,
            )
        })
        .expect("warmed client journals must remain admissible immediately before the deadline");
    assert!(ack.is_empty());

    let due = now + ACK_DELAY;
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut ack, due, 1, 1_200))
        .expect("warmed client journals must admit the due acknowledgement");
    assert_eq!(ack.packets(), 1);
    for packet in ack.iter_mut() {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, due, |_: &rustls::Error| {})
            })
            .expect("server accepts the delayed acknowledgement");
    }
    assert_eq!(server.view().recovery().unacked(Epoch::Application), 0);
}

#[test]
fn gap_acks_immediately() {
    let (pair, now) = path::try_ack().expect("settled ACK peers");
    let (mut server, mut client, mut work) = pair.into_parts();
    assert_eq!(client.view().recovery().unacked(Epoch::Application), 0);
    assert_eq!(server.view().recovery().unacked(Epoch::Application), 0);
    let mut pair = path::try_packets(&mut server, now, 2).expect("delayed-ACK stimulus");
    assert_eq!(pair.packets(), 2);
    let mut ack = Batch::default();

    let second = pair
        .iter_mut()
        .nth(1)
        .expect("two-packet fixture contains its second packet");
    client
        .with_scope(|mut scope| {
            scope
                .input(&mut work)
                .recv_packet(second, now, |_: &rustls::Error| {})
        })
        .expect("client accepts the out-of-order packet");
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut ack, now, 1, 1_200))
        .expect("warmed client journals must admit the gap acknowledgement");
    assert_eq!(
        ack.packets(),
        1,
        "a fresh packet below the largest observed PN closes a gap immediately"
    );
    for packet in ack.iter_mut() {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, now, |_: &rustls::Error| {})
            })
            .expect("server accepts the gap acknowledgement");
    }
    assert_eq!(server.view().recovery().unacked(Epoch::Application), 1);

    let later = now + Duration::from_secs(1);
    let mut pair = path::try_packets(&mut server, later, 2).expect("delayed-ACK stimulus");
    assert_eq!(pair.packets(), 2);
    for packet in pair.iter_mut() {
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, later, |_: &rustls::Error| {})
            })
            .expect("client accepts the two-packet acknowledgement stimulus");
    }
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut ack, later, 1, 1_200))
        .expect("warmed client journals must admit the two-packet acknowledgement");
    assert_eq!(
        ack.packets(),
        1,
        "the second ACK-eliciting packet makes the debt immediately due"
    );
}

#[test]
fn ack_coalesces_early() {
    let (pair, now) = path::try_ack().expect("settled ACK peers");
    let (mut server, mut client, mut work) = pair.into_parts();
    assert_eq!(client.view().recovery().unacked(Epoch::Application), 0);
    assert_eq!(server.view().recovery().unacked(Epoch::Application), 0);
    let mut stimulus = path::try_packets(&mut server, now, 1).expect("delayed-ACK stimulus");
    assert_eq!(stimulus.packets(), 1);
    for packet in stimulus.iter_mut() {
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, now, |_: &rustls::Error| {})
            })
            .expect("client accepts the coalescing stimulus");
    }
    client
        .with_scope(|mut scope| scope.datagrams().try_send(vec![0x51; 64]))
        .expect("coalesced fixture datagram fits the configured queue");

    let mut batch = Batch::default();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 1, 1_200))
        .expect("warmed client journals must admit the coalesced output");
    assert_eq!(batch.packets(), 1);
    for packet in batch.iter_mut() {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, now, |_: &rustls::Error| {})
            })
            .expect("server accepts the coalesced output");
    }
    assert_eq!(
        server.view().recovery().unacked(Epoch::Application),
        0,
        "an already-going packet carries pending debt without waiting or another packet"
    );
}

#[test]
fn datagram_keeps_room() {
    let (pair, now) = path::try_ack().expect("settled ACK peers");
    let (mut server, mut client, mut work) = pair.into_parts();
    assert_eq!(client.view().recovery().unacked(Epoch::Application), 0);
    assert_eq!(server.view().recovery().unacked(Epoch::Application), 0);
    let mut stimulus = path::try_packets(&mut server, now, 1).expect("delayed-ACK stimulus");
    assert_eq!(stimulus.packets(), 1);
    for packet in stimulus.iter_mut() {
        client
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, now, |_: &rustls::Error| {})
            })
            .expect("client accepts the reserved-room stimulus");
    }

    let maximum = client
        .with_scope(|mut scope| scope.datagrams().max_payload())
        .expect("peer advertises DATAGRAM support")
        .min(
            Arena::payload_max(1_200, 8)
                .expect("a 1200-byte packet with an eight-byte CID has payload room"),
        );
    client
        .with_scope(|mut scope| scope.datagrams().try_send(vec![0x71; maximum]))
        .expect("maximum fixture datagram fits the configured queue");
    let mut output = Batch::default();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut output, now, 1, 1_200))
        .expect("warmed client journals must admit the reserved-room datagram");
    assert_eq!(output.packets(), 1);
    for packet in output.iter_mut() {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, now, |_: &rustls::Error| {})
            })
            .expect("server accepts the reserved DATAGRAM output");
    }
    assert_eq!(
        server
            .with_scope(|mut scope| scope.datagrams().recv())
            .expect("server receives the reserved DATAGRAM"),
        vec![0x71; maximum],
        "the queued DATAGRAM owns its reserved wire room",
    );
    assert_eq!(
        server.view().recovery().unacked(Epoch::Application),
        1,
        "an ACK that did not fit must remain pending instead of displacing data",
    );

    let due = now + ACK_DELAY;
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut output, due, 1, 1_200))
        .expect("warmed client journals must admit the deferred acknowledgement");
    assert_eq!(output.packets(), 1);
    for packet in output.iter_mut() {
        server
            .with_scope(|mut scope| {
                scope
                    .input(&mut work)
                    .recv_packet(packet, due, |_: &rustls::Error| {})
            })
            .expect("server accepts the deferred acknowledgement");
    }
    assert_eq!(server.view().recovery().unacked(Epoch::Application), 0,);
}

#[test]
fn wraps_and_retires() {
    use common::suite::peers::packet::Pair;
    use dope_quic::wire::frame::{Frame, View};
    use std::time::Instant;

    let now = Instant::now();
    let mut pair = Pair::try_new(1, now, |_| {}).expect("independent peer handshake");
    let mut held = Vec::new();
    for index in 0..515 {
        let mut packet = pair.peer.packet(&[0x01; 20]).expect("authenticated Ping");
        if matches!(index, 0 | 511 | 513) {
            held.push(packet);
            continue;
        }
        pair.server
            .with_scope(|mut scope| {
                scope
                    .input(&mut pair.work)
                    .recv_packet(&mut packet, now, |_| {})
            })
            .expect("receive wrapped packet window");
    }

    for (arrivals, expected) in [
        (&[][..], Some((0, vec![(0, 0), (0, 508)]))),
        (&[1, 2][..], Some((512, vec![]))),
        (&[0][..], None),
    ] {
        for &index in arrivals {
            pair.server
                .with_scope(|mut scope| {
                    scope
                        .input(&mut pair.work)
                        .recv_packet(&mut held[index], now, |_| {})
                })
                .expect("receive delayed packet");
        }
        let (packets, send_result) = pair.server.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("encode retained ACK ranges");
        let mut acks = Vec::new();
        for packet in packets {
            let Some(mut packet) = pair.peer.receive(&packet).expect("server flight") else {
                continue;
            };
            let (_, body) = pair
                .peer
                .open(&mut packet)
                .expect("authenticated server packet");
            for frame in Frame::decode_all(&body).expect("server frames") {
                if let View::Ack {
                    first_range: first,
                    additional_ranges: ranges,
                    ..
                } = frame.view()
                {
                    acks.push((
                        first.get(),
                        ranges
                            .iter()
                            .map(|(gap, range)| (gap.get(), range.get()))
                            .collect::<Vec<_>>(),
                    ));
                }
            }
        }
        assert_eq!(acks, expected.into_iter().collect::<Vec<_>>());
    }
}
