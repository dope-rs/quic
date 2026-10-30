pub mod common;
use crate::common::peer;
use std::time::{Duration, Instant};

use dope_quic::conn::{stream::SendOutcome, wire::packet::Batch};
use dope_quic::stream::send;
use dope_test::alloc::Tracker;
use o3::buffer::{segments, storage};
use peer::Bind as _;
use peer::Pair;
use peer::Receiver as _;
use peer::Scope as _;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn reuses_acked_lane() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_default().expect("connected peers");
    let stream = client.send_streams().open_uni().expect("send lane");
    let peer = stream.bind(&server).expect("peer lane");
    let mut now = Instant::now() + Duration::from_secs(1);
    for len in [3, 61, 1, 16_320, 1, 8] {
        let payload = vec![0x73; len];
        client
            .send_streams()
            .send(stream, &payload)
            .expect("available send credit");
        let mut received = Vec::with_capacity(len);
        for _ in 0..len {
            now = client.view().recovery().send_at(now);
            assert!(
                server.receive_from(&mut work, &mut client, now).is_ok(),
                "stream packet"
            );
            let part = server
                .recv()
                .recv_owned(peer)
                .expect("receive payload")
                .expect("ready payload");
            assert!(!part.is_empty());
            received.extend(part);
            now += Duration::from_secs(1);
            assert!(
                client.receive_from(&mut work, &mut server, now).is_ok(),
                "stream acknowledgement"
            );
            if received.len() == len {
                break;
            }
        }
        assert_eq!(received.len(), payload.len());
        assert_eq!(received, payload);
        assert_eq!(client.stream_state().wire_bytes(), 0);
    }
    client
        .send_streams()
        .finish(stream)
        .expect("empty FIN after acknowledged data");
    now += Duration::from_secs(1);
    assert!(
        server.receive_from(&mut work, &mut client, now).is_ok(),
        "FIN packet"
    );
    assert!(server.stream_state().recv_eof(peer).expect("received FIN"));
    now += Duration::from_secs(1);
    assert!(
        client.receive_from(&mut work, &mut server, now).is_ok(),
        "FIN acknowledgement"
    );
    assert_eq!(client.stream_state().wire_bytes(), 0);
}

fn retire(first: usize) -> usize {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_default().expect("connected peers");
    let stream = client.send_streams().open_uni().expect("send lane");
    let peer = stream.bind(&server).expect("peer lane");
    let store = segments::Pool::try_new(segments::Plan {
        segments: 2,
        chains: 1,
    })
    .expect("segment slots");
    let mut chain = store.into_chain();
    for len in [first, 1_500] {
        let owner = storage::Shared::try_copy(&vec![0x61; len]).expect("retained segment");
        assert!(chain.try_push(owner).is_ok());
    }
    let chain = match chain.into_shape() {
        segments::Shape::Many(chain) => Some(chain),
        _ => None,
    }
    .expect("two retained owners");
    let parts = send::Parts::from_chain(
        send::Buffer::inline(b"").expect("empty inline prefix"),
        chain,
        send::Boundary::End,
    );
    assert!(matches!(
        client.send_streams().try_parts(stream, parts),
        SendOutcome::Accepted
    ));
    assert_eq!(client.stream_state().segments(), 2);
    let mut now = Instant::now() + Duration::from_secs(1);
    let mut batch = Batch::default();
    client
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 1, 1_200))
        .expect("first packet");
    assert_eq!(batch.packets(), 1);
    for packet in batch.iter_mut() {
        assert!(
            server
                .with_scope(|mut scope| scope.input(&mut work).recv_packet(
                    packet,
                    now,
                    |_: &rustls::Error| {}
                ))
                .is_ok(),
            "first packet ingress"
        );
    }
    let mut received = server
        .recv()
        .recv_owned(peer)
        .expect("prefix receive")
        .expect("prefix payload");
    let count = received.len();
    assert!(count >= first && count < first + 1_500);
    now += Duration::from_secs(1);
    let (ack, send_result) = server.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("prefix acknowledgement");
    let ((), delta) = Tracker::measure(|| {
        for mut packet in ack {
            assert!(
                client
                    .with_scope(|mut scope| {
                        scope
                            .input(&mut work)
                            .recv_packet(&mut packet, now, |_: &rustls::Error| {})
                    })
                    .is_ok(),
                "ACK ingress"
            );
        }
    });
    assert_eq!(delta[0], 0);
    assert_eq!(client.stream_state().segments(), 1);
    assert_eq!(client.stream_state().wire_bytes(), first + 1_500 - count);
    now += Duration::from_secs(1);
    assert!(
        server.receive_from(&mut work, &mut client, now).is_ok(),
        "suffix packets"
    );
    received.extend(
        server
            .recv()
            .recv_owned(peer)
            .expect("suffix receive")
            .expect("suffix payload"),
    );
    assert_eq!(received, vec![0x61; first + 1_500]);
    assert!(server.stream_state().recv_eof(peer).expect("received FIN"));
    now += Duration::from_secs(1);
    client
        .receive_from(&mut work, &mut server, now)
        .expect("final acknowledgement");
    assert_eq!(client.stream_state().wire_bytes(), 0);
    assert_eq!(client.stream_state().segments(), 0);
    count
}

#[test]
fn retires_segment_prefixes() {
    let packet = retire(700);
    assert_eq!(retire(packet), packet);
}
