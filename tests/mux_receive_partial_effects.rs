pub mod common;

use common::runtime::gso::{self, Capture, Pair};
use dope_quic::conn::{Epoch, life::options::Options, stream::Event};
use dope_quic::proto::param;
use dope_test::alloc::Tracker;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn partial_receive_notifies() {
    let params = param::Set::builder()
        .idle_ms(30_000)
        .initial_data(4096)
        .stream_uni(4096)
        .uni_count(1)
        .try_build()
        .expect("one receive stream");
    let tokens = [
        1_u64.to_ne_bytes(),
        2_u64.to_ne_bytes(),
        3_u64.to_ne_bytes(),
    ];
    let mut found = false;
    for budget in 0..32 {
        let mut pair = Pair::new(|| {
            Options::builder()
                .transport(|net| net.params(params.clone()).max_pmtu(1200))
                .try_build()
                .expect("bounded connection")
        })
        .expect("established mux pair");
        let peer = pair.server.handler().events.established.take()[0];
        pair.server.handler().events.clear_stream();
        let stream = Capture::access(&mut pair.client, pair.handle, pair.now, |mut conn| {
            for token in tokens {
                conn.path().try_probe(token).expect("three path probes");
            }
            let mut streams = conn.streams();
            let mut send = streams.send();
            let stream = send.open_uni().expect("negotiated stream");
            send.send(stream, b"accepted").expect("stream payload");
            send.finish(stream).expect("stream FIN");
            stream.id()
        })
        .expect("sender access");
        pair.now =
            Capture::release_at(&pair.client, &[pair.handle], pair.now).expect("sender release");
        let mut flights = Capture::output(&mut pair.client, pair.now).expect("sender output");
        assert_eq!(
            flights
                .iter()
                .map(|flight| flight.packet_count().get())
                .sum::<usize>(),
            1
        );
        let packet = flights
            .iter_mut()
            .flat_map(|flight| flight.segments_mut())
            .next()
            .expect("one stream and probe packet");
        Tracker::fail_after(budget, || {
            Capture::receive(&mut pair.server, gso::CLIENT, packet, pair.now)
        })
        .expect("allocation rejection is a normal packet drop");
        let applied = Capture::access(&mut pair.server, peer, pair.now, |mut conn| {
            conn.streams().resident().key(stream).is_some()
        })
        .expect("receiver observation");
        if !applied {
            continue;
        }

        pair.now = Capture::release_at(&pair.server, &[peer], pair.now).expect("receiver release");
        let replies = Capture::output(&mut pair.server, pair.now).expect("receiver projection");
        let events = pair.server.handler().events.streams.take();
        assert!(
            matches!(events.as_slice(), [(handle, Event::Readable { id })]
                if *handle == peer && *id == stream),
            "accepted stream notification was lost at allocation budget {budget}"
        );
        Capture::deliver_at(&mut pair.client, gso::SERVER, replies, pair.now)
            .expect("accepted replies");
        let client = pair.client.conn(pair.handle).expect("live sender");
        assert_eq!(
            tokens
                .iter()
                .filter(|token| client.view().path().has_token(token))
                .count(),
            2,
            "the third reply must be rejected after stream application"
        );
        assert_eq!(client.view().recovery().unacked(Epoch::Application), 1);
        found = true;
        break;
    }
    assert!(
        found,
        "no allocation failure reached the accepted stream prefix"
    );
}
