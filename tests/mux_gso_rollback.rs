pub mod common;
use common::runtime::gso::{self, Capture, Pair};
use dope_quic::conn::life::options::Options;
use dope_quic::conn::output::transmit::{Admission, Error};
use dope_quic::conn::stream::Event;
use dope_quic::proto::param;
use dope_test::alloc::Tracker;
use o3::depot::capacity::Reason;
use std::{pin::Pin, time::Duration};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn journal_keeps_prefix() {
    const STREAMS: usize = 160;
    const BYTES: usize = 40;
    let params = param::Set::builder()
        .idle_ms(30_000)
        .initial_data(1 << 20)
        .stream_uni(4096)
        .uni_count(STREAMS as u64)
        .try_build()
        .expect("bounded stream parameters");
    let mut observed = false;
    let mut complete = false;
    let mut attempts = Vec::new();
    for budget in 0..32 {
        let mut pair = Pair::new(|| {
            Options::builder()
                .transport(|net| net.params(params.clone()).max_pmtu(1200))
                .journals(|journals| journals.stream::<1024>())
                .try_build()
                .expect("bounded journal options")
        })
        .expect("fixture handshake");
        Pin::new(&mut pair.client)
            .config()
            .enable_gso()
            .expect("native GSO support");
        Capture::access(&mut pair.client, pair.handle, pair.now, |mut conn| {
            let mut streams = conn.streams();
            let mut send = streams.send();
            for ordinal in 0..STREAMS {
                let stream = send.open_uni().expect("negotiated stream count");
                send.send(stream, &[ordinal as u8; BYTES])
                    .expect("stream flow credit");
                send.finish(stream).expect("stream FIN");
            }
        })
        .expect("established sender");
        pair.now = Capture::release_at(&pair.client, &[pair.handle], pair.now)
            .expect("active fixture handle");
        let (result, activity) = Tracker::activity(|| {
            Tracker::fail_after(budget, || {
                Pin::new(&mut pair.client).observe(pair.now, |mut turn| turn.output().drive())
            })
        });
        let cause = result.err().map(|failure| {
            assert!(*failure.connection() == pair.handle);
            failure.into_parts().1
        });
        complete = cause.is_none() && activity.allocations < budget;
        if complete {
            let idle = Pin::new(&mut pair.client)
                .observe(pair.now, |mut turn| turn.output().drive())
                .expect("empty follow-up emission preserves the queued flight");
            assert_eq!(idle, 0, "no empty packet may extend the committed prefix");
        }
        let mut flights = Pin::new(&mut pair.client).observe(pair.now, |mut turn| {
            turn.output().drain().collect::<Vec<_>>()
        });
        let packets = flights
            .iter()
            .map(|flight| flight.packet_count().get())
            .sum::<usize>();
        if matches!(
            &cause,
            Some(Error::Admission(
                Admission::Stream {
                    reason: Reason::Allocation(_),
                    ..
                } | Admission::Packet {
                    reason: Reason::Allocation(_),
                    ..
                }
            ))
        ) && flights.iter().any(|flight| flight.is_segmented())
        {
            observed = true;
        }
        attempts.push((budget, cause, packets));
        for flight in &mut flights {
            let count = flight.packet_count().get();
            let bytes = flight.byte_len();
            assert_eq!(flight.is_segmented(), count > 1);
            let mut seen = 0;
            let mut total = 0;
            let mut width = 0;
            for segment in flight.segments_mut() {
                if seen == 0 {
                    width = segment.len();
                }
                assert!(!segment.is_empty());
                assert!(segment.len() <= width && width <= 1200);
                if seen + 1 < count {
                    assert_eq!(segment.len(), width);
                }
                total += segment.len();
                seen += 1;
                Capture::receive(&mut pair.server, gso::CLIENT, segment, pair.now)
                    .expect("fixture ingress");
            }
            assert_eq!(seen, count);
            assert_eq!(total, bytes);
        }
        for _ in 0..4 {
            pair.now += Duration::from_millis(30);
            Capture::deliver_at(
                &mut pair.client,
                gso::SERVER,
                Capture::output(&mut pair.server, pair.now).expect("fixture output"),
                pair.now,
            )
            .expect("fixture packet delivery");
            pair.now += Duration::from_millis(30);
            Capture::deliver_at(
                &mut pair.server,
                gso::CLIENT,
                Capture::output(&mut pair.client, pair.now).expect("fixture output"),
                pair.now,
            )
            .expect("fixture packet delivery");
        }
        let events = &pair.server.handler().events;
        let ready = events.established.take();
        let handle = ready[0];
        events.established.set(ready);
        let streams = events.streams.take();
        let mut ids: Vec<_> = streams
            .iter()
            .filter_map(|(_, event)| match event {
                Event::Readable { id } => Some(*id),
                _ => None,
            })
            .collect();
        events.streams.set(streams);
        assert_eq!(ids.len(), STREAMS);
        ids.sort_unstable();
        Capture::access(&mut pair.server, handle, pair.now, |mut conn| {
            let mut streams = conn.streams();
            for (ordinal, id) in ids.iter().copied().enumerate() {
                assert_eq!(id.number(), ordinal as u64);
                let stream = streams
                    .view()
                    .resolve_recv(id)
                    .expect("readable stream owner");
                assert_eq!(
                    streams
                        .receive()
                        .recv_owned(stream)
                        .expect("committed receive")
                        .expect("each payload delivered once"),
                    [ordinal as u8; BYTES]
                );
                assert!(streams.view().is_recv_eof(stream));
                assert!(
                    streams
                        .receive()
                        .recv_owned(stream)
                        .expect("drained receive")
                        .is_none()
                );
            }
        })
        .expect("established receiver");
        if complete {
            break;
        }
    }
    assert!(
        complete,
        "allocation prefix exceeded fixture bound: {attempts:?}"
    );
    assert!(
        observed,
        "no journal failure followed a committed GSO prefix: {attempts:?}"
    );
}
