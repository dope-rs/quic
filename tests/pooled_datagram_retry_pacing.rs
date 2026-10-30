use crate::common::peer;
pub mod common;

use common::peer::Config;
use common::runtime::gso::{self, Capture, Pair};
use common::suite::owners;
use dope_quic::conn::stream::Event;
use dope_quic::errors::SendFailure;
use dope_quic::proto::datagram::Arena;
use dope_quic::runtime::mux::builder::{Builder, Plan};
use dope_test::harness::observe::VecCellExt as _;
use std::{
    pin::Pin,
    time::{Duration, Instant},
};

/// Repeated Full and prospective dirty marks cannot release capacity before pacing.
/// The retained packet receives its notification without ingress or queued datagrams.
#[test]
fn wakes_at_pacing_deadline() {
    let Pair {
        mut client,
        handle,
        now,
        ..
    } = Pair::new(|| {
        Config::default()
            .try_build()
            .expect("datagram options")
            .into_builder()
            .transport(|path| path.max_pmtu(1200))
            .try_build()
            .expect("fixed path MTU")
    })
    .expect("fixture handshake");
    assert!(
        Capture::output(&mut client, now)
            .expect("fixture output")
            .is_empty()
    );
    client.handler().events.clear_stream();

    let arena = Arena::try_new(1, 1200).expect("one packet owner");
    let mut blocked = None;
    for _ in 0..32 {
        let mut packet = arena.try_acquire(1150).expect("recycled packet owner");
        packet.payload_mut().fill(7);
        let payload = packet.payload().as_ptr();
        let result = Pin::new(&mut client)
            .observe(now, |mut turn| {
                turn.with_app(handle, |mut conn| {
                    conn.transport().output().try_packet(packet, now, 1200)
                })
            })
            .expect("live managed connection");
        assert!(
            matches!(&result, Ok(_) | Err(SendFailure::Full(_))),
            "pooled burst must send or become full: {:?}",
            result.as_ref().err().map(owners::rejection)
        );
        if let Err(SendFailure::Full(packet)) = result {
            blocked = Some((packet, payload));
            break;
        }
    }
    let (mut packet, payload) = blocked.expect("same-instant burst reaches pacing limit");
    let conn = client.conn(handle).expect("live connection");
    let view = conn.view();
    let recovery = view.recovery();
    assert!(recovery.in_flight() < recovery.window(), "cwnd has room");
    let due = recovery.send_at(now);
    assert!(due > now, "pacing is the active blocker");
    assert!(due < recovery.next_timer().expect("unacknowledged flight"));
    assert_eq!(packet.payload().as_ptr(), payload);
    assert_eq!(arena.available(), 0);

    for _ in 0..2 {
        let result = Pin::new(&mut client)
            .observe(now, |mut turn| {
                turn.with_app(handle, |mut conn| {
                    let net = conn.transport();
                    net.output();
                    net.recovery();
                    net.output().try_packet(packet, now, 1200)
                })
            })
            .expect("live managed connection");
        packet = match result
            .err()
            .expect("unchanged pacing must retain the packet")
        {
            SendFailure::Full(packet) => Some(packet),
            _ => None,
        }
        .expect("unchanged pacing returns the full packet");
        assert!(
            Capture::output(&mut client, now)
                .expect("fixture output")
                .is_empty()
        );
        assert!(client.handler().events.streams.len() == 0);
    }
    assert_eq!(
        Pin::new(&mut client).observe(now, |turn| turn.deadline()),
        Some(due),
        "externally retained packet must register its pacing deadline"
    );

    let before = due - Duration::from_nanos(1);
    assert!(
        Capture::output(&mut client, before)
            .expect("fixture output")
            .is_empty()
    );
    assert!(client.handler().events.streams.len() == 0);

    assert!(
        Capture::output(&mut client, due)
            .expect("fixture output")
            .is_empty()
    );
    let streams = client.handler().events.streams.take();
    assert!(
        streams.as_slice() == [(handle, Event::Writable)],
        "pacing release delivers exactly one writable notification"
    );
    client.handler().events.streams.set(streams);
    assert_eq!(
        Pin::new(&mut client)
            .observe(due, |mut turn| turn.output().drive())
            .expect("consumed notification leaves the scheduler idle"),
        0
    );
    assert!(
        Pin::new(&mut client)
            .observe(due, |turn| turn.deadline())
            .is_none_or(|next| next > due),
        "one-shot interest removes its consumed deadline"
    );
    assert_eq!(packet.payload().as_ptr(), payload);
    assert_eq!(packet.payload(), &[7; 1150]);
    let result = Pin::new(&mut client)
        .observe(due, |mut turn| {
            turn.with_app(handle, |mut conn| {
                conn.transport().output().try_packet(packet, due, 1200)
            })
        })
        .expect("live managed connection");
    result
        .as_ref()
        .map_err(owners::rejection)
        .expect("the notified retained packet must send");
    assert_eq!(arena.available(), 0);
    drop(result);
    assert_eq!(arena.available(), 1);
}

/// Writable progress remains bounded among prior datagrams and deferred stream events.
#[test]
fn wakes_under_backlog() {
    let options = || {
        Config::default()
            .try_build()
            .expect("datagram options")
            .into_builder()
            .streams(|streams| streams.events(1))
            .transport(|path| path.max_pmtu(1200))
            .try_build()
            .expect("one resident stream event per connection")
    };
    let (signing, key) = peer::raw(0x47).expect("server signing key");
    let mut server = Capture::server(
        Capture::default(),
        signing.server().expect("server TLS configuration"),
        options(),
    )
    .expect("server router");
    let mut client = Builder::client(Capture::default())
        .limits(Plan::try_new(2, 64, 1 << 20).expect("two connections"))
        .build()
        .expect("client router");
    let mut now = Instant::now();
    let handles = [1u64, 2].map(|cid| {
        Capture::connect(
            &mut client,
            gso::SERVER,
            key,
            options(),
            cid.to_be_bytes().to_vec(),
            now,
        )
        .expect("client connection")
    });
    for _ in 0..16 {
        now += Duration::from_millis(1);
        Capture::deliver_at(
            &mut server,
            gso::CLIENT,
            Capture::output(&mut client, now).expect("fixture output"),
            now,
        )
        .expect("fixture packet delivery");
        Capture::deliver_at(
            &mut client,
            gso::SERVER,
            Capture::output(&mut server, now).expect("fixture output"),
            now,
        )
        .expect("fixture packet delivery");
    }
    assert_eq!(client.handler().events.established.len(), 2);
    assert_eq!(server.handler().events.established.len(), 2);
    Capture::settle_pair(&mut client, &mut server, gso::CLIENT, gso::SERVER, &mut now)
        .expect("fixture pair settlement");

    let ready = server.handler().events.established.take();
    let peers = ready.clone();
    server.handler().events.established.set(ready);
    for handle in peers {
        Capture::access(&mut server, handle, now, |mut conn| {
            let mut streams = conn.streams();
            let mut send = streams.send();
            let stream = send.open_uni().expect("server stream");
            send.send(stream, b"deferred").expect("stream payload");
        })
        .expect("live server connection");
        for value in 0..8 {
            Capture::send(&mut server, handle, vec![value], now)
                .expect("fixture datagram admission");
        }
    }
    Capture::deliver_at(
        &mut client,
        gso::SERVER,
        Capture::output(&mut server, now).expect("fixture output"),
        now,
    )
    .expect("fixture packet delivery");
    {
        let events = &client.handler().events;
        let mut data = events.data.take();
        data.clear();
        events.data.set(data);
        events.defer_readable.set(true);
    }
    let arena = Arena::try_new(2, 1200).expect("one retained packet per connection");
    let packets = handles.map(|handle| {
        let mut blocked = None;
        for _ in 0..32 {
            let packet = arena.try_acquire(1150).expect("packet owner");
            let result = Pin::new(&mut client)
                .observe(now, |mut turn| {
                    turn.with_app(handle, |mut conn| {
                        conn.transport().output().try_packet(packet, now, 1200)
                    })
                })
                .expect("live client connection");
            assert!(
                matches!(&result, Ok(_) | Err(SendFailure::Full(_))),
                "pooled burst must send or become full: {:?}",
                result.as_ref().err().map(owners::rejection)
            );
            if let Err(SendFailure::Full(packet)) = result {
                blocked = Some(packet);
                break;
            }
        }
        blocked.expect("same-instant burst must reach pacing")
    });
    let due = Capture::release_at(&client, &handles, now).expect("active fixture handle");
    assert!(due > now);
    for handle in handles {
        Pin::new(&mut client)
            .observe(due, |mut turn| turn.with_app(handle, |_| ()))
            .expect("live client connection");
    }
    assert!(client.handler().events.data.len() == 0);
    Capture::output(&mut client, due).expect("fixture output");

    let events = &client.handler().events;
    let observed = events.data.take();
    for handle in handles {
        let data = observed
            .iter()
            .filter(|(owner, _)| *owner == handle)
            .map(|(_, event)| *event)
            .collect::<Vec<_>>();
        let writable = data
            .iter()
            .position(|event| *event == Some(Event::Writable))
            .expect("retained packet gets a writable notification");
        assert!(
            writable < 4,
            "writable callback index {writable} exceeds the per-connection bound"
        );
        assert_eq!(data.iter().filter(|event| event.is_none()).count(), 8);
        let readable = data
            .iter()
            .copied()
            .find(|event| matches!(event, Some(Event::Readable { .. })))
            .expect("ordinary stream notification");
        assert!(
            data.iter().filter(|event| **event == readable).count() > 1,
            "the same ordinary stream event remains deferred"
        );
    }
    events.data.set(observed);
    drop(packets);
}
