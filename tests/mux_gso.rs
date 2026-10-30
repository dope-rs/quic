use crate::common::peer;
use dope_quic::conn::life::options::Options;
use dope_quic::conn::stream;
use dope_quic::runtime::mux::builder::{Builder, Plan};
pub mod common;
use common::runtime::gso::{self, Capture};
use dope_quic::{conn::stream::Event, proto::param, runtime::mux::output};
use std::{
    pin::Pin,
    time::{Duration, Instant},
};
#[test]
fn retry_requires_train() {
    for lost in [1usize, 4] {
        let (signing, key) = peer::raw(0x60 + lost as u8).expect("raw identity");
        let params = param::Set::builder()
            .idle_ms(30_000)
            .initial_data(1 << 20)
            .stream_uni(1 << 20)
            .uni_count(4)
            .try_build()
            .expect("fixture transport parameters");
        let options = || {
            Options::builder()
                .transport(|net| net.params(params.clone()).max_pmtu(1_200))
                .try_build()
                .expect("fixture connection options must be valid")
        };
        let source = signing.server().expect("server TLS");
        let mut server = Capture::server(gso::Capture::default(), source, options())
            .expect("fixture server must initialize");
        let capture = gso::Capture::default();
        let events = capture.events.clone();
        let limits = Plan::try_new(1, 64, 1 << 20).expect("retry fixture limits are valid");
        let mut client = Builder::client(capture)
            .limits(limits)
            .build()
            .expect("fixture client router has valid limits");
        assert!(
            Pin::new(&mut client).config().enable_gso().is_ok(),
            "fixture client supports GSO configuration"
        );

        let mut now = Instant::now();
        let handle = Capture::connect(
            &mut client,
            gso::SERVER,
            key,
            options(),
            gso::CID.to_vec(),
            now,
        )
        .expect("fixture connection must initialize");
        for _ in 0..16 {
            now += Duration::from_millis(1);
            let flights = Capture::output(&mut client, now).expect("fixture output");
            Capture::deliver_at(&mut server, gso::CLIENT, flights, now)
                .expect("fixture packet delivery");
            let flights = Capture::output(&mut server, now).expect("fixture output");
            Capture::deliver_at(&mut client, gso::SERVER, flights, now)
                .expect("fixture packet delivery");
        }
        let ready = events.established.take();
        assert!(ready == [handle]);
        events.established.set(ready);

        Capture::settle_pair(&mut client, &mut server, gso::CLIENT, gso::SERVER, &mut now)
            .expect("fixture pair settlement");

        let body = vec![0x80 | lost as u8; (lost + 4) * 1_150];
        assert!(
            Capture::access(&mut client, handle, now, |mut conn| {
                let mut streams = conn.streams();
                let mut send = streams.send();
                let stream = send
                    .open_uni()
                    .expect("established fixture connection has stream credit");
                assert!(
                    send.send(stream, &body).is_ok(),
                    "open fixture stream accepts the retry body"
                );
                assert!(
                    send.finish(stream).is_ok(),
                    "open fixture stream accepts FIN"
                );
            })
            .is_ok(),
            "fixture connection must remain installed"
        );

        let mut packets: Vec<Vec<u8>> = Vec::new();
        let burst = Capture::output(&mut client, now).expect("fixture output");
        for mut outgoing in burst {
            packets.extend(outgoing.segments_mut().map(|segment| segment.to_vec()));
            Pin::new(&mut client).output().recycle(outgoing);
        }
        assert!(
            packets.len() >= lost + 3,
            "later ACKs must cross the packet-loss threshold"
        );
        for packet in &mut packets[lost..] {
            Capture::receive(&mut server, gso::CLIENT, packet, now).expect("fixture ingress");
        }

        let ack_at = now + Duration::from_millis(50);
        let acks = Capture::output(&mut server, ack_at).expect("fixture output");
        Capture::deliver_at(&mut client, gso::SERVER, acks, ack_at)
            .expect("fixture packet delivery");
        let retries = Capture::output(&mut client, ack_at).expect("fixture output");
        let shapes: Vec<_> = retries
            .iter()
            .map(|outgoing| {
                (
                    outgoing.packet_count(),
                    outgoing.is_segmented(),
                    outgoing.payload().len(),
                )
            })
            .collect();
        if lost == 1 {
            assert!(
                retries.iter().any(|outgoing| {
                    !outgoing.is_segmented() && outgoing.payload().len() > 1_000
                }),
                "one retry must stay on the plain path: {shapes:?}"
            );
            assert!(
                retries.iter().all(|outgoing| !outgoing.is_segmented()),
                "one retry plus any ACK-only output cannot create a GSO train: {shapes:?}"
            );
        } else {
            assert!(
                retries
                    .iter()
                    .any(|outgoing| outgoing.is_segmented() && outgoing.packet_count().get() >= 2),
                "proven retry work must produce a useful GSO train: {shapes:?}"
            );
        }
    }
}

#[test]
fn destinations_split() {
    const PER_DEST: usize = 4;
    const TOTAL: usize = PER_DEST * 2;

    let (sign_a, key_a) = peer::raw(0x51).expect("first raw identity");
    let (sign_b, key_b) = peer::raw(0x52).expect("second raw identity");
    let params = param::Set::builder()
        .idle_ms(30_000)
        .datagram(Some(65_535))
        .try_build()
        .expect("fixture transport parameters");
    let options = || {
        Options::builder()
            .transport(|net| net.params(params.clone()).max_pmtu(1_200))
            .try_build()
            .expect("fixture connection options must be valid")
    };
    let source_a = sign_a.server().expect("server TLS");
    let source_b = sign_b.server().expect("server TLS");
    let mut server_a = Capture::server(gso::Capture::default(), source_a, options())
        .expect("first server must initialize");
    let mut server_b = Capture::server(gso::Capture::default(), source_b, options())
        .expect("second server must initialize");
    let limits = Plan::try_new(TOTAL, 64, 1 << 20).expect("multi-route fixture limits are valid");
    let mut client = Builder::client(gso::Capture::default())
        .limits(limits)
        .build()
        .expect("fixture client router has valid limits");
    let mut now = Instant::now();
    let mut handles = Vec::with_capacity(TOTAL);
    for ordinal in 0..TOTAL {
        let (addr, key) = if ordinal % 2 == 0 {
            (gso::SERVER, key_a)
        } else {
            (gso::SERVER_B, key_b)
        };
        let handle = Capture::connect(
            &mut client,
            addr,
            key,
            options(),
            (ordinal as u64 + 1).to_be_bytes().to_vec(),
            now,
        )
        .expect("fixture connection must initialize");
        handles.push(handle);
    }
    for _ in 0..16 {
        now += Duration::from_millis(1);
        Capture::route(&mut client, &mut server_a, &mut server_b, now).expect("fixture route");
        Capture::deliver(
            &mut client,
            gso::SERVER,
            Capture::output(&mut server_a, now).expect("fixture output"),
        )
        .expect("fixture packet delivery");
        Capture::deliver(
            &mut client,
            gso::SERVER_B,
            Capture::output(&mut server_b, now).expect("fixture output"),
        )
        .expect("fixture packet delivery");
    }

    for _ in 0..4 {
        now += Duration::from_millis(30);
        Capture::route(&mut client, &mut server_a, &mut server_b, now).expect("fixture route");
        now += Duration::from_millis(30);
        let flights = Capture::output(&mut server_a, now).expect("fixture output");
        Capture::deliver_at(&mut client, gso::SERVER, flights, now)
            .expect("fixture packet delivery");
        let flights = Capture::output(&mut server_b, now).expect("fixture output");
        Capture::deliver_at(&mut client, gso::SERVER_B, flights, now)
            .expect("fixture packet delivery");
    }
    now += Duration::from_millis(30);
    Capture::route(&mut client, &mut server_a, &mut server_b, now).expect("fixture route");

    assert!(
        Pin::new(&mut client).config().enable_gso().is_ok(),
        "fixture client supports GSO configuration"
    );
    for (ordinal, handle) in handles.iter().copied().enumerate() {
        Capture::send(&mut client, handle, vec![ordinal as u8; 1_150], now)
            .expect("fixture datagram admission");
    }
    now = Capture::release_at(&client, &handles, now).expect("active fixture handle");
    let flights = Capture::output(&mut client, now).expect("fixture output");
    assert_eq!(flights.len(), 2);
    assert!(flights.iter().all(output::Flight::is_segmented));
    assert!(
        flights
            .iter()
            .all(|flight| flight.packet_count().get() == PER_DEST)
    );
    assert!(flights.iter().any(|flight| flight.addr() == gso::SERVER));
    assert!(flights.iter().any(|flight| flight.addr() == gso::SERVER_B));
}

#[test]
fn burst_reassembles() {
    let (signing, key) = peer::raw(7).expect("raw identity");

    let params = param::Set::builder()
        .idle_ms(30_000)
        .initial_data(1 << 20)
        .stream_uni(1 << 20)
        .uni_count(8)
        .try_build()
        .expect("fixture transport parameters");
    let [srv_opts, cli_opts] = [params.clone(), params]
        .map(|params| Options::try_from(params).expect("fixture connection options must be valid"));

    let capture = gso::Capture::default();
    let remote = capture.events.clone();
    let mut server = Capture::server(capture, signing.server().expect("server TLS"), srv_opts)
        .expect("fixture server must initialize");
    assert!(
        Pin::new(&mut server).config().enable_gso().is_ok(),
        "fixture server supports GSO configuration"
    );

    let capture = gso::Capture::default();
    let local = capture.events.clone();
    let mut client = Builder::client(capture)
        .build()
        .expect("default fixture client router is valid");

    let mut now = Instant::now();
    let dialed = Capture::connect(
        &mut client,
        gso::SERVER,
        key,
        cli_opts,
        gso::CID.to_vec(),
        now,
    )
    .expect("fixture connection must initialize");
    Capture::deliver(
        &mut server,
        gso::CLIENT,
        Capture::output(&mut client, now).expect("fixture output"),
    )
    .expect("fixture packet delivery");
    Capture::deliver(
        &mut client,
        gso::SERVER,
        Capture::output(&mut server, now).expect("fixture output"),
    )
    .expect("fixture packet delivery");
    Capture::deliver(
        &mut server,
        gso::CLIENT,
        Capture::output(&mut client, now).expect("fixture output"),
    )
    .expect("fixture packet delivery");
    for (mux, peer) in [(&mut server, "server"), (&mut client, "client")] {
        Pin::new(mux).observe(now, |mut turn| {
            assert!(
                turn.output().drive().is_ok(),
                "fixture {peer} connections must admit settled stream output"
            )
        });
    }

    let ready = remote.established.take();
    let accepted = ready
        .first()
        .copied()
        .expect("server observes the fixture connection as established");
    remote.established.set(ready);

    let body: Vec<u8> = (0..8192u32).map(|index| (index * 31) as u8).collect();
    let id = Capture::access(&mut server, accepted, now, |mut conn| {
        let mut streams = conn.streams();
        let mut send = streams.send();
        let stream = send.open_uni()?;
        send.send(stream, &body)?;
        send.finish(stream)?;
        Ok::<_, stream::Error>(stream.id())
    })
    .expect("fixture connection access must succeed")
    .expect("established server must enqueue the complete stream and FIN");

    let mut gso_runs = 0;
    for _ in 0..16 {
        now += Duration::from_millis(20);
        assert!(Pin::new(&mut server).output().len() <= Pin::new(&mut server).output().capacity());
        assert!(
            Pin::new(&mut server).output().bytes() <= Pin::new(&mut server).output().byte_limit()
        );
        gso_runs += Capture::deliver(
            &mut client,
            gso::SERVER,
            Capture::output(&mut server, now).expect("fixture output"),
        )
        .expect("fixture packet delivery");
        Capture::deliver(
            &mut server,
            gso::CLIENT,
            Capture::output(&mut client, now).expect("fixture output"),
        )
        .expect("fixture packet delivery");
        let eof = Capture::access(&mut client, dialed, now, |mut conn| {
            let streams = conn.streams();
            let receive = streams.view().resolve_recv(id)?;
            Ok::<_, stream::Error>(streams.view().is_recv_eof(receive))
        })
        .expect("fixture connection access must succeed")
        .expect("delivered stream remains installed until EOF");
        if eof {
            break;
        }
    }

    assert!(gso_runs >= 1, "the paced 8 KiB blast coalesces ≥1 GSO run");
    let streams = local.streams.take();
    assert!(
        streams.contains(&(dialed, Event::Readable { id })),
        "client saw stream data"
    );
    local.streams.set(streams);

    let mut recv = Vec::new();
    let eof = Capture::access(&mut client, dialed, now, |mut conn| {
        let mut streams = conn.streams();
        let receive = streams.view().resolve_recv(id)?;
        assert!(
            streams.receive().recv(receive, &mut recv).is_ok(),
            "fixture receive capacity must admit the coalesced burst"
        );
        let receive = streams.view().resolve_recv(id)?;
        Ok::<_, stream::Error>(streams.view().is_recv_eof(receive))
    })
    .expect("fixture connection access must succeed")
    .expect("consumed stream remains installed through EOF observation");
    assert_eq!(recv, body, "GSO-coalesced burst reassembles byte-exact");
    assert!(eof, "fin delivered");
}
