use crate::common::peer;
pub mod common;
use common::suite::mux::dispatch::{CID, CLIENT, Capture, Defer, SERVER};
use dope_quic::conn::life::options::Options;
use dope_quic::conn::stream::Event;
use dope_quic::errors::Code;
use dope_quic::proto::param;
use dope_quic::runtime::mux::builder::{Builder, Plan};
use std::pin::Pin;
use std::rc::Rc;
use std::time::{Duration, Instant};

#[test]
fn handshake() {
    let (signing, key) = peer::raw(0x39).expect("raw identity");
    let params = param::Set::builder()
        .idle_ms(30_000)
        .datagram(Some(65_535))
        .initial_data(1 << 20)
        .local_bidi(1 << 20)
        .remote_bidi(1 << 20)
        .stream_uni(1 << 20)
        .bidi_count(8)
        .uni_count(8)
        .try_build()
        .expect("fixture transport parameters");

    let capture = Capture::default();
    let srv_log = Rc::clone(&capture.events);
    let mut server = Capture::server(
        capture,
        signing.server().expect("server TLS"),
        Options::try_from(params.clone())
            .expect("fixture configuration must satisfy its declared bounds"),
        Plan::standard(),
    )
    .expect("fixture server");
    let capture = Capture::default();
    let cli_log = Rc::clone(&capture.events);
    let mut client = Builder::client(capture)
        .build()
        .expect("default client router resources must be valid");
    let now = Instant::now();
    let cli_h = Capture::connect(
        &mut client,
        SERVER,
        key,
        Options::try_from(params).expect("fixture configuration must satisfy its declared bounds"),
        CID.to_vec(),
        now,
    )
    .expect("fixture connect");

    Capture::relay(&mut client, &mut server, CLIENT, now).expect("fixture relay");
    Capture::relay(&mut server, &mut client, SERVER, now).expect("fixture relay");
    Capture::relay(&mut client, &mut server, CLIENT, now).expect("fixture relay");
    Capture::drive(&mut server, now).expect("fixture drive");
    Capture::drive(&mut client, now).expect("fixture drive");

    let srv_h = {
        let events = srv_log.borrow();
        assert_eq!(events.established.len(), 1, "server got Established");
        events.established[0]
    };
    {
        let events = cli_log.borrow();
        assert_eq!(events.established.len(), 1, "client got Established");
        assert!(events.established[0] == cli_h);
    }

    Capture::send(&mut client, cli_h, b"hello server".to_vec(), now).expect("fixture send");
    let packets = Capture::output(&mut client, now).expect("fixture output");
    assert!(!packets.is_empty());
    for mut packet in packets {
        for segment in packet.segments_mut() {
            let mut copy = segment.to_vec();
            Capture::recv(&mut server, CLIENT, segment, now).expect("fixture recv");
            Capture::recv(&mut server, CLIENT, &mut copy, now).expect("fixture recv");
        }
    }
    Capture::drive(&mut server, now).expect("fixture drive");
    {
        let events = srv_log.borrow();
        assert_eq!(events.datagrams.len(), 1);
        assert!(events.datagrams[0].0 == srv_h);
        assert_eq!(events.datagrams[0].1, b"hello server");
    }

    Capture::send(&mut server, srv_h, b"hello client".to_vec(), now).expect("fixture send");
    Capture::relay(&mut server, &mut client, SERVER, now).expect("fixture relay");
    {
        let events = cli_log.borrow();
        assert_eq!(events.datagrams.len(), 1);
        assert!(events.datagrams[0].0 == cli_h);
        assert_eq!(events.datagrams[0].1, b"hello client");
    }

    let at = Instant::now();
    let stream = Pin::new(&mut client)
        .observe(at, |mut turn| {
            turn.protocol().with_conn(cli_h, |mut conn| {
                let mut streams = conn.streams();
                let mut send = streams.send();
                let stream = send
                    .open_bidi()
                    .expect("established connection must retain a bidi stream slot");
                send.send(stream.send(), b"hello stream")
                    .expect("fixture stream credit must admit its payload");
                send.finish(stream.send())
                    .expect("fixture send stream must finish once");
                stream.id()
            })
        })
        .expect("established client handle must expose its connection");
    assert!(Capture::relay(&mut client, &mut server, CLIENT, at).expect("fixture relay") > 0);
    let visible = Pin::new(&mut server)
        .observe(at, |mut turn| {
            turn.protocol().with_conn(srv_h, |mut conn| {
                conn.streams().view().resolve_recv(stream).is_ok()
            })
        })
        .expect("established server handle must expose its connection");
    assert!(visible);
    {
        let events = srv_log.borrow();
        assert!(
            events
                .streams
                .contains(&(srv_h, Event::Readable { id: stream })),
            "the server handle must expose the readable stream",
        );
        assert_eq!(
            events
                .streams
                .iter()
                .filter(|(handle, event)| {
                    *handle == srv_h && *event == Event::Readable { id: stream }
                })
                .count(),
            1,
        );
    }

    let closed = Pin::new(&mut client).observe(at, |mut turn| turn.protocol().try_close(cli_h));
    closed.expect("active client connection closes");
    assert!(cli_log.borrow().closed == vec![cli_h]);
    assert_eq!(cli_log.borrow().certificates, 0);
    assert_eq!(srv_log.borrow().certificates, 0);
    for events in [&cli_log, &srv_log] {
        assert!(
            events
                .borrow()
                .owners
                .iter()
                .all(|(owner, handle)| owner == handle)
        );
    }
}

#[test]
fn deferred_reset() {
    let (signing, key) = peer::raw(0x3a).expect("raw identity");
    let params = param::Set::builder()
        .idle_ms(30_000)
        .initial_data(1 << 20)
        .local_bidi(1 << 20)
        .remote_bidi(1 << 20)
        .bidi_count(2)
        .try_build()
        .expect("fixture transport parameters");

    let defer = Defer::default();
    let state = Rc::clone(&defer.state);
    let mut server = Capture::server(
        defer,
        signing.server().expect("server TLS"),
        Options::try_from(params.clone())
            .expect("fixture configuration must satisfy its declared bounds"),
        Plan::standard(),
    )
    .expect("fixture server");
    let mut client = Builder::client(Capture::default())
        .build()
        .expect("default client router resources must be valid");
    let now = Instant::now();
    let cli_h = Capture::connect(
        &mut client,
        SERVER,
        key,
        Options::try_from(params).expect("fixture configuration must satisfy its declared bounds"),
        CID.to_vec(),
        now,
    )
    .expect("fixture connect");

    Capture::relay(&mut client, &mut server, CLIENT, now).expect("fixture relay");
    Capture::relay(&mut server, &mut client, SERVER, now).expect("fixture relay");
    Capture::relay(&mut client, &mut server, CLIENT, now).expect("fixture relay");
    let ready = state.established.take();
    let srv_h = ready[0];
    state.established.set(ready);

    let at = Instant::now() + Duration::from_secs(1);
    let stream = Pin::new(&mut client)
        .observe(at, |mut turn| {
            turn.protocol().with_conn(cli_h, |mut conn| {
                let mut streams = conn.streams();
                let mut send = streams.send();
                let stream = send
                    .open_bidi()
                    .expect("established connection must retain a bidi stream slot");
                let id = stream.id();
                send.send(stream.send(), b"leased")
                    .expect("fixture stream credit must admit its payload");
                id
            })
        })
        .expect("established client handle must expose its connection");
    Capture::drive(&mut client, at).expect("fixture drive");
    assert!(Capture::relay(&mut client, &mut server, CLIENT, at).expect("fixture relay") > 0);
    let history = state.attempts.take();
    let key = history
        .iter()
        .copied()
        .find(|(handle, event, _)| *handle == srv_h && *event == Event::Readable { id: stream })
        .and_then(|entry| entry.2)
        .expect("first STREAM flight must own a resident identity");
    state.attempts.set(history);

    let reset_at = at + Duration::from_millis(1);
    Pin::new(&mut client)
        .observe(reset_at, |mut turn| {
            turn.protocol().with_conn(cli_h, |mut conn| {
                let mut streams = conn.streams();
                let stream = streams
                    .view()
                    .resolve_send(stream)
                    .expect("live stream ID must resolve to send state");
                streams
                    .send()
                    .reset(stream, Code::from_u8(0x5a))
                    .expect("live send stream must reset once");
            })
        })
        .expect("established client handle must expose its connection");
    Capture::drive(&mut client, reset_at).expect("fixture drive");
    assert!(Capture::relay(&mut client, &mut server, CLIENT, reset_at).expect("fixture relay") > 0);
    Capture::drive(&mut server, reset_at).expect("fixture drive");

    let history = state.attempts.take();
    let attempts = history
        .iter()
        .copied()
        .filter(|(handle, event, _)| {
            *handle == srv_h
                && *event
                    == (Event::Reset {
                        id: stream,
                        error_code: Code::from_u8(0x5a),
                    })
        })
        .collect::<Vec<_>>();
    assert_eq!(attempts.len(), 2, "one defer followed by one acceptance");
    assert!(attempts[0].2 == Some(key));
    assert!(attempts[0].2 == attempts[1].2);
    assert!(!state.certificates.get());
    assert_eq!(client.handler().events.borrow().certificates, 0);
    assert!(
        client
            .handler()
            .events
            .borrow()
            .owners
            .iter()
            .all(|(owner, handle)| owner == handle)
    );
}
