pub mod common;

use common::suite::{
    mux::dispatch::{CLIENT, Capture, Defer},
    peers::{Authority, Error},
};
use dope_quic::conn::stream::Event;
use dope_quic::{
    conn,
    runtime::{mux::builder::Builder, routing},
    wire::packet::cid,
};
use dope_test::harness::observe::VecCellExt as _;
use std::{pin::Pin, rc::Rc, time::Instant};

#[test]
fn parks_until_established() {
    let result = Authority::params()
        .and_then(Authority::options)
        .and_then(Authority::try_new);
    result.as_ref().map_err(Error::cause).expect("setup");
    let auth = result.ok().expect("early authority");
    let result = auth.first(&[0x51; 8]);
    result.as_ref().map_err(Error::cause).expect("setup");
    let initial = cid::Id::try_from([0x52; routing::ENTROPY_LEN]).expect("initial ID");
    let local = cid::Id::try_from([0x53; 8]).expect("client identity");
    let result = auth.resume(initial, local, routing::Plain);
    result.as_ref().map_err(Error::cause).expect("setup");
    let mut client = result.ok().expect("early client");
    let defer = Defer::default();
    let events = Rc::clone(&defer.state);
    let mut server = Builder::server(defer, auth.server)
        .build()
        .expect("server router");
    let now = Instant::now();
    let stream = client.with_scope(|mut conn| {
        let mut streams = conn.streams();
        let mut send = streams.send();
        let stream = send.open_bidi().expect("cached early credit");
        send.send(stream.send(), b"retained")
            .expect("early payload");
        send.finish(stream.send()).expect("early input end");
        stream.id()
    });
    let (emitted_packets, send_result) = client.with_scope(|mut conn| conn.output().send(now));
    send_result.expect("early flight");
    for mut packet in emitted_packets {
        Capture::recv(&mut server, CLIENT, &mut packet, now).expect("fixture recv");
    }
    Capture::drive(&mut server, now).expect("fixture drive");
    let first = {
        let attempts = events.attempts.take();
        assert_eq!(events.established.len(), 0);
        let reads = attempts
            .iter()
            .filter(|(_, event, _)| *event == Event::Readable { id: stream })
            .collect::<Vec<_>>();
        assert_eq!(
            reads.len(),
            1,
            "early deferral must park instead of spinning"
        );
        let first = *reads[0];
        events.attempts.set(attempts);
        first
    };
    let mut work = conn::Workspace::try_new().expect("receive workspace");
    for _ in 0..3 {
        for mut flight in Capture::output(&mut server, now).expect("fixture output") {
            for packet in flight.segments_mut() {
                client
                    .with_scope(|mut conn| conn.input(&mut work).recv_packet(packet, now, |_| {}))
                    .expect("server handshake flight");
            }
        }
        let (emitted_packets, send_result) = client.with_scope(|mut conn| conn.output().send(now));
        send_result.expect("client handshake flight");
        for mut packet in emitted_packets {
            Capture::recv(&mut server, CLIENT, &mut packet, now).expect("fixture recv");
        }
        Capture::drive(&mut server, now).expect("fixture drive");
    }
    let handle = {
        let ready = events.established.take();
        let attempts = events.attempts.take();
        assert_eq!(ready.len(), 1);
        let reads = attempts
            .iter()
            .filter(|(_, event, _)| *event == Event::Readable { id: stream })
            .collect::<Vec<_>>();
        assert!(
            reads.as_slice() == [&first, &first],
            "the same resident event is accepted exactly once after parking"
        );
        let handle = ready[0];
        events.established.set(ready);
        events.attempts.set(attempts);
        handle
    };
    let mut payload = Vec::new();
    Pin::new(&mut server)
        .observe(now, |mut turn| {
            turn.protocol().with_conn(handle, |mut conn| {
                let mut streams = conn.streams();
                let stream = streams
                    .view()
                    .resolve_recv(stream)
                    .expect("retained peer stream");
                streams
                    .receive()
                    .recv(stream, &mut payload)
                    .expect("retained early bytes");
            })
        })
        .expect("established peer");
    assert_eq!(payload, b"retained");
}
