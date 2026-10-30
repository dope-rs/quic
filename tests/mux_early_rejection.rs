pub mod common;

use common::suite::{
    mux::dispatch::{CID, CLIENT, Capture, Reject, SERVER},
    peers::{Authority, Error},
};
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::{conn::stream::Event, errors::Code};
use std::{pin::Pin, time::Instant};

#[test]
fn notifies_rejected_resume() {
    let result = Authority::params()
        .and_then(Authority::options)
        .and_then(Authority::try_new);
    result.as_ref().map_err(Error::cause).expect("setup");
    let auth = result.ok().expect("early authority");
    let result = auth.first(&CID);
    result.as_ref().map_err(Error::cause).expect("ticket");
    auth.server.reject_early();
    let result = Authority::params().and_then(Authority::options);
    result.as_ref().map_err(Error::cause).expect("options");
    let options = result.ok().expect("client options");
    let mut server = Builder::server(Capture::default(), auth.server)
        .build()
        .expect("server router");
    let mut client = Builder::client(Reject::default())
        .build()
        .expect("client router");
    let now = Instant::now();
    let handle = Pin::new(&mut client)
        .observe(now, |mut turn| {
            turn.protocol()
                .connect(SERVER, &auth.client, options, CID.to_vec())
        })
        .expect("resumed mux client");
    let stream = Pin::new(&mut client)
        .observe(now, |mut turn| {
            turn.protocol().with_conn(handle, |mut conn| {
                let mut streams = conn.streams();
                let mut send = streams.send();
                let stream = send.open_bidi().expect("cached early credit");
                send.send(stream.send(), b"rejected")
                    .expect("early payload");
                send.finish(stream.send()).expect("early input end");
                stream.id()
            })
        })
        .expect("client connection");
    let mut early = false;
    for mut flight in Capture::output(&mut client, now).expect("early flight") {
        for packet in flight.segments_mut() {
            early |= packet.first().is_some_and(|byte| byte & 0xF0 == 0xD0);
            Capture::recv(&mut server, CLIENT, packet, now).expect("early receive");
        }
    }
    assert!(early, "the mux client must send an actual 0-RTT packet");
    for _ in 0..4 {
        Capture::relay(&mut server, &mut client, SERVER, now).expect("server relay");
        Capture::relay(&mut client, &mut server, CLIENT, now).expect("client relay");
    }
    let peer = server.sole().expect("server connection");
    let mut payload = Vec::new();
    Pin::new(&mut server)
        .observe(now, |mut turn| {
            turn.protocol().with_conn(peer, |mut conn| {
                let mut streams = conn.streams();
                let stream = streams
                    .view()
                    .resolve_recv(stream)
                    .expect("replayed stream");
                streams
                    .receive()
                    .recv(stream, &mut payload)
                    .expect("replayed payload");
            })
        })
        .expect("server connection");
    Capture::drive(&mut client, now).expect("continued notification progress");
    let events = client.handler();
    assert_eq!(events.rejected, [(handle, 0)]);
    assert_eq!(events.ready, [handle]);
    assert_eq!(payload, b"rejected");
}

#[test]
fn retains_reset() {
    for code in [Code::ZERO, Code::MAX] {
        for queued in [false, true] {
            let result = Authority::params()
                .and_then(Authority::options)
                .and_then(Authority::try_new);
            result.as_ref().map_err(Error::cause).expect("setup");
            let auth = result.ok().expect("early authority");
            auth.first(&CID)
                .as_ref()
                .map_err(Error::cause)
                .expect("resumption ticket");
            auth.server.reject_early();
            let result = Authority::params().and_then(Authority::options);
            result.as_ref().map_err(Error::cause).expect("options");
            let options = result.ok().expect("client options");
            let mut server = Builder::server(Capture::default(), auth.server)
                .build()
                .expect("server router");
            let mut client = Builder::client(Reject::default())
                .build()
                .expect("client router");
            let now = Instant::now();
            let handle = Pin::new(&mut client)
                .observe(now, |mut turn| {
                    turn.protocol()
                        .connect(SERVER, &auth.client, options, CID.to_vec())
                })
                .expect("resumed connection");
            let stream = Pin::new(&mut client)
                .observe(now, |mut turn| {
                    turn.protocol().with_conn(handle, |mut conn| {
                        let mut streams = conn.streams();
                        let mut send = streams.send();
                        let stream = send.open_bidi().expect("early stream");
                        send.send(stream.send(), b"discarded").expect("early bytes");
                        let witness = send.open_bidi().expect("early witness");
                        send.send(witness.send(), b"live").expect("witness bytes");
                        send.finish(witness.send()).expect("witness end");
                        if queued {
                            send.reset(stream.send(), code).expect("early reset");
                        }
                        stream.id()
                    })
                })
                .expect("client owner");
            let flights = Capture::output(&mut client, now).expect("early flight");
            if !queued {
                Pin::new(&mut client)
                    .observe(now, |mut turn| {
                        turn.protocol().with_conn(handle, |mut conn| {
                            let mut streams = conn.streams();
                            let stream = streams.view().resolve_send(stream).expect("live sender");
                            streams.send().reset(stream, code).expect("deferred reset");
                        })
                    })
                    .expect("client owner");
            }
            let mut early = false;
            for mut flight in flights {
                for packet in flight.segments_mut() {
                    early |= packet.first().is_some_and(|byte| byte & 0xF0 == 0xD0);
                    Capture::recv(&mut server, CLIENT, packet, now).expect("early receive");
                }
            }
            assert!(early, "actual 0-RTT flight: code={code:?} queued={queued}");
            for _ in 0..4 {
                Capture::relay(&mut server, &mut client, SERVER, now).expect("server relay");
                Capture::relay(&mut client, &mut server, CLIENT, now).expect("client relay");
            }
            let events = server.handler().events.borrow();
            let resets = events
                .streams
                .iter()
                .filter(|(_, event)| {
                    *event
                        == Event::Reset {
                            id: stream,
                            error_code: code,
                        }
                })
                .count();
            assert_eq!(resets, 1, "one reset with its original code");
            assert_eq!(client.handler().rejected, [(handle, 0)]);
        }
    }
}
