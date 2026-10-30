use crate::common::peer;
pub mod common;
use common::receive::cancel;
use common::runtime::gso::{self, Capture};
use dope_quic::conn::life::{accept::Authority, options::Options};
use dope_quic::errors::detail::{Diagnostic, Scope, Stream, Streams};
use dope_quic::proto::param;
use dope_quic::runtime::mux::builder::{Builder, Plan};
use dope_quic::runtime::mux::router::Router;
use dope_quic::stream::Capacity;
use dope_quic::wire::{ranges, stream::Id};
use dope_test::alloc::Tracker;
use o3::alloc;
use std::{
    cell::RefCell,
    pin::Pin,
    time::{Duration, Instant},
};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn cancels_then_reuses() {
    let payloads: [&[u8]; 3] = [b"first", b"second", b"third!!"];
    let certs = RefCell::new(Vec::new());
    let params = param::Set::builder()
        .idle_ms(30_000)
        .initial_data(4096)
        .stream_uni(2048)
        .uni_count(3)
        .try_build()
        .expect("three bounded streams");
    let options = || {
        Options::builder()
            .transport(|net| net.params(params.clone()))
            .streams(|streams| streams.recv_parts(3).local_uni(3))
            .try_build()
            .expect("three exact receive slots")
    };
    let mut observed = false;
    for budget in 0..32 {
        let (signing, key) = peer::raw(0x57).expect("receiver signing key");
        let auth = Authority::new(
            signing.server().expect("receiver TLS configuration"),
            options(),
        )
        .expect("receiver authority");
        let mut server: Router<cancel::Capture<_>> = Builder::server(
            cancel::Capture {
                ready: None,
                readable: Vec::new(),
                fault: None,
                packet_error: None,
                certificate: |cause: &rustls::Error| certs.borrow_mut().push(format!("{cause:?}")),
            },
            auth,
        )
        .limits(Plan::try_new(1, 64, 1 << 20).expect("bounded receiver"))
        .build()
        .expect("receiver allocation");
        let mut client = Builder::client(Capture::default())
            .limits(Plan::try_new(1, 64, 1 << 20).expect("bounded sender"))
            .build()
            .expect("sender allocation");
        let mut now = Instant::now();
        let handle = Capture::connect(
            &mut client,
            gso::SERVER,
            key,
            options(),
            gso::CID.to_vec(),
            now,
        )
        .expect("client connection");
        for _ in 0..32 {
            now += Duration::from_millis(30);
            cancel::Capture::deliver(
                &mut server,
                gso::CLIENT,
                Capture::output(&mut client, now).expect("fixture output"),
                now,
            )
            .expect("fixture deliver");
            Capture::deliver_at(
                &mut client,
                gso::SERVER,
                cancel::Capture::output(&mut server, now).expect("fixture output"),
                now,
            )
            .expect("fixture deliver_at");
        }
        let ready = client.handler().events.established.take();
        assert_eq!(ready, [handle]);
        client.handler().events.established.set(ready);
        let peer = server.handler().ready.expect("established receiver");
        assert!(server.handler().fault.is_none());
        Capture::access(&mut client, handle, now, |mut conn| {
            let mut streams = conn.streams();
            let mut send = streams.send();
            for payload in payloads {
                let stream = send.open_uni().expect("three negotiated streams");
                send.send(stream, payload).expect("stream credit");
                send.finish(stream).expect("stream FIN");
            }
        })
        .expect("sender access");
        now = Capture::release_at(&client, &[handle], now).expect("fixture release_at");
        let mut flights = Capture::output(&mut client, now).expect("fixture output");
        assert_eq!(
            flights
                .iter()
                .map(|flight| flight.packet_count().get())
                .sum::<usize>(),
            1
        );
        let mut wire = flights
            .iter_mut()
            .flat_map(|flight| flight.segments_mut())
            .next()
            .expect("one encrypted three-stream packet")
            .to_vec();
        let mut retry = wire.clone();
        let ((), activity) = Tracker::activity(|| {
            Tracker::fail_after(budget, || {
                cancel::Capture::receive(&mut server, gso::CLIENT, &mut wire, now)
                    .expect("fixture receive");
            })
        });
        let fault = matches!(
            server.handler().fault.as_ref(),
            Some(Diagnostic::Streams(Streams::Receiver(Scope::Prepare {
                error: Stream::Range(ranges::Error::Capacity(Capacity::Allocation {
                    error: alloc::Error::Exhausted,
                    requested: 7
                })),
                ..
            })))
        );
        assert!(
            server.handler().packet_error.is_none(),
            "{:?}",
            server.handler().packet_error
        );
        assert!(certs.borrow().is_empty(), "{:?}", certs.borrow());
        if !fault {
            continue;
        }
        assert_eq!(activity.deallocations, 0);
        assert_eq!(activity.deallocated_bytes, 0);
        assert!(server.handler().readable.is_empty());
        Pin::new(&mut server).observe(now, |mut turn| {
            turn.protocol()
                .with_conn(peer, |mut conn| {
                    let streams = conn.streams();
                    let resident = streams.resident();
                    for number in [2, 6, 10] {
                        assert!(
                            resident
                                .handle(Id::new(number).expect("bounded stream identifier"))
                                .is_none()
                        );
                    }
                })
                .expect("receiver access after cancel");
        });
        now += Duration::from_millis(1);
        cancel::Capture::receive(&mut server, gso::CLIENT, &mut retry, now)
            .expect("fixture receive");
        Pin::new(&mut server)
            .observe(now, |mut turn| turn.output().drive())
            .expect("dispatch committed stream notifications");
        assert_eq!(
            server.handler().readable.len(),
            3,
            "budget={budget}, activity={activity:?}"
        );
        Pin::new(&mut server).observe(now, |mut turn| {
            turn.protocol()
                .with_conn(peer, |mut conn| {
                    let mut streams = conn.streams();
                    for (number, payload) in [2, 6, 10].into_iter().zip(payloads) {
                        let stream = streams
                            .view()
                            .resolve_recv(Id::new(number).expect("bounded stream identifier"))
                            .expect("reused receiver slot");
                        assert_eq!(
                            streams
                                .receive()
                                .recv_owned(stream)
                                .expect("committed receive")
                                .expect("received owner"),
                            payload
                        );
                        assert!(streams.view().is_recv_eof(stream));
                        assert!(
                            streams
                                .receive()
                                .recv_owned(stream)
                                .expect("drained owner")
                                .is_none()
                        );
                    }
                })
                .expect("receiver access after replay");
        });
        assert!(
            server.handler().packet_error.is_none(),
            "{:?}",
            server.handler().packet_error
        );
        assert!(certs.borrow().is_empty(), "{:?}", certs.borrow());
        observed = true;
        break;
    }
    assert!(
        observed,
        "no failure cancelled both prepared slots while preserving reusable buffers"
    );
}
