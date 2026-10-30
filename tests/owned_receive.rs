use crate::common::peer;
pub mod common;

use common::receive::copied;
use common::runtime::gso::{self, Capture};
use dope_quic::conn::life::{accept::Authority, options::Options};
use dope_quic::proto::param;
use dope_quic::runtime::mux::builder::{Builder, Plan};
use dope_quic::stream::{Recv as _, RecvBuffer};
use dope_test::alloc::Tracker;
use o3::buffer::Residency as _;
use std::{
    cell::RefCell,
    num::NonZero,
    pin::Pin,
    time::{Duration, Instant},
};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn moves_received_owner() {
    let certs = RefCell::new(Vec::new());
    let params = param::Set::builder()
        .idle_ms(30_000)
        .initial_data(4096)
        .stream_uni(2048)
        .uni_count(2)
        .try_build()
        .expect("bounded receive parameters");
    let options = || {
        Options::builder()
            .transport(|net| net.params(params.clone()))
            .streams(|streams| streams.recv_parts(1))
            .try_build()
            .expect("one reusable receive node")
    };
    let (signing, key) = peer::raw(0x56).expect("raw identity");
    let mut server = Builder::server(
        copied::Capture {
            ready: None,
            readable: None,
            released: 0,
            certificate: |cause: &rustls::Error| certs.borrow_mut().push(format!("{cause:?}")),
        },
        Authority::new(signing.server().expect("server TLS"), options())
            .expect("receiver authority"),
    )
    .limits(Plan::try_new(1, 64, 1 << 20).expect("bounded receiver"))
    .build()
    .expect("receiver router");
    let mut client = Builder::client(Capture::default())
        .limits(Plan::try_new(1, 64, 1 << 20).expect("bounded output"))
        .build()
        .expect("client router");
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
    for _ in 0..16 {
        now += Duration::from_millis(1);
        copied::Capture::deliver(
            &mut server,
            gso::CLIENT,
            Capture::output(&mut client, now).expect("fixture output"),
            now,
        )
        .expect("fixture deliver");
        Capture::deliver_at(
            &mut client,
            gso::SERVER,
            copied::Capture::output(&mut server, now).expect("fixture output"),
            now,
        )
        .expect("fixture deliver_at");
    }
    let ready = client.handler().events.established.take();
    assert!(ready == [handle]);
    client.handler().events.established.set(ready);
    let peer = server.handler().ready.expect("established receiver");
    for (ordinal, payload) in [b"owned", b"again"].into_iter().enumerate() {
        Capture::access(&mut client, handle, now, |mut conn| {
            let mut streams = conn.streams();
            let mut send = streams.send();
            let stream = send.open_uni().expect("negotiated stream");
            send.send(stream, payload).expect("stream credit");
            send.finish(stream).expect("stream FIN");
        })
        .expect("established sender");
        now = Capture::release_at(&client, &[handle], now).expect("fixture release_at");
        let flights = Capture::output(&mut client, now).expect("fixture output");
        assert!(!flights.is_empty());
        {
            copied::Capture::deliver(&mut server, gso::CLIENT, flights, now)
                .expect("fixture deliver");

            Capture::deliver_at(
                &mut client,
                gso::SERVER,
                copied::Capture::output(&mut server, now).expect("fixture output"),
                now,
            )
            .expect("fixture deliver_at");
            let id = server.handler().readable.expect("readable owner");
            assert_eq!(id.number(), ordinal as u64);
            Pin::new(&mut server).observe(now, |mut turn| {
                turn.protocol()
                    .with_conn(peer, |mut conn| {
                        let mut streams = conn.streams();
                        let stream = streams.view().resolve_recv(id).expect("bound stream");
                        assert!(streams.view().has_recv_fin(stream));
                        assert!(!streams.view().is_recv_eof(stream));
                        let ((bytes, expected), moved) = Tracker::activity(|| {
                            Tracker::fail_after(0, || {
                                if ordinal == 0 {
                                    let bytes = streams
                                        .receive()
                                        .recv_owned(stream)
                                        .expect("owned read needs no allocation")
                                        .expect("one owner");
                                    (RecvBuffer::from_vec(bytes), &payload[..])
                                } else {
                                    let held = streams.receive().hold(stream).expect("held owner");
                                    assert_eq!(held.as_ref(), payload);
                                    let (bytes, mut credit) = held.into_parts();
                                    let pointer = bytes.as_ref().as_ptr();
                                    let resident = bytes.resident();
                                    let bytes = bytes.into_suffix(2);
                                    assert_eq!(bytes.as_ref().as_ptr(), pointer);
                                    assert_eq!(bytes.resident(), resident);
                                    let prefix = credit
                                        .take_prefix(NonZero::new(2).expect("nonzero"))
                                        .expect("delivered prefix");
                                    assert_eq!((prefix.len(), credit.len()), (2, bytes.len()));
                                    prefix.release(&mut streams.receive());
                                    credit.release(&mut streams.receive());
                                    (bytes, &payload[2..])
                                }
                            })
                        });
                        assert_eq!(bytes.as_ref(), expected);

                        assert_eq!(moved.allocations, 0);
                        assert_eq!(moved.deallocations, 0);
                        assert!(streams.view().is_recv_eof(stream));
                        assert!(
                            streams
                                .receive()
                                .recv_owned(stream)
                                .expect("drained owner")
                                .is_none()
                        );
                        let ((), freed) = Tracker::activity(|| drop(bytes));

                        assert_eq!(freed.deallocations, 1);
                        assert_eq!(freed.deallocated_bytes, 5);
                    })
                    .expect("connection access");
            });
        }
    }
    assert!(certs.borrow().is_empty(), "{:?}", certs.borrow());
    assert_eq!(server.handler().released, 0);
}
