use crate::common::peer;
pub mod common;

use common::receive::cancel;
use common::suite::peers::tls;
use dope_quic::conn::Workspace;
use dope_quic::conn::life::{
    accept::{Authority, Ids},
    options::Options,
};
use dope_quic::errors::detail::{Diagnostic, Scope, Stream, Streams};
use dope_quic::proto::param;
use dope_quic::runtime::routing;
use dope_quic::stream::{Capacity, Recv, RecvBuffer};
use dope_quic::wire::{packet::cid, ranges, stream::Id};
use dope_test::alloc::Tracker;
use o3::{alloc, buffer::storage::Shared};
use std::{
    cell::RefCell,
    time::{Duration, Instant},
};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

fn cancel<B: Recv>(work: &mut Workspace, released: usize) {
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
            .expect("three reusable receiver slots")
    };
    let mut observed = false;
    for budget in 0..32 {
        let (signing, key) = peer::raw(0x58).expect("raw identity");
        let auth = Authority::<0>::new(signing.server().expect("server TLS"), options())
            .expect("sender authority");
        let cid = cid::Id::try_from([0x58; 8]).expect("connection identity");
        let mut sender = auth
            .accept::<Shared>(Ids::initial(cid, cid, cid))
            .expect("sender connection");
        let mut receiver = tls::client(key)
            .expect("receiver TLS")
            .connect::<0, B, Shared>(cid, cid, options(), routing::Plain)
            .expect("receiver connection");
        let mut now = Instant::now();
        let mut handshake = Workspace::try_new().expect("handshake workspace");
        for _ in 0..32 {
            now += Duration::from_millis(30);
            let (packets, result) = receiver.with_scope(|mut scope| scope.output().send(now));
            result.expect("receiver handshake output");
            for mut packet in packets {
                sender
                    .with_scope(|mut scope| {
                        scope
                            .input(&mut handshake)
                            .recv_packet(&mut packet, now, |cause| {
                                certs.borrow_mut().push(format!("{cause:?}"));
                            })
                    })
                    .expect("sender handshake receive");
            }
            let (packets, result) = sender.with_scope(|mut scope| scope.output().send(now));
            result.expect("sender handshake output");
            for mut packet in packets {
                receiver
                    .with_scope(|mut scope| {
                        scope
                            .input(&mut handshake)
                            .recv_packet(&mut packet, now, |cause| {
                                certs.borrow_mut().push(format!("{cause:?}"));
                            })
                    })
                    .expect("receiver handshake receive");
            }
        }
        assert!(sender.view().lifecycle().is_ready());
        assert!(receiver.view().lifecycle().is_ready());
        sender.with_scope(|mut conn| {
            let mut streams = conn.streams();
            let mut send = streams.send();
            for payload in payloads {
                let stream = send.open_uni().expect("three negotiated streams");
                send.send(stream, payload).expect("stream credit");
                send.finish(stream).expect("stream FIN");
            }
        });
        now = sender.view().recovery().send_at(now);
        let (packets, result) = sender.with_scope(|mut scope| scope.output().send(now));
        result.expect("sender output");
        assert_eq!(packets.len(), 1);
        let mut wire = packets.into_iter().next().expect("one encrypted packet");
        let mut retry = wire.clone();
        let mut proof = cancel::Proof(None, |cause: &rustls::Error| {
            certs.borrow_mut().push(format!("{cause:?}"));
        });
        let (result, activity) = Tracker::activity(|| {
            Tracker::fail_after(budget, || {
                receiver
                    .with_scope(|mut scope| scope.input(work).recv_with(&mut wire, now, &mut proof))
            })
        });
        result.expect("recoverable input");
        let fault = matches!(
            proof.0,
            Some(Diagnostic::Streams(Streams::Receiver(Scope::Prepare {
                error: Stream::Range(ranges::Error::Capacity(Capacity::Allocation {
                    error: alloc::Error::Exhausted,
                    requested: 7,
                })),
                ..
            })))
        );
        assert!(certs.borrow().is_empty(), "{:?}", certs.borrow());
        if !fault {
            continue;
        }
        assert_eq!(activity.deallocations, 2 * released);
        assert_eq!(activity.deallocated_bytes, 11 * released);
        receiver.with_scope(|mut scope| {
            let mut streams = scope.streams();
            for number in [3, 7, 11] {
                assert!(
                    streams
                        .resident()
                        .handle(Id::new(number).expect("bounded stream identifier"))
                        .is_none()
                );
            }
            assert!(streams.events().poll().is_none());
        });
        now += Duration::from_millis(1);
        receiver
            .with_scope(|mut scope| scope.input(work).recv_with(&mut retry, now, &mut proof))
            .expect("replay after cancel");
        receiver.with_scope(|mut scope| {
            let mut streams = scope.streams();
            for (number, payload) in [3, 7, 11].into_iter().zip(payloads) {
                let stream = streams
                    .view()
                    .resolve_recv(Id::new(number).expect("bounded stream identifier"))
                    .expect("reused slot");
                assert_eq!(
                    streams
                        .receive()
                        .recv_owned(stream)
                        .expect("received data")
                        .expect("owned data"),
                    payload
                );
                assert!(streams.view().is_recv_eof(stream));
            }
        });
        assert!(certs.borrow().is_empty(), "{:?}", certs.borrow());
        observed = true;
        break;
    }
    assert!(observed, "cancel did not exercise both prepared owners");
}

#[test]
fn cancels_before_reloan() {
    let mut work = Workspace::try_new().expect("one serialized receive workspace");
    cancel::<Vec<u8>>(&mut work, 0);
    cancel::<RecvBuffer<'_, true>>(&mut work, 1);
    cancel::<RecvBuffer<'_, false>>(&mut work, 1);
    cancel::<Vec<u8>>(&mut work, 0);
}
