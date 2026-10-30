pub mod common;

use common::{receive::cancel::Proof, suite::peers::packet::Pair};
use dope_quic::{
    conn::life::options::Options,
    errors::detail::{Diagnostic, Unavailable},
    proto::param,
    wire::{
        frame::{self, Borrowed, Boundary, Length},
        stream::Id,
        varint::VarInt,
    },
};
use dope_test::alloc::Tracker;
use std::time::Instant;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn queue_alloc_retry() {
    let old = [0xf0, 0xf1];
    let id = Id::new(2).expect("peer unidirectional stream");
    let mut found = false;
    for budget in 0..128 {
        let now = Instant::now();
        let params = param::Set::builder()
            .initial_data(4096)
            .stream_uni(2048)
            .uni_count(1)
            .datagram(Some(4))
            .try_build()
            .expect("stream and datagram parameters");
        let options = Options::builder()
            .transport(|net| net.params(params))
            .streams(|streams| streams.local_uni(0).recv_parts(1))
            .datagrams(|queue| queue.incoming(64))
            .try_build()
            .expect("bounded receive queues");
        let mut pair = Pair::try_options(options, now, |_| {}).expect("peer handshake");
        for byte in old {
            pair.receive(&[frame::TYPE_DATAGRAM_LEN, 1, byte], now)
                .expect("existing queued datagram");
        }
        let mut frames = Vec::new();
        Borrowed::stream(id, VarInt::ZERO, Boundary::End, Length::Explicit, b"stream")
            .expect("stream frame")
            .encode(&mut frames)
            .expect("encoded stream");
        for byte in 0..32 {
            frames.extend_from_slice(&[frame::TYPE_DATAGRAM_LEN, 1, byte]);
        }
        let mut wire = pair.peer.packet(&frames).expect("mixed receive packet");
        let mut retry = wire.clone();
        let mut proof = Proof(None, |_: &rustls::Error| {});
        Tracker::fail_after(budget, || {
            pair.server.with_scope(|mut scope| {
                scope
                    .input(&mut pair.work)
                    .recv_with(&mut wire, now, &mut proof)
            })
        })
        .expect("allocation rejection is a packet drop");
        match proof.0.as_ref() {
            Some(Diagnostic::Datagram(Unavailable::Queue {
                requested: count, ..
            })) => {
                assert_eq!(*count, 32);
            }
            _ => continue,
        }
        pair.server.with_scope(|mut scope| {
            assert!(scope.streams().resident().handle(id).is_none());
            let mut queue = scope.datagrams();
            for byte in old {
                assert_eq!(queue.recv().as_deref(), Some([byte].as_slice()));
            }
            assert!(queue.recv().is_none());
        });
        proof.0 = None;
        pair.server
            .with_scope(|mut scope| {
                scope
                    .input(&mut pair.work)
                    .recv_with(&mut retry, now, &mut proof)
            })
            .expect("same packet retries after queue rejection");
        assert!(proof.0.is_none());
        pair.server.with_scope(|mut scope| {
            let mut queue = scope.datagrams();
            for byte in 0..32 {
                assert_eq!(queue.recv().as_deref(), Some([byte].as_slice()));
            }
            assert!(queue.recv().is_none());
        });
        pair.server.with_scope(|mut scope| {
            let mut streams = scope.streams();
            let stream = streams
                .view()
                .resolve_recv(id)
                .expect("retried peer stream");
            assert_eq!(
                streams
                    .receive()
                    .recv_owned(stream)
                    .expect("stream body")
                    .as_deref(),
                Some(b"stream".as_slice()),
            );
            assert!(streams.view().is_recv_eof(stream));
            assert!(
                streams
                    .receive()
                    .recv_owned(stream)
                    .expect("drained stream")
                    .is_none()
            );
        });
        found = true;
        break;
    }
    assert!(found);
}
