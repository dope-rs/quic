use common::peer::Receiver;
pub mod common;

use common::peer::Pair;
use common::suite::mux::paths;
use common::suite::peers::path;
use dope::core::driver::schedule::clock;
use dope_quic::conn::{Mutation, stream, wire::packet::Batch};
use dope_quic::errors::{Code, SendFailure};
use dope_quic::security::qkdf::Initial;
use dope_quic::wire::{
    frame::{Frame, View, close},
    packet::long::{Parsed, initial::Prefix},
};
use std::{
    pin::Pin,
    time::{Duration, Instant},
};

#[test]
fn initial_close_floor() {
    let mut client = path::try_initial().expect("initial client");
    let now = Instant::now();
    let mut batch = Batch::default();
    client
        .with_scope(|mut scope| {
            scope
                .lifecycle()
                .close(Code::ZERO, b"application detail".to_vec());
            scope.output().send_batch(&mut batch, now, 1, 1_199)
        })
        .expect("insufficient capacity defers close");
    assert!(batch.is_empty());
    assert_eq!(batch.byte_len(), 0);
    assert!(client.view().lifecycle().is_closing());
    assert!(!client.view().lifecycle().is_closed());

    client
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, now, 1, 1_200))
        .expect("minimum Initial capacity admits close");
    assert_eq!(batch.packets(), 1);
    let packet = batch.iter_mut().next().expect("Initial close packet");
    assert_eq!(packet.len(), 1_200);
    let prefix = Prefix::decode(packet).expect("Initial close header");
    let open = Initial::try_new(prefix.dcid.into_slice())
        .expect("initial derivation")
        .try_client()
        .expect("client key admission");
    let packet = match Parsed::parse(packet).expect("protected close packet") {
        Parsed::Initial(packet) => Some(packet),
        _ => None,
    }
    .expect("close retains Initial protection");
    let opened = packet.decrypt(&open, 0).expect("Initial close protection");
    let (frame, _) = Frame::decode_ref(opened.body()).expect("close frame");
    assert!(matches!(
        frame.view(),
        View::ConnectionClose {
            code: close::Code::Transport { error_code, .. },
            reason,
        } if error_code.get() == 0x0c && reason.is_empty()
    ));
    assert!(client.view().lifecycle().is_closed());
}

#[test]
fn closes_application() {
    let (mut server, mut client, mut wire) =
        Pair::try_default().expect("connected peers").into_parts();
    clock::Scope::run(|clock| {
        let now = clock.now();
        let due = now.try_add(Duration::from_secs(1)).expect("deadline");
        client.with_scope(|mut scope| {
            assert!(matches!(
                scope.application().sync(Some(due)),
                Mutation::Replaced
            ));
            scope.application().ready();
            let stream = scope.streams().send().open_bidi().expect("open stream");
            scope.lifecycle().close(Code::ZERO, Vec::new());
            assert!(!scope.view().lifecycle().is_closed());
            assert!(matches!(
                scope.streams().send().open_bidi(),
                Err(stream::Error::NotEstablished)
            ));
            assert_eq!(
                scope.streams().send().send(stream.send(), b"late"),
                Err(stream::Error::NotEstablished)
            );
            let data = b"late".to_vec();
            let storage = (data.as_ptr(), data.capacity());
            assert!(matches!(
                scope.datagrams().try_send(data),
                Err(SendFailure::Closed(data))
                    if (data.as_ptr(), data.capacity()) == storage && data == b"late"
            ));
            assert!(matches!(
                scope.application().sync(None),
                Mutation::Unchanged
            ));
            scope.application().ready();
            assert!(matches!(
                scope.application().sync(Some(due)),
                Mutation::Unchanged
            ));
        });
        Receiver::receive_from(&mut server, &mut wire, &mut client, now.into_raw())
            .expect("peer packet transfer");
        assert!(client.view().lifecycle().is_closed());
        assert!(server.view().lifecycle().is_closed());
    });
}

#[test]
fn rejects_closing() {
    let mut pair = paths::Pending::try_new(19, 21)
        .expect("router pair")
        .establish()
        .expect("path fixture operation");
    Pin::new(&mut pair.client).observe(pair.start, |mut turn| {
        turn.with_app(pair.client_id, |mut conn| {
            conn.ready();
            conn.transport().lifecycle().close(Code::ZERO, Vec::new());
            conn.ready();
            assert!(!conn.transport().view().lifecycle().is_closed());
        })
        .expect("open application");
        assert_eq!(
            turn.with_app(pair.client_id, |_| ()),
            Err(dope_quic::errors::Access::Closed)
        );
    });
    for router in [&pair.client, &pair.server] {
        assert!(
            router.handler().errors.is_empty(),
            "{:?}",
            router.handler().errors
        );
    }
}
