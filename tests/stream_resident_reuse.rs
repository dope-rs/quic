pub mod common;

use common::peer::{Pair, Receiver};
use dope_quic::conn::stream::{access::bindings, event};
use std::time::Instant;

#[test]
fn empty_fin_cancels_readable() {
    let (mut server, mut client, mut wire) =
        Pair::try_default().expect("connected peers").into_parts();
    for resident in [false, true] {
        let id = client.with_scope(|mut scope| {
            let mut streams = scope.streams();
            let stream = streams.send().open_uni().expect("empty stream");
            streams.send().finish(stream).expect("empty FIN");
            stream.id()
        });
        Receiver::receive_from(&mut server, &mut wire, &mut client, Instant::now())
            .expect("empty FIN delivery");
        server.with_scope(|mut scope| {
            let mut streams = scope.streams();
            let handle = streams.resident().handle(id).expect("receive identity");
            let key = handle.local().key();
            assert!(streams.view().has_events());
            assert!(streams.binding().try_attach(handle) == Ok(bindings::Attach::Added));
            let (held, eof) = if resident {
                streams.try_hold_eof(handle).expect("admitted resident")
            } else {
                let receive = streams.view().resolve_recv(id).expect("receive half");
                streams.receive().hold_eof(receive)
            };
            assert!(held.is_none() && eof);
            assert!(
                streams.events().poll().is_none(),
                "consumed FIN is not readable"
            );
            assert_eq!(streams.try_recv_eof(handle), Ok(true));
            assert!(streams.binding().try_release(handle).is_ok());
            assert!(streams.resident().handle_key(key).is_none());
        });
    }
}

#[test]
fn reused_slot_is_clear() {
    let (mut server, mut client, mut wire) =
        Pair::try_default().expect("connected peers").into_parts();
    let first = client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let stream = streams
            .send()
            .open_uni()
            .expect("client must open the first stream");
        streams
            .send()
            .send(stream, b"first")
            .expect("first stream must accept payload");
        streams
            .send()
            .finish(stream)
            .expect("first stream must finish");
        stream.id()
    });

    Receiver::receive_from(&mut server, &mut wire, &mut client, Instant::now())
        .expect("peer packet transfer");

    let (origin, retired) = server.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let stream = match streams.events().poll() {
            Some(event::Item::Readable { id }) => Some(id),
            _ => None,
        }
        .expect("first server event must be readable");
        assert!(stream.id() == first);
        let resident = streams.resident();
        let handle = resident
            .handle(first)
            .expect("first stream must have a resident handle");
        let origin = resident.origin();
        let local = handle.local();
        assert_eq!(streams.try_recv_eof(handle), Ok(false));
        {
            let mut binding = streams.binding();
            assert!(binding.try_attach(handle) == Ok(bindings::Attach::Added));
            assert!(binding.try_bind(handle, 17) == Ok(bindings::Bind::Added));
        }
        let (held, eof) = streams.try_hold_eof(handle).expect("resident stream");
        let held = held.expect("final payload");
        assert_eq!(held.as_ref(), b"first");
        assert!(eof);
        assert!(matches!(streams.try_hold_eof(handle), Ok((None, true))));
        held.release(&mut streams.receive());
        assert!(streams.view().is_recv_eof(stream));
        assert_eq!(streams.try_recv_eof(handle), Ok(true));
        assert!(matches!(streams.try_hold_eof(handle), Ok((None, true))));
        assert!(matches!(streams.receive().hold_eof(stream), (None, true)));
        assert!(
            streams.binding().try_retire(handle, 18)
                == Err(bindings::Fault::Bound {
                    local,
                    expected: 18,
                    actual: 17,
                })
        );
        assert!(streams.binding().try_slot(handle) == Ok(Some(17)));
        assert!(streams.binding().try_retire(handle, 17).is_ok());
        assert!(matches!(
            streams.try_recv_eof(handle),
            Err(stale) if stale.local() == local && stale.actual().is_none()
        ));
        assert!(matches!(
            streams.try_hold_eof(handle),
            Err(stale) if stale.local() == local && stale.actual().is_none()
        ));
        (origin, local)
    });

    let second = client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let stream = streams
            .send()
            .open_uni()
            .expect("client must open the second stream");
        streams
            .send()
            .send(stream, b"second")
            .expect("second stream must accept payload");
        stream.id()
    });

    Receiver::receive_from(&mut server, &mut wire, &mut client, Instant::now())
        .expect("peer packet transfer");

    server.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let stream = match streams.events().poll() {
            Some(event::Item::Readable { id }) => Some(id),
            _ => None,
        }
        .expect("second server event must be readable");
        assert!(stream.id() == second);
        let resident = streams.resident();
        let handle = resident
            .handle(second)
            .expect("second stream must have a resident handle");
        let reused = handle.local().key();
        assert_eq!(reused.raw().get() as u32, retired.key().raw().get() as u32);
        assert_ne!(reused.raw().get() >> 32, retired.key().raw().get() >> 32);
        assert!(resident.handle_key(reused) == Some(handle));
        assert!(resident.handle_key(retired.key()).is_none());
        let owner = resident
            .owner(origin)
            .expect("resident origin must remain valid");
        assert!(matches!(
            resident.bind(owner, retired),
            Err(stale) if stale.local() == retired && stale.actual().is_none()
        ));
        assert!(streams.binding().try_slot(handle) == Ok(None));
        let (held, eof) = streams.receive().hold_eof(stream);
        let held = held.expect("replacement payload");
        assert_eq!(held.as_ref(), b"second");
        assert!(!eof);
        assert!(matches!(streams.try_hold_eof(handle), Ok((None, false))));
        held.release(&mut streams.receive());
    });
}
