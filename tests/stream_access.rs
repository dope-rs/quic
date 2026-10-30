use common::peer::Pair;
use common::peer::Receiver;
pub mod common;
use common::receive::retained::Commit;

use dope_quic::errors::Code;
use std::time::{Duration, Instant};

use dope_quic::conn::stream::{Error, access::bindings, event};
use dope_quic::stream::send;
use dope_quic::wire::stream::Direction;
use send::admit;

#[test]
fn tracks_one_stream() {
    let mut client = Pair::try_default().expect("connected peers").into_parts().1;
    client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let first = streams.send().open_bidi().expect("first stream must open");
        let second = streams.send().open_bidi().expect("second stream must open");
        assert_eq!(streams.view().buffered(first.send()), 0);
        assert!(streams.view().is_send_open(first.send()));
        streams
            .send()
            .send(first.send(), b"first")
            .expect("first payload must fit");
        streams
            .send()
            .send(second.send(), b"second")
            .expect("second payload must fit");
        assert_eq!(streams.view().buffered(first.send()), 5);
        assert_eq!(streams.view().buffered(second.send()), 6);
        streams
            .send()
            .reset(first.send(), Code::ZERO)
            .expect("first stream must reset");
        assert_eq!(streams.view().buffered(first.send()), 0);
        assert_eq!(streams.view().buffered(second.send()), 6);
        assert!(!streams.view().is_send_open(first.send()));
        assert!(streams.view().is_send_open(second.send()));
    });
}

#[test]
fn branded_ids_work() {
    let (mut server, mut client, mut wire) =
        Pair::try_default().expect("connected peers").into_parts();
    let id = client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let stream = streams
            .send()
            .open_bidi()
            .expect("client must open a bidirectional stream");
        streams
            .send()
            .send(stream.send(), b"branded")
            .expect("client stream must accept payload");
        streams
            .send()
            .finish(stream.send())
            .expect("client stream must finish");
        assert!(!streams.view().is_send_open(stream.send()));
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
        .expect("server event must be readable");
        assert!(stream.id() == id);
        assert_eq!(
            streams
                .receive()
                .recv_owned(stream)
                .expect("fixture receive capacity must admit the branded stream")
                .as_deref(),
            Some(&b"branded"[..])
        );
        assert!(streams.view().is_recv_eof(stream));
    });
}

#[test]
fn inert_id_revalidates() {
    let mut client = Pair::try_default().expect("connected peers").into_parts().1;
    let id = client.with_scope(|mut scope| {
        scope
            .streams()
            .send()
            .open_bidi()
            .expect("client must open a bidirectional stream")
            .id()
    });

    client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let stream = streams
            .view()
            .resolve_send(id)
            .expect("saved identity must resolve for sending");
        streams
            .send()
            .send(stream, b"durable")
            .expect("resolved stream must accept payload");
        streams
            .send()
            .finish(stream)
            .expect("resolved stream must finish");
    });
}

#[test]
fn resident_key_crosses() {
    let mut client = Pair::try_default().expect("connected peers").into_parts().1;
    let (id, key) = client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let id = streams
            .send()
            .open_bidi()
            .expect("client must open a resident stream")
            .id();
        let resident = streams.resident();
        let key = resident
            .key(id)
            .expect("opened stream must have a resident key");
        assert!(resident.id(key) == Some(id));
        (id, key)
    });

    client.with_scope(|mut scope| {
        let streams = scope.streams();
        let resident = streams.resident();
        assert!(resident.id(key) == Some(id));
        assert!(resident.key(id) == Some(key));
    });
}

#[test]
fn binding_tracks_resident() {
    let mut client = Pair::try_default().expect("connected peers").into_parts().1;

    client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let handle = streams
            .send()
            .open_handle(Direction::Bidi)
            .expect("client must open a resident stream");
        let id = handle.id();
        let mut binding = streams.binding();

        assert!(binding.try_attach(handle) == Ok(bindings::Attach::Added));
        assert!(binding.try_attach(handle) == Ok(bindings::Attach::Present));
        assert!(binding.try_release(handle) == Ok(bindings::Release::Unbound));

        assert!(binding.try_slot(handle) == Ok(None));
        assert!(binding.try_bind(handle, 17) == Ok(bindings::Bind::Added));
        assert!(binding.try_slot(handle) == Ok(Some(17)));
        assert!(binding.try_bind(handle, 17) == Ok(bindings::Bind::Present));
        assert!(
            binding.try_bind(handle, 18)
                == Err(bindings::Fault::Bound {
                    local: handle.local(),
                    expected: 18,
                    actual: 17,
                }),
        );
        assert!(
            binding.try_unbind(handle, 18)
                == Err(bindings::Fault::Bound {
                    local: handle.local(),
                    expected: 18,
                    actual: 17,
                }),
        );
        assert!(binding.try_unbind(handle, 17).is_ok());
        assert!(binding.try_slot(handle) == Ok(None));
        assert!(streams.resident().handle(id) == Some(handle));
    });
}

#[test]
fn resident_send_is_direct() {
    let (mut server, mut client, mut wire) =
        Pair::try_default().expect("connected peers").into_parts();
    let id = client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let handle = streams
            .send()
            .open_handle(Direction::Bidi)
            .expect("client must open a resident stream");
        let id = handle.id();
        let parts = send::Parts::new(
            send::Buffer::Owned(b"resident-direct".to_vec()),
            None,
            send::Boundary::End,
        );
        let outcome = streams.try_write(handle, parts, Commit);

        assert!(
            matches!(outcome, admit::Outcome::Retained(actual) if actual == id),
            "resident admission must retain its exact source"
        );
        id
    });

    Receiver::receive_from(&mut server, &mut wire, &mut client, Instant::now())
        .expect("peer packet transfer");

    server.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let stream = match streams.events().poll() {
            Some(event::Item::Readable { id }) => Some(id),
            _ => None,
        }
        .expect("direct server event must be readable");
        assert!(stream.id() == id);
        let handle = streams
            .resident()
            .handle(id)
            .expect("direct stream must have a resident handle");
        streams
            .binding()
            .try_prepare(handle)
            .expect("resident send state must prepare");
        assert_eq!(
            streams
                .receive()
                .recv_owned(stream)
                .expect("fixture receive capacity must admit the direct stream")
                .as_deref(),
            Some(&b"resident-direct"[..])
        );
        assert!(streams.view().is_recv_eof(stream));
        let parts = send::Parts::new(
            send::Buffer::Owned(b"incoming-resident-direct".to_vec()),
            None,
            send::Boundary::End,
        );
        let outcome = streams.try_write(handle, parts, Commit);
        assert!(
            matches!(outcome, admit::Outcome::Retained(actual) if actual == id),
            "resident admission must retain its exact source"
        );
    });

    Receiver::receive_from(&mut client, &mut wire, &mut server, Instant::now())
        .expect("peer packet transfer");

    client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let stream = match streams.events().poll() {
            Some(event::Item::Readable { id }) => Some(id),
            _ => None,
        }
        .expect("direct client event must be readable");
        assert!(stream.id() == id);
        assert_eq!(
            streams
                .receive()
                .recv_owned(stream)
                .expect("fixture receive capacity must admit the direct response")
                .as_deref(),
            Some(&b"incoming-resident-direct"[..])
        );
        assert!(streams.view().is_recv_eof(stream));
    });
}

#[test]
fn origin_rejects_foreign() {
    let mut first = Pair::try_default().expect("connected peers").into_parts().1;
    let mut second = Pair::try_default().expect("connected peers").into_parts().1;
    let (origin_a, local_a) = first.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let handle = streams
            .send()
            .open_handle(Direction::Bidi)
            .expect("first connection must open a resident stream");
        (streams.resident().origin(), handle.local())
    });
    let (origin_b, local_b) = second.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let handle = streams
            .send()
            .open_handle(Direction::Bidi)
            .expect("second connection must open a resident stream");
        (streams.resident().origin(), handle.local())
    });

    assert!(origin_a != origin_b);
    assert!(local_a == local_b);
    second.with_scope(|mut scope| {
        let streams = scope.streams();
        assert!(streams.resident().owner(origin_a).is_err());
    });

    first.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let resident = streams.resident();
        let owner = resident
            .owner(origin_a)
            .expect("first origin must remain valid");
        let handle = resident
            .bind(owner, local_a)
            .expect("first local handle must rebind");
        let parts = send::Parts::new(send::Buffer::Owned(Vec::new()), None, send::Boundary::End);
        let outcome = streams.try_write(handle, parts, Commit);
        assert!(
            matches!(outcome, admit::Outcome::Retained(actual) if actual == local_a.id()),
            "resident admission must retain its exact source"
        );
    });
}

#[test]
fn stopped_peer_closed() {
    let (mut server, mut client, mut wire) =
        Pair::try_default().expect("connected peers").into_parts();
    let code = Code::from_u8(0x95);
    let (stopped, other) = client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let first = streams.send().open_bidi().expect("stopped stream");
        let other = streams.send().open_bidi().expect("unrelated stream");
        streams
            .receive()
            .stop(first.receive(), code)
            .expect("stop before peer sends bytes");
        streams
            .send()
            .send(other.send(), b"live")
            .expect("unrelated stream data");
        assert!(streams.view().is_send_open(first.send()));
        (first.id(), other.id())
    });
    server.with_scope(|mut scope| {
        let streams = scope.streams();
        let send = streams
            .view()
            .resolve_send(stopped)
            .expect("send direction");
        assert!(!streams.view().is_send_open(send), "unopened peer stream");
    });
    let sent = Instant::now() + Duration::from_secs(1);
    Receiver::receive_from(&mut server, &mut wire, &mut client, sent).expect("STOP delivery");
    server.with_scope(|mut scope| {
        let streams = scope.streams();
        let send = streams.view().resolve_send(stopped).expect("stopped half");
        assert_eq!(streams.view().stopped(send), Some(code));
        assert!(!streams.view().is_send_open(send));
        let other = streams.view().resolve_send(other).expect("unrelated half");
        assert!(streams.view().is_send_open(other), "lazy peer send half");
    });
    let reset = sent + Duration::from_millis(1);
    Receiver::receive_from(&mut client, &mut wire, &mut server, reset).expect("reset delivery");
    let ack = client
        .view()
        .recovery()
        .send_at(reset + Duration::from_millis(30));
    Receiver::receive_from(&mut server, &mut wire, &mut client, ack).expect("reset ACK");
    server.with_scope(|mut scope| {
        let streams = scope.streams();
        let send = streams.view().resolve_send(stopped).expect("retired half");
        assert_eq!(streams.view().stopped(send), None, "send entry retired");
        assert!(!streams.view().is_send_open(send), "retained closed half");
        let recv = streams.view().resolve_recv(stopped).expect("receive half");
        assert!(
            !streams.view().is_recv_eof(recv),
            "receive direction stays open"
        );
        let other = streams.view().resolve_send(other).expect("unrelated half");
        assert!(streams.view().is_send_open(other));
    });
}

#[test]
fn local_rebind_resets() {
    let mut client = Pair::try_default().expect("connected peers").into_parts().1;
    let (origin, local) = client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let handle = streams
            .send()
            .open_handle(Direction::Bidi)
            .expect("client must open a resident stream");
        (streams.resident().origin(), handle.local())
    });

    client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let resident = streams.resident();
        let owner = resident
            .owner(origin)
            .expect("resident origin must remain valid");
        let handle = resident
            .bind(owner, local)
            .expect("resident handle must rebind");
        let mut release = None;
        assert!(
            streams
                .try_reset(handle, Code::ZERO, &mut |event| { release = Some(event) })
                .is_ok(),
        );
        let release = release.expect("reset must retire the exact stream source");
        assert!(release.source.id() == local.id());
        assert!(release.cause == dope_quic::stream::release::Cause::Reset);
        assert!(release.charge.is_empty());
    });
}

#[test]
fn wrong_half_is_rejected() {
    let (mut server, mut client, _) = Pair::try_default().expect("connected peers").into_parts();
    let id = client.with_scope(|mut scope| {
        scope
            .streams()
            .send()
            .open_uni()
            .expect("client must open a unidirectional stream")
            .id()
    });

    client.with_scope(|mut scope| {
        let streams = scope.streams();
        assert!(matches!(
            streams.view().resolve_recv(id),
            Err(Error::InvalidDirection)
        ));
    });
    server.with_scope(|mut scope| {
        let streams = scope.streams();
        assert!(matches!(
            streams.view().resolve_send(id),
            Err(Error::InvalidDirection)
        ));
        assert_eq!(
            streams
                .view()
                .resolve_recv(id)
                .expect("server receive half must resolve")
                .get(),
            id.get(),
        );
    });
}
