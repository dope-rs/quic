use crate::common::peer;
pub mod common;
use common::suite::commit::Retain;
use common::suite::peers::config;
use std::time::{Duration, Instant};

use dope_quic::conn::stream::{Error, SendOutcome};
use dope_quic::errors::Code;
use dope_quic::stream::send::{self, admit};
use o3::buffer::{Residency as _, storage};
use peer::Event;
use peer::Pair;
use peer::Receiver as _;
use peer::Scope as _;

#[test]
fn commit_borrows_owner() {
    let mut pair = Pair::try_default().expect("test precondition");
    let client = &mut pair.client;
    let stream = (client.send_streams().open_bidi()).expect("client can open admission stream");
    let mut backing = vec![0x5a; 31];
    let retained = (storage::Shared::try_from(&mut backing))
        .expect("backing buffer supports shared ownership");
    let pointer = retained.as_slice().as_ptr();
    let prefix = (send::Buffer::inline(b"prefix")).expect("prefix fits inline send buffer");
    let parts = send::Parts::new(
        prefix,
        Some(send::Buffer::Retained(retained)),
        send::Boundary::End,
    );
    client.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let send_id = (streams.view().resolve_send(stream.id()))
            .expect("admission stream belongs to client connection");
        let outcome = streams.send().try_admit(send_id, parts, Retain);
        assert!(matches!(outcome,
            admit::Outcome::Retained((id, send::Boundary::End, owners))
                if id == stream.id() && owners == [pointer]
        ));
    });
}

#[test]
fn ids_bind_to_connection() {
    let Pair {
        server: mut server_a,
        client: mut client_a,
        work: mut work_a,
    } = Pair::try_default().expect("connected peer fixture");
    let Pair {
        server: mut server_b,
        client: mut client_b,
        work: mut work_b,
    } = Pair::try_default().expect("connected peer fixture");
    let stream_a = (client_a.send_streams().open_bidi()).expect("first client can open a stream");
    let stream_b = (client_b.send_streams().open_bidi()).expect("second client can open a stream");

    assert_eq!(stream_a.get(), stream_b.get());
    assert!(
        client_a.send_streams().send(stream_a, b"alpha").is_ok(),
        "queue first connection bytes"
    );
    assert!(
        client_b.send_streams().send(stream_a, b"bravo").is_ok(),
        "wire id resolves in second connection"
    );

    let now = Instant::now();
    assert!(
        server_a
            .receive_from(&mut work_a, &mut client_a, now)
            .is_ok()
    );
    assert!(
        server_b
            .receive_from(&mut work_b, &mut client_b, now)
            .is_ok()
    );
    let (recv_a,) = match server_a.poll().poll_event() {
        Some(Event::Readable { stream_id: recv_a }) => Some((recv_a,)),
        _ => None,
    }
    .expect("first server must receive its readable stream");
    let (recv_b,) = match server_b.poll().poll_event() {
        Some(Event::Readable { stream_id: recv_b }) => Some((recv_b,)),
        _ => None,
    }
    .expect("second server must receive its readable stream");

    assert_eq!(recv_a.get(), recv_b.get());
    assert!(recv_a == recv_b);
    let received = (server_b.recv().recv_owned(recv_a))
        .expect("second server resolves equal wire id in its own scope");
    assert_eq!(received.as_deref(), Some(&b"bravo"[..]));
}

#[test]
fn id_survives_drop() {
    let mut first = Pair::try_default().expect("test precondition");
    let stale =
        (first.client.send_streams().open_bidi()).expect("first connection can open a stream");
    drop(first);
    let mut pair = Pair::try_default().expect("test precondition");
    let client = &mut pair.client;
    let current =
        (client.send_streams().open_bidi()).expect("replacement connection can open a stream");

    assert_eq!(stale.get(), current.get());
    assert!(stale == current);
    assert!(
        client.send_streams().send(stale, b"current").is_ok(),
        "durable id resolves in replacement connection"
    );
}

#[test]
fn direction_precedes_brand() {
    let Pair {
        server, mut client, ..
    } = Pair::try_default().expect("connected peer fixture");
    let stream =
        (client.send_streams().open_uni()).expect("client can open a unidirectional stream");

    client.view().with_streams(|view| {
        assert!(matches!(
            view.resolve_recv(stream.id()),
            Err(Error::InvalidDirection)
        ));
    });
    server.view().with_streams(|view| {
        assert!(matches!(
            view.resolve_send(stream.id()),
            Err(Error::InvalidDirection)
        ));
        let received = view
            .resolve_recv(stream.id())
            .expect("server owns receive half");
        assert!(received.id() == stream.id());
    });
}

#[test]
fn atomic_parts_resume() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = config::try_budget(8, 64, 4).expect("stream budget fixture");
    let stream = (client.send_streams().open_bidi()).expect("client can open atomic-parts stream");

    assert!(
        matches!(
            client
                .send_streams()
                .try_buffer(stream, send::Buffer::Owned(vec![1; 4])),
            SendOutcome::Accepted
        ),
        "the four-byte owner must consume the available send budget"
    );
    let first = vec![2; 3];
    let second = vec![3; 2];
    let ptr_one = first.as_ptr();
    let ptr_two = second.as_ptr();
    let blocked = client.send_streams().try_parts(
        stream,
        send::Parts::new(
            send::Buffer::Owned(first),
            Some(send::Buffer::Owned(second)),
            send::Boundary::More,
        ),
    );
    let (parts,) = match blocked {
        SendOutcome::Blocked(parts) => Some((parts,)),
        _ => None,
    }
    .expect("five-byte atomic write must block behind four retained bytes");
    let (first, tail, boundary) = parts.into_tail();
    let (second,) = match tail {
        Some(send::Tail::Buffer(second)) => Some((second,)),
        _ => None,
    }
    .expect("blocked atomic parts must retain their buffer tail");
    assert_eq!(first.as_slice().as_ptr(), ptr_one);
    assert_eq!(second.as_slice().as_ptr(), ptr_two);
    let parts = send::Parts::new(first, Some(second), boundary);

    let sent_at = Instant::now() + Duration::from_secs(1);
    assert!(server.receive_from(&mut work, &mut client, sent_at).is_ok());
    let ack_at = server
        .view()
        .recovery()
        .send_at(sent_at + Duration::from_millis(1));
    assert!(client.receive_from(&mut work, &mut server, ack_at).is_ok());

    assert!(client.poll().poll_event() == Some(Event::Writable));
    assert!(client.poll().poll_event().is_none());
    assert!(matches!(
        client.send_streams().try_parts(stream, parts),
        SendOutcome::Accepted
    ));
    assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
}

#[test]
fn reset_wakes_retry() {
    let mut pair = config::try_budget(4, 64, 4).expect("stream budget fixture");
    let client = &mut pair.client;
    let old = (client.send_streams().open_bidi()).expect("client can open budget owner stream");
    let retry = (client.send_streams().open_bidi()).expect("client can open retry stream");

    assert!(
        matches!(
            client
                .send_streams()
                .try_buffer(old, send::Buffer::Owned(vec![1; 4])),
            SendOutcome::Accepted
        ),
        "the four-byte owner must consume the full send budget"
    );
    let owner = vec![2];
    let pointer = owner.as_ptr();
    let (owner,) = match client
        .send_streams()
        .try_buffer(retry, send::Buffer::Owned(owner))
    {
        SendOutcome::Blocked(send::Buffer::Owned(owner)) => Some((owner,)),
        _ => None,
    }
    .expect("one byte must remain atomically blocked");
    assert_eq!(owner.as_ptr(), pointer);
    assert_eq!(client.stream_state().wire_bytes(), 4);
    assert_eq!(client.stream_state().resident(), 4);
    assert_eq!(client.stream_state().segments(), 1);

    assert!(
        client
            .send_streams()
            .reset(old, Code::from_u8(0x51))
            .is_ok(),
        "reset budget owner stream"
    );
    assert_eq!(client.stream_state().wire_bytes(), 0);
    assert_eq!(client.stream_state().resident(), 0);
    assert_eq!(client.stream_state().segments(), 0);
    assert!(client.poll().poll_event() == Some(Event::Writable));
    assert!(client.poll().poll_event().is_none());
    assert!(matches!(
        client
            .send_streams()
            .try_buffer(retry, send::Buffer::Owned(owner)),
        SendOutcome::Accepted
    ));
}

#[test]
fn writable_coalesces() {
    let mut pair = config::try_budget(10, 6, 8).expect("stream budget fixture");
    let client = &mut pair.client;
    let wire = (client.send_streams().open_bidi()).expect("client can open wire owner stream");
    let held = (client.send_streams().open_bidi()).expect("client can open resident owner stream");
    let res_try =
        (client.send_streams().open_bidi()).expect("client can open resident retry stream");
    let wire_try = (client.send_streams().open_bidi()).expect("client can open wire retry stream");

    let owner = (send::Buffer::inline(&[0x11; 2])).expect("wire owner fits inline buffer");
    assert!(
        matches!(
            client.send_streams().try_buffer(wire, owner),
            SendOutcome::Accepted
        ),
        "the inline wire owner must fit both send budgets"
    );
    assert!(
        matches!(
            client
                .send_streams()
                .try_buffer(held, send::Buffer::Owned(vec![0x22; 6])),
            SendOutcome::Accepted
        ),
        "the resident owner must consume the resident send budget"
    );

    let mut backing = vec![0x33; 6];
    let pointer = backing.as_ptr();
    let retained = (storage::Shared::try_from(&mut backing))
        .expect("backing buffer supports shared ownership");
    let retained = retained
        .project(0..2)
        .expect("retained slice stays within backing owner");
    let (retained,) = match client
        .send_streams()
        .try_buffer(res_try, send::Buffer::Retained(retained))
    {
        SendOutcome::Blocked(send::Buffer::Retained(retained)) => Some((retained,)),
        _ => None,
    }
    .expect("resident-bound owner must block");
    let inline = (send::Buffer::inline(&[0x44; 8])).expect("wire retry fits inline buffer");
    let (inline,) = match client.send_streams().try_buffer(wire_try, inline) {
        SendOutcome::Blocked(inline) => Some((inline,)),
        _ => None,
    }
    .expect("wire-bound owner must block");
    assert_eq!(retained.as_slice().as_ptr(), pointer);
    assert!(client.poll().poll_event().is_none());
    assert!(
        client
            .send_streams()
            .reset(wire, Code::from_u8(0x61))
            .is_ok(),
        "reset wire owner stream"
    );
    assert!(client.poll().poll_event() == Some(Event::Writable));
    assert!(client.poll().poll_event().is_none());

    let (retained,) = match client
        .send_streams()
        .try_buffer(res_try, send::Buffer::Retained(retained))
    {
        SendOutcome::Blocked(send::Buffer::Retained(retained)) => Some((retained,)),
        _ => None,
    }
    .expect("resident retry must rearm while blocked");
    let (inline,) = match client.send_streams().try_buffer(wire_try, inline) {
        SendOutcome::Blocked(inline) => Some((inline,)),
        _ => None,
    }
    .expect("wire retry must remain blocked");
    assert_eq!(retained.as_slice().as_ptr(), pointer);
    assert!(client.poll().poll_event().is_none());

    assert!(
        client
            .send_streams()
            .reset(held, Code::from_u8(0x62))
            .is_ok(),
        "reset resident owner stream"
    );
    assert!(client.poll().poll_event() == Some(Event::Writable));
    assert!(client.poll().poll_event().is_none());
    assert!(matches!(
        client
            .send_streams()
            .try_buffer(res_try, send::Buffer::Retained(retained)),
        SendOutcome::Accepted
    ));
    assert!(matches!(
        client.send_streams().try_buffer(wire_try, inline),
        SendOutcome::Accepted
    ));
}

#[test]
fn limit_returns_owner() {
    let mut pair = config::try_budget(16, 8, 4).expect("stream budget fixture");
    let client = &mut pair.client;
    let stream =
        (client.send_streams().open_bidi()).expect("client can open resident-limit stream");
    let mut backing = vec![0x5a; 64];
    let pointer = backing.as_ptr();
    let retained = (storage::Shared::try_from(&mut backing))
        .expect("backing buffer supports shared ownership");
    let retained = retained
        .project(0..1)
        .expect("retained slice stays within backing owner");

    let (owner,) = match client
        .send_streams()
        .try_buffer(stream, send::Buffer::Retained(retained))
    {
        SendOutcome::Failed {
            owner: send::Buffer::Retained(owner),
            error: Error::ValueOutOfRange,
        } => Some((owner,)),
        _ => None,
    }
    .expect("resident oversize must return the exact owner");
    assert_eq!(owner.as_slice().as_ptr(), pointer);
    assert_eq!(owner.len(), 1);
    assert_eq!(owner.resident(), 64);
    assert_eq!(client.stream_state().wire_bytes(), 0);
    assert_eq!(client.stream_state().resident(), 0);
    assert_eq!(client.stream_state().segments(), 0);
    assert!(
        client
            .send_streams()
            .reset(stream, Code::from_u8(0x63))
            .is_ok(),
        "reset resident-limit stream"
    );
    assert!(client.poll().poll_event().is_none());
}
