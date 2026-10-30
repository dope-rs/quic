pub mod common;
use common::peer::{Bind, Event, Pair, Receiver, Scope as _};
use common::suite::peers::receive::{MIXED_STREAM, REVERSE_STREAM, try_options, try_queue};
use dope_quic::conn::{self, wire::packet::Batch};
use std::time::{Duration, Instant};

fn transfer(
    from: &mut conn::Connection,
    into: &mut impl Receiver,
    work: &mut conn::Workspace,
    at: Instant,
) {
    let mut batch = Batch::default();
    from.with_scope(|mut scope| scope.output().send_batch(&mut batch, at, 1, 1_200))
        .expect("warmed journals must admit the mixed stream packet");
    assert_eq!(batch.packets(), 1);
    into.receive_all(work, &mut batch, at)
        .expect("receive mixed stream packet");
}

#[test]
fn mixed_stream_reset() {
    let (mut server, mut client, mut work) = Pair::try_new(
        try_options(4).expect("four server event slots"),
        try_options(4).expect("four client event slots"),
    )
    .expect("connected peers")
    .into_parts();
    let (data, reset) = try_queue(&mut client).expect("queue mixed stream and reset");

    let at = Instant::now() + Duration::from_secs(1);
    transfer(&mut client, &mut server, &mut work, at);

    let events = [server.poll().poll_event(), server.poll().poll_event()];
    let data_at = Bind::bind(data, &server).expect("peer stream");
    let reset_at = Bind::bind(reset, &server).expect("peer stream");
    assert!(events.contains(&Some(Event::Readable { stream_id: data_at })));
    assert!(events.contains(&Some(Event::Reset {
        stream_id: reset_at,
        error_code: dope_quic::errors::Code::from_u8(0x51),
    })));
    assert!(server.poll().poll_event().is_none());
    let data = server
        .recv()
        .recv_owned(data_at)
        .expect("readable stream retains its receive owner");
    assert_eq!(data.as_deref(), Some(MIXED_STREAM));
}

#[test]
fn mixed_stop_stream() {
    let (mut server, mut client, mut work) = Pair::try_new(
        try_options(4).expect("four server event slots"),
        try_options(4).expect("four client event slots"),
    )
    .expect("connected peers")
    .into_parts();
    let stopped = client
        .send_streams()
        .open_uni()
        .expect("test options reserve the stopped stream");
    assert!(
        client
            .send_streams()
            .send(stopped, b"open stop target")
            .is_ok()
    );
    let warm_at = Instant::now() + Duration::from_secs(1);
    Receiver::receive_from(&mut server, &mut work, &mut client, warm_at)
        .expect("peer packet transfer");
    let peer = Bind::bind(stopped, &server).expect("peer stream");
    assert!(server.poll().poll_event() == Some(Event::Readable { stream_id: peer }));
    assert!(
        server
            .recv()
            .stop(peer, dope_quic::errors::Code::from_u8(0x61))
            .is_ok()
    );

    let data = server
        .send_streams()
        .open_uni()
        .expect("test options reserve the reverse stream");
    assert!(server.send_streams().send(data, REVERSE_STREAM).is_ok());
    assert!(server.send_streams().finish(data).is_ok());

    let at = warm_at + Duration::from_secs(1);
    transfer(&mut server, &mut client, &mut work, at);

    let events = [client.poll().poll_event(), client.poll().poll_event()];
    let data_at = Bind::bind(data, &client).expect("peer stream");
    assert!(events.contains(&Some(Event::Stopped {
        stream_id: stopped,
        error_code: dope_quic::errors::Code::from_u8(0x61),
    })));
    assert!(events.contains(&Some(Event::Readable { stream_id: data_at })));
    assert!(client.poll().poll_event().is_none());
    assert!(
        client.stream_state().stopped(stopped) == Ok(Some(dope_quic::errors::Code::from_u8(0x61)))
    );
    let data = client
        .recv()
        .recv_owned(data_at)
        .expect("readable reverse stream retains its receive owner");
    assert_eq!(data.as_deref(), Some(REVERSE_STREAM));
}

#[test]
fn event_pressure() {
    let (mut server, mut client, mut work) = Pair::try_new(
        try_options(1).expect("one server event slot"),
        try_options(4).expect("four client event slots"),
    )
    .expect("connected peers")
    .into_parts();
    let (data, reset) = try_queue(&mut client).expect("queue mixed stream and reset");

    let at = Instant::now() + Duration::from_secs(1);
    transfer(&mut client, &mut server, &mut work, at);

    assert!(server.poll().poll_event().is_none());
    let (data_ok, reset_ok) = server.with_scope(|mut scope| {
        let streams = scope.streams();
        let slots = streams.resident();
        (
            slots.handle(data.id()).is_some(),
            slots.handle(reset.id()).is_some(),
        )
    });
    assert!(!data_ok);
    assert!(!reset_ok);
}
