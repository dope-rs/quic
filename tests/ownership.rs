use crate::common::peer;
pub mod common;
use common::suite::{commit::Retain, owners::Capture};
use std::time::{Duration, Instant};

use dope_quic::conn::stream::SendOutcome;
use dope_quic::errors::Code;
use dope_quic::stream::{
    release,
    send::{self, admit},
};
use o3::buffer::{self, segments, storage};
use peer::Bind as _;
use peer::Event;
use peer::Pair;
use peer::Receiver as _;
use peer::Scope as _;

#[test]
fn data_and_fin_cross() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_default().expect("default connection pair must initialize");
    let sent_cli = client
        .send_streams()
        .open_bidi()
        .expect("client can open a bidirectional stream");
    let sent_srv = server
        .send_streams()
        .open_bidi()
        .expect("server can open a bidirectional stream");
    let recv_cli = sent_cli
        .bind(&server)
        .expect("client stream must resolve on server");
    let recv_srv = sent_srv
        .bind(&client)
        .expect("server stream must resolve on client");
    client
        .send_streams()
        .send(sent_cli, b"client")
        .expect("queue client stream bytes");
    client
        .send_streams()
        .finish(sent_cli)
        .expect("finish client stream");
    server
        .send_streams()
        .send(sent_srv, b"server")
        .expect("queue server stream bytes");
    server
        .send_streams()
        .finish(sent_srv)
        .expect("finish server stream");
    let now = Instant::now();
    let received = server.receive_from(&mut work, &mut client, now);
    assert!(received.is_ok(), "client flight must reach server");
    let received = client.receive_from(&mut work, &mut server, now);
    assert!(received.is_ok(), "server flight must reach client");

    assert!(
        server.poll().poll_event()
            == Some(Event::Readable {
                stream_id: recv_cli.receive()
            })
    );
    assert!(server.poll().poll_event().is_none());
    let mut got_cli = Vec::new();
    let mut got_srv = Vec::new();
    server
        .recv()
        .recv(recv_cli, &mut got_cli)
        .expect("read client stream bytes");
    client
        .recv()
        .recv(recv_srv, &mut got_srv)
        .expect("read server stream bytes");
    assert_eq!(got_cli, b"client");
    assert_eq!(got_srv, b"server");
    assert!(
        server
            .stream_state()
            .recv_eof(recv_cli)
            .expect("client FIN is visible")
    );
    assert!(
        client
            .stream_state()
            .recv_eof(recv_srv)
            .expect("server FIN is visible")
    );
}

#[test]
fn ack_releases_owner_once() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_default().expect("default connection pair must initialize");
    let stream = client
        .send_streams()
        .open_uni()
        .expect("client can open a unidirectional stream");
    let owner = vec![0x5a; 257];
    let resident = owner.capacity();
    assert!(
        matches!(
            client
                .send_streams()
                .try_buffer(stream, send::Buffer::Owned(owner)),
            SendOutcome::Accepted
        ),
        "the owned stream buffer must fit the default send limits"
    );

    let sent_at = Instant::now() + Duration::from_secs(1);
    let received = server.receive_from(&mut work, &mut client, sent_at);
    assert!(received.is_ok(), "client flight must reach server");
    let ack_at = server
        .view()
        .recovery()
        .send_at(sent_at + Duration::from_millis(1));
    let (packets, result) = server.with_scope(|mut scope| scope.output().send(ack_at));
    result.expect("configured server journals must admit the crossing ACK");
    let copies = packets.clone();
    let mut releases = Vec::new();
    for mut packet in packets.into_iter().chain(copies) {
        let mut failure = None;
        assert!(
            client
                .with_scope(|mut scope| {
                    scope.input(&mut work).recv_with(
                        &mut packet,
                        ack_at,
                        &mut Capture(&mut releases, &mut failure),
                    )
                })
                .is_ok(),
            "client accepts acknowledgement packet: {failure:?}"
        );
    }

    assert_eq!(releases.len(), 1, "duplicate ACKs cannot release twice");
    let release = releases[0];
    assert!(release.source.id() == stream.id());
    assert_eq!(release.charge.logical_bytes, 257);
    assert_eq!(release.charge.resident_bytes, resident);
    assert_eq!(release.charge.owners, 1);
    assert!(matches!(release.cause, release::Cause::Acked));
}

#[test]
fn ack_maps_owned_part() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_default().expect("default connection pair must initialize");
    let stream = client
        .send_streams()
        .open_uni()
        .expect("client can open a unidirectional stream");
    let owner = vec![0x6b; 257];
    let resident = owner.capacity();
    let parts = send::Parts::new(
        send::Buffer::inline(b"h3-inline-prefix").expect("inline prefix fits send buffer"),
        Some(send::Buffer::Owned(owner)),
        send::Boundary::More,
    );
    assert!(matches!(
        client.send_streams().try_parts(stream, parts),
        SendOutcome::Accepted
    ));

    let sent_at = Instant::now() + Duration::from_secs(1);
    let received = server.receive_from(&mut work, &mut client, sent_at);
    assert!(received.is_ok(), "client flight must reach server");
    let ack_at = server
        .view()
        .recovery()
        .send_at(sent_at + Duration::from_millis(1));
    let (packets, result) = server.with_scope(|mut scope| scope.output().send(ack_at));
    result.expect("configured server journals must admit the split-ack output");
    let mut releases = Vec::new();
    for mut packet in packets {
        let mut failure = None;
        assert!(
            client
                .with_scope(|mut scope| {
                    scope.input(&mut work).recv_with(
                        &mut packet,
                        ack_at,
                        &mut Capture(&mut releases, &mut failure),
                    )
                })
                .is_ok(),
            "client accepts acknowledgement packet: {failure:?}"
        );
    }

    assert_eq!(releases.len(), 1);
    let release = releases[0];
    assert!(release.source.id() == stream.id());
    assert_eq!(release.charge.logical_bytes, 257);
    assert_eq!(release.charge.resident_bytes, resident);
    assert_eq!(release.charge.owners, 1);
    assert!(matches!(release.cause, release::Cause::Acked));
}

#[test]
fn ack_folds_owners() {
    use crate::common::suite::peers::config;
    use dope_quic::conn::{output::transmit, wire::packet::Batch};

    let Pair {
        mut server,
        mut client,
        mut work,
    } = config::try_packet().expect("1200-byte packet peers");
    let stream = client
        .send_streams()
        .open_uni()
        .expect("client can open a unidirectional stream");

    let mut buf_one = Vec::with_capacity(2400);
    buf_one.extend_from_slice(&[0x31; 2400]);
    let first = (storage::Shared::try_from(&mut buf_one))
        .expect("first test buffer must preserve its owner");
    let mut buf_two = Vec::with_capacity(96);
    buf_two.extend_from_slice(&[0x32; 23]);
    let second = (storage::Shared::try_from(&mut buf_two))
        .expect("second test buffer must preserve its owner");
    let resident = buffer::Residency::resident(&first) + buffer::Residency::resident(&second);
    let pool = segments::Pool::try_new(segments::Plan {
        segments: 2,
        chains: 1,
    })
    .expect("segment pool plan is valid");
    let mut chain = pool.into_chain();
    assert!(
        chain.try_push(first).is_ok(),
        "segment pool admits first owner"
    );
    assert!(
        chain.try_push(second).is_ok(),
        "segment pool admits second owner"
    );
    let chain = match chain.into_shape() {
        segments::Shape::Many(chain) => Some(chain),
        _ => None,
    }
    .expect("two retained owners");
    let parts = send::Parts::from_chain(
        send::Buffer::inline(b"inline-prefix").expect("inline prefix fits send buffer"),
        chain,
        send::Boundary::End,
    );
    assert!(matches!(
        client.send_streams().try_parts(stream, parts),
        SendOutcome::Accepted
    ));

    let mut now = Instant::now() + Duration::from_secs(1);
    let mut batch = Batch::default();
    let mut releases = Vec::new();
    for partial in [true, true, false] {
        let before = client.stream_state().wire_bytes();
        now = client.view().recovery().send_at(now);
        let effects = client
            .with_scope(|mut scope| scope.output().send_effects(&mut batch, now, 1, 1200))
            .expect("one stream packet fits the journal");
        assert!(effects.contains(transmit::Effects::FRESH_STREAM));
        server
            .receive_all(&mut work, &mut batch, now)
            .expect("client flight must reach server");
        let ack_at = server
            .view()
            .recovery()
            .send_at(now + Duration::from_millis(30));
        let (packets, result) = server.with_scope(|mut scope| scope.output().send(ack_at));
        result.expect("configured server journals must admit the release ACK");
        for mut packet in packets {
            let mut failure = None;
            assert!(
                client
                    .with_scope(|mut scope| {
                        scope.input(&mut work).recv_with(
                            &mut packet,
                            ack_at,
                            &mut Capture(&mut releases, &mut failure),
                        )
                    })
                    .is_ok(),
                "client accepts acknowledgement packet: {failure:?}"
            );
        }
        if partial {
            assert_eq!(releases.len(), 1);
            let release = releases.pop().expect("partial ACK emits release evidence");
            assert!(release.source.id() == stream.id());
            assert!(matches!(release.cause, release::Cause::Acked));
            assert_eq!(
                (
                    release.charge.logical_bytes,
                    release.charge.resident_bytes,
                    release.charge.owners,
                ),
                (0, 0, 0),
            );
            let left = client.stream_state().wire_bytes();
            assert!(left < before, "each ACK advances the same owner");
            assert!(left < 2400 + 23, "ACK reaches the first owner");
            assert_eq!(client.stream_state().active_bytes(), resident);
        }
        now = ack_at;
    }

    assert_eq!(releases.len(), 1);
    let release = releases[0];
    assert!(release.source.id() == stream.id());
    assert_eq!(release.charge.logical_bytes, 2400 + 23);
    assert_eq!(release.charge.resident_bytes, resident);
    assert_eq!(release.charge.owners, 2);
    assert!(matches!(release.cause, release::Cause::Acked));
    let mut received = Vec::new();
    server
        .recv()
        .recv(stream.id(), &mut received)
        .expect("receive the acknowledged stream");
    assert_eq!(received.len(), b"inline-prefix".len() + 2400 + 23);
    assert_eq!(server.stream_state().recv_eof(stream.id()), Ok(true));
}

#[test]
fn inline_reset_no_owner() {
    let Pair { mut client, .. } =
        Pair::try_default().expect("default connection pair must initialize");
    let inline = client
        .send_streams()
        .open_uni()
        .expect("client can open inline stream");
    assert!(
        matches!(
            client.send_streams().try_buffer(
                inline,
                send::Buffer::inline(b"inline-only").expect("inline payload fits send buffer"),
            ),
            SendOutcome::Accepted
        ),
        "the inline stream buffer must fit the default send limits"
    );
    let mut releases = Vec::new();
    {
        client
            .with_scope(|mut scope| {
                let mut streams = scope.streams();
                let send_id = streams.view().resolve_send(inline.id())?;
                streams
                    .send()
                    .reset_with(send_id, Code::from_u8(0x11), &mut |release| {
                        releases.push(release)
                    })
            })
            .expect("reset active static stream");
    }
    assert_eq!(releases.len(), 1);
    let released = releases.first().expect("reset emits its terminal event");
    assert!(released.source.id() == inline.id());
    assert!(matches!(released.cause, release::Cause::Reset));
    assert_eq!(
        (
            released.charge.logical_bytes,
            released.charge.resident_bytes,
            released.charge.owners,
        ),
        (0, 0, 0),
    );
}

#[test]
fn reset_releases_once() {
    let Pair { mut client, .. } =
        Pair::try_default().expect("default connection pair must initialize");
    let stream = client
        .send_streams()
        .open_uni()
        .expect("client can open owned stream");
    let owner = vec![0xa5; 257];
    let resident = owner.capacity();
    assert!(
        matches!(
            client
                .send_streams()
                .try_buffer(stream, send::Buffer::Owned(owner)),
            SendOutcome::Accepted
        ),
        "the owned reset buffer must fit the default send limits"
    );

    let mut releases = Vec::new();
    for _ in 0..2 {
        client
            .with_scope(|mut scope| {
                let mut streams = scope.streams();
                let send_id = streams.view().resolve_send(stream.id())?;
                streams
                    .send()
                    .reset_with(send_id, Code::from_u8(0x10), &mut |release| {
                        releases.push(release)
                    })
            })
            .expect("reset active owned stream");
    }

    assert_eq!(releases.len(), 1, "repeated RESET cannot release twice");
    let release = releases[0];
    assert!(release.source.id() == stream.id());
    assert_eq!(release.charge.logical_bytes, 257);
    assert_eq!(release.charge.resident_bytes, resident);
    assert_eq!(release.charge.owners, 1);
    assert!(matches!(release.cause, release::Cause::Reset));
}

#[test]
fn late_write_is_retired() {
    let Pair {
        mut server,
        mut client,
        mut work,
    } = Pair::try_default().expect("default connection pair must initialize");
    let stream = client
        .send_streams()
        .open_bidi()
        .expect("client can open request stream");
    client
        .send_streams()
        .send(stream, b"request")
        .expect("queue request bytes");
    client
        .send_streams()
        .finish(stream)
        .expect("finish request stream");

    let request = Instant::now() + Duration::from_secs(1);
    let received = server.receive_from(&mut work, &mut client, request);
    assert!(received.is_ok(), "request must reach server");
    let peer = stream.bind(&server);
    let peer = (peer).expect("paired stream must resolve");
    server
        .send_streams()
        .send(peer, b"response")
        .expect("queue response bytes");
    server
        .send_streams()
        .finish(peer)
        .expect("finish response stream");

    let response = request + Duration::from_secs(1);
    let received = client.receive_from(&mut work, &mut server, response);
    assert!(received.is_ok(), "response must reach client");
    let ack_at = client
        .view()
        .recovery()
        .send_at(response + Duration::from_millis(1));
    let received = server.receive_from(&mut work, &mut client, ack_at);
    assert!(received.is_ok(), "acknowledgement must reach server");

    let late = send::Parts::new(
        send::Buffer::Owned(vec![0x7e; 33]),
        None,
        send::Boundary::More,
    );
    let outcome = server.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let send_id = streams
            .view()
            .resolve_send(peer.id())
            .expect("peer send stream remains addressable after retirement");
        streams.send().try_admit(send_id, late, Retain)
    });
    assert!(matches!(outcome, admit::Outcome::Discarded(discard)
            if discard.source().id() == peer.id()
                && discard.cause() == admit::Cause::PeerRetired));
    assert_eq!(server.stream_state().wire_bytes(), 0);
    assert_eq!(server.stream_state().resident(), 0);
}
