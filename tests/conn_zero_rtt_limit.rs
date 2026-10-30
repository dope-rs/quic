use std::time::Instant;

use dope_quic::conn::wire::packet::Batch;
use dope_quic::runtime::routing;
use dope_quic::wire::packet::cid;

pub mod common;
use common::peer::Pair;
use common::suite::peers;
use common::suite::peers::{Authority, Error};

#[test]
fn cached_credit() {
    let result = Authority::params();
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("fixture transport parameters must fit");
    let params = result.ok().expect("admitted parameters");
    let params = (params
        .to_builder()
        .remote_bidi(4)
        .initial_data(4)
        .try_build())
    .expect("four-byte early credit must fit");
    let result = Authority::options(params).and_then(Authority::try_new);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("limited ticket authority must construct");
    let auth = result.ok().expect("admitted authority");
    let result = auth.first(&peers::CID);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("initial handshake must warm the native session cache");
    let result = auth.resumed([0xC1; 8], [0xC2; 8]);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("limited reconnect must construct peers");
    let Pair {
        mut server,
        mut client,
        mut work,
    } = result.ok().expect("admitted peer sessions");
    client.with_scope(|mut client| {
        server.with_scope(|mut server| {
            let stream = (client.streams().send().open_bidi())
                .expect("cached peer credit must admit the stream");
            let peer = (server.streams().view().resolve_recv(stream.id()))
                .expect("server must accept the incoming stream direction");
            assert!(
                client
                    .streams()
                    .send()
                    .send(stream.send(), b"abcdefghij")
                    .is_ok()
            );
            let now = Instant::now();
            let (packets, send_result) = client.output().send(now);
            send_result.expect("configured journals must admit bounded early output");
            for mut packet in packets {
                assert!(
                    server
                        .input(&mut work)
                        .recv_packet(&mut packet, now, |_| {})
                        .is_ok()
                );
            }
            let mut got = Vec::new();
            assert_eq!(server.streams().receive().recv(peer, &mut got), Ok(4));
            assert_eq!(
                got, b"abcd",
                "cached limits must cap early emission at four bytes"
            );
        })
    });
}

#[test]
fn packet_ceiling() {
    let result = Authority::params()
        .and_then(Authority::options)
        .and_then(Authority::try_new);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("ticket authority must construct");
    let auth = result.ok().expect("admitted authority");
    let result = auth.first(&peers::CID);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("initial handshake must warm the native session cache");
    let initial = cid::Id::try_from([0x65; routing::ENTROPY_LEN]).expect("initial ID");
    let local = (cid::Id::try_from(peers::CID)).expect("client ID must fit");
    let result = auth.resume(initial, local, routing::Plain);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("native session cache must construct the resumed client");
    let mut client = result.ok().expect("admitted client connection");
    client.with_scope(|mut client| {
        let stream = (client.streams().send().open_bidi())
            .expect("cached peer credit must admit the stream");
        let payload = vec![0x33; 64 * 1024];
        assert!(
            client
                .streams()
                .send()
                .send(stream.send(), &payload)
                .is_ok()
        );
        let mut packets = Batch::default();
        assert!(
            client
                .output()
                .send_batch(&mut packets, Instant::now(), 64, 1_200)
                .is_ok()
        );
        let early = packets
            .iter()
            .filter(|packet| packet.first().is_some_and(|byte| byte & 0xF0 == 0xD0))
            .count();
        assert!(early > 1, "the 64-KiB payload must span early-data packets");
        assert!(
            packets.iter().all(|packet| packet.len() <= 1_200),
            "every emitted early-data packet must respect the requested byte ceiling"
        );
    });
}

#[test]
fn rejected_ticket_credit() {
    use common::peer::{Config, Receiver as _};

    let result = Authority::try_new(
        Config::new(1000, 1000, 8, 8)
            .try_build()
            .expect("issuing transport limits"),
    );
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("issuing authority");
    let issuing = result.ok().expect("admitted authority");
    for (conn_max, strm_max, early) in [
        (4, 1000, false),
        (1000, 4, false),
        (4, 1000, true),
        (1000, 4, true),
    ] {
        let result = issuing.first(&peers::CID);
        result
            .as_ref()
            .map_err(Error::cause)
            .expect("issued ticket");
        let result = Authority::try_new(
            Config::new(strm_max, conn_max, 8, 8)
                .try_build()
                .expect("reduced transport limits"),
        );
        result
            .as_ref()
            .map_err(Error::cause)
            .expect("independent authority");
        let target = result.ok().expect("admitted authority");
        let result = issuing.pair_to(&target.server, [0xC3; 8], [0xC4; 8]);
        result
            .as_ref()
            .map_err(Error::cause)
            .expect("offered resumption");
        let Pair {
            mut server,
            mut client,
            mut work,
        } = result.ok().expect("admitted peer sessions");
        let stream = client.with_scope(|mut scope| {
            scope
                .streams()
                .send()
                .open_bidi()
                .expect("cached stream credit")
                .id()
        });
        let mut now = Instant::now();
        if early {
            client.with_scope(|mut scope| {
                let stream = scope
                    .streams()
                    .view()
                    .resolve_bidi(stream)
                    .expect("opened stream");
                scope
                    .streams()
                    .send()
                    .send(stream.send(), b"abcdefghij")
                    .expect("early queue");
            });
            let (packets, send_result) = client.with_scope(|mut scope| scope.output().send(now));
            send_result.expect("early flight");
            assert!(
                packets
                    .iter()
                    .any(|packet| { packet.first().is_some_and(|byte| byte & 0xF0 == 0xD0) })
            );
            for mut packet in packets {
                server
                    .receive(&mut work, &mut packet, now)
                    .expect("offered early flight");
            }
        }
        for _ in 0..6 {
            server
                .receive_from(&mut work, &mut client, now)
                .expect("client flight");
            client
                .receive_from(&mut work, &mut server, now)
                .expect("server flight");
        }
        assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
        if !early {
            client.with_scope(|mut scope| {
                let stream = scope
                    .streams()
                    .view()
                    .resolve_bidi(stream)
                    .expect("opened stream");
                scope
                    .streams()
                    .send()
                    .send(stream.send(), b"abcdefghij")
                    .expect("queued data");
            });
        }
        now = client.view().recovery().send_at(now);
        server
            .receive_from(&mut work, &mut client, now)
            .expect("application flight");
        for expected in [b"abcd".as_slice(), b"efgh".as_slice(), b"ij".as_slice()] {
            let mut got = Vec::new();
            server.with_scope(|mut scope| {
                let stream = scope
                    .streams()
                    .view()
                    .resolve_recv(stream)
                    .expect("incoming stream");
                assert_eq!(
                    scope.streams().receive().recv(stream, &mut got),
                    Ok(expected.len()),
                    "connection_limit={conn_max}, strm_max={strm_max}, early={early}, expected={expected:?}"
                );
            });
            assert_eq!(
                got, expected,
                "fresh credit bounds ordered application delivery"
            );
            now = server.view().recovery().send_at(now);
            client
                .receive_from(&mut work, &mut server, now)
                .expect("updated peer credit");
            now = client.view().recovery().send_at(now);
            server
                .receive_from(&mut work, &mut client, now)
                .expect("next application flight");
        }
    }
}

#[test]
fn rejected_stream_count() {
    use common::peer::{Bind, Config, Receiver as _, Scope as _};

    let result = Authority::try_new(
        Config::new(1000, 1000, 0, 2)
            .try_build()
            .expect("two-stream ticket limits"),
    );
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("issuing authority");
    let issuing = result.ok().expect("admitted authority");
    let result = issuing.first(&peers::CID);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("issued ticket");
    let result = Authority::try_new(
        Config::new(1000, 1000, 0, 1)
            .try_build()
            .expect("one-stream authenticated limit"),
    );
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("independent authority");
    let target = result.ok().expect("admitted authority");
    let result = issuing.pair_to(&target.server, [0xC5; 8], [0xC6; 8]);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("offered resumption");
    let Pair {
        mut server,
        mut client,
        mut work,
    } = result.ok().expect("admitted peer sessions");
    let first = client
        .send_streams()
        .open_uni()
        .expect("first cached stream");
    let excess = client
        .send_streams()
        .open_uni()
        .expect("second cached stream");
    for bytes in [b"early-".as_slice(), b"retained".as_slice()] {
        client
            .send_streams()
            .send(excess, bytes)
            .expect("retained early bytes");
    }
    client
        .send_streams()
        .finish(excess)
        .expect("retained early FIN");
    let mut now = Instant::now();
    let (packets, send_result) = client.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("early flight");
    assert!(
        packets
            .iter()
            .any(|packet| { packet.first().is_some_and(|byte| byte & 0xF0 == 0xD0) })
    );
    for mut packet in packets {
        server
            .receive(&mut work, &mut packet, now)
            .expect("offered early flight");
    }
    for _ in 0..6 {
        client
            .receive_from(&mut work, &mut server, now)
            .expect("server flight");
        server
            .receive_from(&mut work, &mut client, now)
            .expect("bounded client flight");
    }
    assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
    now = client.view().recovery().send_at(now);
    server
        .receive_from(&mut work, &mut client, now)
        .expect("blocked stream flight at pacing release");
    let incoming = excess.bind(&server).expect("incoming stream direction");
    assert!(
        server
            .recv()
            .recv_owned(incoming)
            .expect("blocked stream receive")
            .is_none()
    );
    assert_eq!(
        client.with_scope(|mut scope| {
            let streams = scope.streams();
            let stream = streams
                .view()
                .resolve_send(excess.id())
                .expect("retained stream");
            streams.view().buffered(stream)
        }),
        14
    );

    client
        .send_streams()
        .send(first, b"release")
        .expect("first permitted stream");
    client
        .send_streams()
        .finish(first)
        .expect("first permitted FIN");
    now = client.view().recovery().send_at(now);
    server
        .receive_from(&mut work, &mut client, now)
        .expect("permitted stream flight");
    let first = first.bind(&server).expect("first incoming stream");
    assert_eq!(
        server
            .recv()
            .recv_owned(first)
            .expect("consume first stream")
            .as_deref(),
        Some(b"release".as_slice())
    );
    now = server.view().recovery().send_at(now);
    client
        .receive_from(&mut work, &mut server, now)
        .expect("increased MAX_STREAMS");
    now = client.view().recovery().send_at(now);
    server
        .receive_from(&mut work, &mut client, now)
        .expect("newly permitted stream flight");
    assert_eq!(
        server
            .recv()
            .recv_owned(incoming)
            .expect("retained ordered bytes")
            .as_deref(),
        Some(b"early-retained".as_slice())
    );
    assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
}
