use o3::buffer::storage;
use std::time::Instant;

use dope_quic::conn;
use dope_quic::conn::life::accept;
use dope_quic::runtime::routing;
use dope_quic::wire::packet::cid;

pub mod common;
use common::peer::Pair;
use common::suite::peers;
use common::suite::peers::{Authority, Error};

#[test]
fn round_trip() {
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
    let result = auth.resumed([0x91; 8], [0x92; 8]);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("native cache must resume peer sessions");
    let Pair {
        mut server,
        mut client,
        mut work,
    } = result.ok().expect("admitted peer sessions");
    client.with_scope(|mut client| {
        server.with_scope(|mut server| {
            let now = Instant::now();
            let stream = (client.streams().send().open_bidi())
                .expect("the resumed client must retain bidirectional stream credit");
            let peer = server.streams().view().resolve_bidi(stream.id());
            let peer = (peer).expect("test precondition");
            assert!(
                client
                    .streams()
                    .send()
                    .send(stream.send(), b"early")
                    .is_ok(),
                "five early bytes must fit the cached peer credit"
            );
            let (packets, send_result) = client.output().send(now);
            send_result.expect("fixture flight must fit");
            for mut packet in packets {
                assert!(
                    server
                        .input(&mut work)
                        .recv_packet(&mut packet, now, |_| {})
                        .is_ok()
                );
            }

            let mut early = Vec::new();
            assert_eq!(
                server.streams().receive().recv(peer.receive(), &mut early),
                Ok(5),
                "the server must expose all early bytes before handshake completion"
            );
            assert_eq!(early, b"early");

            for _ in 0..3 {
                let (packets, send_result) = server.output().send(now);
                send_result.expect("fixture flight must fit");
                for mut packet in packets {
                    assert!(
                        client
                            .input(&mut work)
                            .recv_packet(&mut packet, now, |_| {})
                            .is_ok()
                    );
                }
                let (packets, send_result) = client.output().send(now);
                send_result.expect("fixture flight must fit");
                for mut packet in packets {
                    assert!(
                        server
                            .input(&mut work)
                            .recv_packet(&mut packet, now, |_| {})
                            .is_ok()
                    );
                }
            }
            assert!(
                client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready(),
                "three post-early bidirectional flights must finish the resumed handshake"
            );

            assert!(
                server
                    .streams()
                    .send()
                    .send(peer.send(), b"late-1rtt")
                    .is_ok(),
                "the established server must retain response stream credit"
            );
            let (packets, send_result) = server.output().send(now);
            send_result.expect("fixture flight must fit");
            for mut packet in packets {
                assert!(
                    client
                        .input(&mut work)
                        .recv_packet(&mut packet, now, |_| {})
                        .is_ok()
                );
            }
            let mut late = Vec::new();
            assert_eq!(
                client.streams().receive().recv(stream.receive(), &mut late),
                Ok(9)
            );
            assert_eq!(late, b"late-1rtt");
        })
    });
}

#[test]
fn issuing_lane() {
    let result = Authority::params()
        .and_then(Authority::options)
        .and_then(Authority::try_new);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("first lane authority must construct");
    let first = result.ok().expect("admitted authority");
    let result = Authority::params()
        .and_then(Authority::options)
        .and_then(Authority::try_new);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("second lane authority must construct");
    let second = result.ok().expect("admitted authority");
    let lanes = [first, second];
    let result = lanes[1].first(&[1; routing::CONNECTION_ID_LEN]);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("second lane must warm the native session cache");
    let route = routing::Shard::from_index(1);
    let mut initial = vec![0x62; routing::CONNECTION_ID_LEN];
    initial[0] = route.index();
    let initial = cid::Id::try_from(initial).expect("routed initial ID");
    let lane = usize::from(initial.as_slice()[0]);
    assert_eq!(lane, 1);
    let auth =
        (lanes.get(lane)).expect("authenticated route must select the second configured lane");
    let local =
        (cid::Id::try_from([1; routing::CONNECTION_ID_LEN])).expect("routed server ID must fit");
    let peer = (cid::Id::try_from([0x42; 8])).expect("client ID must fit");
    let result = auth
        .server
        .accept::<storage::Shared>(accept::Ids::initial(initial, local, peer));
    let mut server = result.expect("routed server session must construct");
    let result = auth.resume(initial, peer, route);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("routed reconnect must construct the client");
    let mut client = result.ok().expect("admitted client connection");
    client.with_scope(|mut client| {
        server.with_scope(|mut server| {
            let stream = (client.streams().send().open_bidi())
                .expect("the routed reconnect must retain stream credit");
            let peer = server.streams().view().resolve_bidi(stream.id());
            let peer = (peer).expect("test precondition");
            assert!(
                client
                    .streams()
                    .send()
                    .send(stream.send(), b"lane-one")
                    .is_ok(),
                "the routed early payload must fit cached peer credit"
            );
            let mut work = conn::Workspace::try_new().expect("receive workspace allocation");
            let (packets, send_result) = client.output().send(Instant::now());
            send_result.expect("fixture flight must fit");
            for mut packet in packets {
                assert!(
                    server
                        .input(&mut work)
                        .recv_packet(&mut packet, Instant::now(), |_| {})
                        .is_ok()
                );
            }
            let mut got = Vec::new();
            assert_eq!(
                server.streams().receive().recv(peer.receive(), &mut got),
                Ok(8)
            );
            assert_eq!(got, b"lane-one");
        })
    });
}

#[test]
fn new_identity() {
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
    let result = auth.resumed([0xD1; 8], [0xD2; 8]);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("native cache must resume peer sessions");
    let Pair {
        mut server,
        mut client,
        mut work,
    } = result.ok().expect("admitted peer sessions");
    client.with_scope(|mut client| {
        server.with_scope(|mut server| {
            let now = Instant::now();
            let stream = (client.streams().send().open_bidi())
                .expect("the resumed client must retain bidirectional stream credit");
            let peer = server.streams().view().resolve_bidi(stream.id());
            let peer = (peer).expect("test precondition");
            assert!(
                client
                    .streams()
                    .send()
                    .send(stream.send(), b"new-generation")
                    .is_ok(),
                "the generation payload must fit cached peer credit"
            );
            let (packets, send_result) = client.output().send(now);
            send_result.expect("fixture flight must fit");
            for mut packet in packets {
                assert!(
                    server
                        .input(&mut work)
                        .recv_packet(&mut packet, now, |_| {})
                        .is_ok()
                );
            }

            let mut got = Vec::new();
            assert_eq!(
                server.streams().receive().recv(peer.receive(), &mut got),
                Ok(14)
            );
            assert_eq!(got, b"new-generation");
            assert!(
                !server.view().lifecycle().is_ready(),
                "new connection IDs must not relabel accepted early data as one-RTT"
            );
        })
    });
}

#[test]
fn before_handshake() {
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
    let result = auth.resumed([0xE1; 8], [0xE2; 8]);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("native cache must resume peer sessions");
    let Pair {
        mut server,
        mut client,
        mut work,
    } = result.ok().expect("admitted peer sessions");
    client.with_scope(|mut client| {
        server.with_scope(|mut server| {
            let now = Instant::now();
            let stream = (client.streams().send().open_bidi())
                .expect("the resumed client must retain bidirectional stream credit");
            let peer = server.streams().view().resolve_bidi(stream.id());
            let peer = (peer).expect("test precondition");
            assert!(
                client
                    .streams()
                    .send()
                    .send(stream.send(), b"early-bytes")
                    .is_ok(),
                "the early payload must fit cached peer credit"
            );

            let (mut flight, send_result) = client.output().send(now);
            send_result.expect("configured client journals must admit the zero-RTT flight");
            assert!(
                flight
                    .iter()
                    .any(|packet| packet.first().is_some_and(|byte| byte & 0xF0 == 0xD0)),
                "the first resumed flight must contain a zero-RTT packet"
            );
            for packet in &mut flight {
                assert!(
                    server
                        .input(&mut work)
                        .recv_packet(packet, now, |_| {})
                        .is_ok(),
                    "a client-generated zero-RTT packet must pass paired server ingress"
                );
            }

            let mut got = Vec::new();
            assert_eq!(
                server.streams().receive().recv(peer.receive(), &mut got),
                Ok(11)
            );
            assert_eq!(got, b"early-bytes");
            assert!(
                !server.view().lifecycle().is_ready(),
                "the server must expose zero-RTT stream data before handshake completion"
            );
        })
    });
}

#[test]
fn accepted_stream_count() {
    use common::suite::peers::packet::{self, params};
    use dope_quic::{
        conn::{life::options::Options, life::tls::clients, stream},
        proto::{early::ReplayCap, param},
        wire::{frame, stream::Direction},
    };
    use rustls::pki_types::ServerName;
    use std::net::Ipv4Addr;

    let (client, server, _) = params::configs().expect("TLS configuration");
    let params = param::Set::builder()
        .initial_data(1024)
        .local_bidi(1024)
        .remote_bidi(1024)
        .stream_uni(1024)
        .bidi_count(1)
        .uni_count(1)
        .try_build()
        .expect("initial stream limits");
    let options = Options::builder()
        .transport(|wire| wire.params(params.clone()))
        .streams(|streams| streams.local_bidi(3).local_uni(3))
        .try_build()
        .expect("three local slots per direction");
    let auth = Authority {
        server: accept::Authority::with_early(
            server,
            options,
            ReplayCap::new(8).expect("session capacity"),
        )
        .expect("server authority"),
        client: clients::Authority::try_new(
            client.clone(),
            ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()),
        )
        .expect("client authority"),
    };
    let warmed = auth.first(&packet::CID);
    warmed
        .as_ref()
        .map_err(Error::cause)
        .expect("shared native session cache");
    let id = cid::Id::try_from(packet::CID).expect("connection ID");
    let mut peer = packet::Session::try_new(client, &params).expect("resumed TLS client");
    let mut server = auth
        .server
        .accept::<storage::Shared>(accept::Ids::initial(id, id, id))
        .expect("resuming server");
    let mut work = conn::Workspace::try_new().expect("connection workspace");
    let now = Instant::now();
    let mut initial = peer.initial().expect("client Initial");
    server
        .with_scope(|mut scope| {
            scope
                .input(&mut work)
                .recv_packet(&mut initial, now, |_| {})
        })
        .expect("client hello");
    let mut early = peer
        .early(&[
            frame::TYPE_MAX_STREAMS_BIDI,
            2,
            frame::TYPE_MAX_STREAMS_UNI,
            2,
        ])
        .expect("authenticated zero-RTT limits");
    server
        .with_scope(|mut scope| scope.input(&mut work).recv_packet(&mut early, now, |_| {}))
        .expect("early MAX_STREAMS");
    assert!(server.view().lifecycle().is_opening());
    let (emitted_packets, send_result) = server.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("server handshake");
    for packet in emitted_packets {
        let _ = peer.receive(&packet).expect("server flight");
    }
    let mut finish = peer.finish(None).expect("client Finished");
    server
        .with_scope(|mut scope| scope.input(&mut work).recv_packet(&mut finish, now, |_| {}))
        .expect("handshake completion");
    assert!(server.view().lifecycle().is_ready());
    assert!(server.view().lifecycle().is_early());
    server.with_scope(|mut scope| {
        let mut streams = scope.streams();
        let mut send = streams.send();
        for (dir, first) in [(Direction::Bidi, 1), (Direction::Uni, 3)] {
            assert_eq!(send.open_handle(dir).map(|id| id.id().get()), Ok(first));
            assert_eq!(send.open_handle(dir).map(|id| id.id().get()), Ok(first + 4));
            assert_eq!(
                send.open_handle(dir).map(|id| id.id().get()),
                Err(stream::Error::PeerLimit),
            );
        }
    });
    let mut next = peer
        .packet(&[frame::TYPE_MAX_STREAMS_BIDI, 3])
        .expect("one-RTT continues the application packet numbers");
    server
        .with_scope(|mut scope| scope.input(&mut work).recv_packet(&mut next, now, |_| {}))
        .expect("one-RTT stream limit");
    assert_eq!(
        server.with_scope(|mut scope| {
            scope
                .streams()
                .send()
                .open_bidi()
                .map(|stream| stream.id().get())
        }),
        Ok(9),
    );
}
