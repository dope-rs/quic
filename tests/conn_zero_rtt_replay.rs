pub mod common;
use common::peer::Pair;
use common::suite::peers;
use common::suite::peers::Error;
use common::suite::peers::receive::replay::{self, finish};
use dope_quic::conn;
use dope_quic::conn::life::accept;
use dope_quic::conn::life::options::Options;
use dope_quic::runtime::routing;
use dope_quic::wire::packet::cid;
use dope_test::alloc::Tracker;
use o3::buffer::storage;
use std::time::Instant;

#[test]
fn route_mismatch() {
    let result = replay::authority();
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("ticket authority must construct");
    let auth = result.ok().expect("admitted authority");
    let result = auth.first(&[1; routing::CONNECTION_ID_LEN]);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("routed handshake must warm the native session cache");
    let route = routing::Shard::from_index(0);
    let mut initial = vec![0x66; routing::CONNECTION_ID_LEN];
    initial[0] = route.index();
    let initial = cid::Id::try_from(initial).expect("routed initial ID");
    let local = cid::Id::try_from([0x67; 8]).expect("client ID");
    let client = auth
        .client
        .connect::<0, Vec<u8>, storage::Shared>(initial, local, Options::default(), route)
        .expect("a foreign-lane ticket falls back to a fresh handshake");
    let mut fresh = Pair {
        client,
        server: auth
            .server
            .accept::<storage::Shared>(accept::Ids::initial(initial, initial, local))
            .expect("target lane server"),
        work: conn::Workspace::try_new().expect("receive workspace"),
    };
    assert!(
        fresh
            .client
            .with_scope(|mut scope| scope.streams().send().open_bidi().is_err())
    );
    fresh
        .exchange(Instant::now(), 6)
        .expect("fresh target lane handshake");
    fresh.try_ready().expect("target lane remains reachable");
    assert!(!fresh.client.view().lifecycle().is_early());
    assert!(!fresh.server.view().lifecycle().is_early());
    drop(fresh);

    let route = routing::Shard::from_index(1);
    let mut initial = vec![0x68; routing::CONNECTION_ID_LEN];
    initial[0] = route.index();
    let initial = cid::Id::try_from(initial).expect("matching initial ID");
    let result = auth.resume(initial, local, route);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("the second native ticket retains the issuing lane");
    let mut client = result.ok().expect("admitted client");
    let mut server = auth
        .server
        .accept::<storage::Shared>(accept::Ids::initial(initial, initial, local))
        .expect("issuing server");
    let mut work = conn::Workspace::try_new().expect("receive workspace");
    let now = Instant::now();
    client.with_scope(|mut client| {
        server.with_scope(|mut server| {
            let stream = client
                .streams()
                .send()
                .open_bidi()
                .expect("selected ticket credit");
            client
                .streams()
                .send()
                .send(stream.send(), b"lane")
                .expect("early bytes");
            let (emitted_packets, send_result) = client.output().send(now);
            send_result.expect("early flight");
            for mut packet in emitted_packets {
                server
                    .input(&mut work)
                    .recv_packet(&mut packet, now, |_| {})
                    .expect("early packet");
            }
            assert!(!server.view().lifecycle().is_ready());
            let peer = server
                .streams()
                .view()
                .resolve_recv(stream.id())
                .expect("incoming stream");
            let mut got = Vec::new();
            assert_eq!(server.streams().receive().recv(peer, &mut got), Ok(4));
            assert_eq!(got, b"lane");
            finish(&mut server, &mut client, &mut work, now).expect("resumed handshake");
        });
    });
    assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
}

#[test]
fn single_use() {
    let result = replay::authority();
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("ticket authority must construct");
    let auth = result.ok().expect("admitted authority");
    let result = auth.first(&peers::CID);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("handshake must warm the native session cache");
    let initial = cid::Id::try_from([0x63; routing::ENTROPY_LEN]).expect("initial ID");
    let local = (cid::Id::try_from([0xA1; 8])).expect("server ID must fit");
    let remote = (cid::Id::try_from([0xA2; 8])).expect("client ID must fit");
    let result = auth
        .server
        .accept::<storage::Shared>(accept::Ids::initial(initial, local, remote));
    let mut first = result.expect("first server session must construct");
    let result = auth.resume(initial, remote, routing::Plain);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("native session cache must construct the resumed client");
    let mut client = result.ok().expect("admitted client connection");
    let mut work = conn::Workspace::try_new().expect("receive workspace allocation");
    let now = Instant::now();
    client.with_scope(|mut client| {
        let stream = (client.streams().send().open_bidi())
            .expect("cached peer credit must admit the stream");
        assert!(
            client
                .streams()
                .send()
                .send(stream.send(), b"first-use")
                .is_ok()
        );
        let (mut flight, send_result) = client.output().send(now);
        send_result.expect("configured journals must admit early output");
        let mut replay = flight.clone();
        first.with_scope(|mut first| {
            let peer = (first.streams().view().resolve_recv(stream.id()))
                .expect("first server must accept the incoming stream direction");
            for packet in &mut flight {
                assert!(
                    first
                        .input(&mut work)
                        .recv_packet(packet, now, |_| {})
                        .is_ok()
                );
            }
            let mut got = Vec::new();
            assert_eq!(first.streams().receive().recv(peer, &mut got), Ok(9));
            assert_eq!(got, b"first-use");
        });
        let result = auth
            .server
            .accept::<storage::Shared>(accept::Ids::initial(initial, local, remote));
        let mut second = result.expect("replay probe must construct an independent server");
        second.with_scope(|mut second| {
            let peer = (second.streams().view().resolve_recv(stream.id()))
                .expect("second server must accept the incoming stream direction");
            for packet in &mut replay {
                assert!(
                    second
                        .input(&mut work)
                        .recv_packet(packet, now, |_| {})
                        .is_ok()
                );
            }
            let mut rejected = Vec::new();
            assert_eq!(second.streams().receive().recv(peer, &mut rejected), Ok(0));
            assert!(
                rejected.is_empty(),
                "a ticket and ClientHello may authorize early data once"
            );
        });
    });
}

#[test]
fn disabled() {
    let result = replay::authority();
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("issuing authority must construct");
    let issuing = result.ok().expect("admitted authority");
    let result = issuing.first(&peers::CID);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("handshake must warm the native session cache");
    let initial = cid::Id::try_from([0x64; routing::ENTROPY_LEN]).expect("initial ID");
    issuing.server.reject_early();
    let local = (cid::Id::try_from(peers::CID)).expect("fixture ID must fit");
    let result = issuing
        .server
        .accept::<storage::Shared>(accept::Ids::initial(initial, local, local));
    let mut server = result.expect("server with early data disabled must construct");
    let ((), count) = Tracker::count(|| issuing.server.reject_early());
    assert_eq!(count, 0);
    let result = issuing.resume(initial, local, routing::Plain);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("native session cache must construct the resumed client");
    let mut client = result.ok().expect("admitted client connection");
    let mut work = conn::Workspace::try_new().expect("receive workspace allocation");
    let now = Instant::now();
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
                    .send(stream.send(), b"rejected")
                    .is_ok()
            );
            let (packets, send_result) = client.output().send(now);
            send_result.expect("configured journals must admit early output");
            assert!(
                packets
                    .iter()
                    .any(|packet| packet.first().is_some_and(|byte| byte & 0xF0 == 0xD0)),
                "the issuing client must attempt early data"
            );
            for mut packet in packets {
                assert!(
                    server
                        .input(&mut work)
                        .recv_packet(&mut packet, now, |_| {})
                        .is_ok()
                );
            }
            let mut got = Vec::new();
            assert_eq!(server.streams().receive().recv(peer, &mut got), Ok(0));
            assert!(
                got.is_empty(),
                "a server with early data disabled must reject early bytes"
            );
            assert!(finish(&mut server, &mut client, &mut work, now).is_ok());
            assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
            let (packets, send_result) = client.output().send(now);
            send_result.expect("configured journals must admit retransmission");
            for mut packet in packets {
                assert!(
                    server
                        .input(&mut work)
                        .recv_packet(&mut packet, now, |_| {})
                        .is_ok()
                );
            }
            let mut retry = Vec::new();
            assert_eq!(server.streams().receive().recv(peer, &mut retry), Ok(8));
            assert_eq!(retry, b"rejected");
        })
    });
}

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn foreign() {
    let result = replay::authority();
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("issuing authority must construct");
    let issuing = result.ok().expect("admitted authority");
    let result = replay::authority();
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("independent target authority must construct");
    let target = result.ok().expect("admitted authority");
    let result = issuing.first(&peers::CID);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("handshake must warm the native session cache");
    let initial = cid::Id::try_from([0x61; routing::ENTROPY_LEN]).expect("initial ID");
    let local = (cid::Id::try_from([0xB1; 8])).expect("server ID must fit");
    let remote = (cid::Id::try_from([0xB2; 8])).expect("client ID must fit");
    let result = target
        .server
        .accept::<storage::Shared>(accept::Ids::initial(initial, local, remote));
    let mut server = result.expect("independent target server must construct");
    let result = issuing.resume(initial, remote, routing::Plain);
    result
        .as_ref()
        .map_err(Error::cause)
        .expect("issuing client must retain its original resumption configuration");
    let mut client = result.ok().expect("admitted client connection");
    let mut work = conn::Workspace::try_new().expect("receive workspace allocation");
    let now = Instant::now();
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
                    .send(stream.send(), b"foreign-authority")
                    .is_ok()
            );
            let (packets, send_result) = client.output().send(now);
            send_result.expect("configured journals must admit early output");
            assert!(
                packets
                    .iter()
                    .any(|packet| packet.first().is_some_and(|byte| byte & 0xF0 == 0xD0)),
                "the issuing client must attempt early data"
            );
            for mut packet in packets {
                assert!(
                    server
                        .input(&mut work)
                        .recv_packet(&mut packet, now, |_| {})
                        .is_ok()
                );
            }
            let mut early = Vec::new();
            assert_eq!(server.streams().receive().recv(peer, &mut early), Ok(0));
            assert!(
                early.is_empty(),
                "a ticket cannot authorize another authority's early data"
            );
            assert!(finish(&mut server, &mut client, &mut work, now).is_ok());
            assert!(client.view().lifecycle().is_ready() && server.view().lifecycle().is_ready());
            let (packets, send_result) = client.output().send(now);
            send_result.expect("configured journals must admit retransmission");
            for mut packet in packets {
                assert!(
                    server
                        .input(&mut work)
                        .recv_packet(&mut packet, now, |_| {})
                        .is_ok()
                );
            }
            let mut retry = Vec::new();
            assert_eq!(server.streams().receive().recv(peer, &mut retry), Ok(17));
            assert_eq!(retry, b"foreign-authority");
        })
    });
}
