use common::suite::mux::dispatch;
pub mod common;

use common::suite::mux::paths::{CLIENT, Pair, Pending, SERVER};
use dope_quic::conn;
use dope_quic::errors::SendFailure;
use dope_quic::proto::epoch;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

#[test]
fn foreign_does_not_credit() {
    let mut pending = Pending::try_new(0x6d, 0xa7).expect("paths fixture must open");
    let foreign = SocketAddr::from(([198, 51, 100, 9], 41_000));
    let at = pending.start;
    let mut initial =
        dispatch::Capture::output(&mut pending.client, at).expect("path fixture operation");
    assert!(!initial.is_empty());
    let replay = initial
        .iter()
        .map(|packet| packet.payload().to_vec())
        .collect::<Vec<_>>();
    Pair::deliver(&mut initial, CLIENT, &mut pending.server, at).expect("path fixture operation");
    let ids = &pending.server.handler().created;
    let handle = *ids
        .first()
        .expect("valid Initial must create one server handle");
    let credited = Pair::credit(&mut pending.server, handle, at).expect("path fixture operation");
    assert_ne!(credited, 0);
    for mut packet in replay {
        Pair::receive(&mut pending.server, foreign, &mut packet, at)
            .expect("path fixture operation");
    }
    assert_eq!(
        Pair::credit(&mut pending.server, handle, at).expect("path fixture operation"),
        credited
    );
    for router in [&pending.client, &pending.server] {
        assert!(
            router.handler().errors.is_empty(),
            "{:?}",
            router.handler().errors
        );
    }
}

#[test]
fn rejects_unknown_server() {
    let pending = Pending::try_new(0x39, 0x81).expect("paths fixture must open");
    let mut pair = pending.establish().expect("path fixture operation");
    let unknown = SocketAddr::from(([10, 0, 0, 3], 443));
    let at = pair.start + Duration::from_secs(1);
    pair.send_server(b"wrong-server-path".to_vec(), at)
        .expect("path fixture operation");
    let mut packets =
        dispatch::Capture::output(&mut pair.server, at).expect("path fixture operation");
    assert!(!packets.is_empty());
    for packet in &mut packets {
        for segment in packet.segments_mut() {
            let error = Pin::new(&mut pair.client).observe(at, |mut turn| {
                turn.protocol().recv(unknown, segment, epoch::WALL_CLOCK)
            });
            assert!(matches!(error, Err(dope_quic::errors::Receive::Packet(
                conn::Error::Path(conn::wire::path::Error::Policy { active: SERVER, source })
            )) if source == unknown));
        }
    }
    Pair::discard(&mut pair.client, at).expect("path fixture operation");
    assert!(pair.client.handler().datagrams.is_empty());
    assert_eq!(
        Pair::peer(&mut pair.client, pair.client_id, at).expect("path fixture operation"),
        Some(SERVER)
    );
    for router in [&pair.client, &pair.server] {
        assert!(
            router.handler().errors.is_empty(),
            "{:?}",
            router.handler().errors
        );
    }
}

#[test]
fn validates_before_rebind() {
    let pending = Pending::try_new(0x39, 0x81).expect("paths fixture must open");
    let mut pair = pending.establish().expect("path fixture operation");
    let rebound = SocketAddr::from(([10, 0, 0, 1], 50_001));
    let at = pair.start + Duration::from_millis(20);
    let received = pair
        .observe(rebound, b"from-new-port".to_vec(), pair.start, at)
        .expect("path fixture operation");
    assert_eq!(
        Pair::peer(&mut pair.server, pair.server_id, at).expect("path fixture operation"),
        Some(CLIENT)
    );
    pair.send_server(b"before-validation".to_vec(), at)
        .expect("path fixture operation");
    let stream = Pair::access(&mut pair.server, pair.server_id, at, |mut conn| {
        let mut streams = conn.streams();
        let mut send = streams.send();
        let id = send
            .open_uni()
            .expect("the negotiated unidirectional stream credit must remain available");
        send.send(id, b"survives-paths")
            .expect("the fixture stream payload must fit its send credit");
        send.finish(id)
            .expect("the fixture send stream must remain open for FIN");
        id.id()
    })
    .expect("path fixture operation");
    let mut flight =
        dispatch::Capture::output(&mut pair.server, at).expect("path fixture operation");
    assert_eq!(
        pair.server.handler().datagrams,
        vec![b"from-new-port".to_vec()]
    );
    assert!(Pair::path(&flight, rebound).next().is_some());
    assert!(Pair::path(&flight, rebound).all(|packet| packet.payload().len() >= 1_200));
    let sent = Pair::path(&flight, rebound)
        .map(|packet| packet.payload().len())
        .sum::<usize>();
    assert!(sent <= received.saturating_mul(3));
    assert!(Pair::path(&flight, CLIENT).next().is_some());
    let active = Pair::path(&flight, CLIENT)
        .find_map(Pair::short_cid)
        .expect("the active path must emit a short-header packet");
    let probe = Pair::path(&flight, rebound)
        .find_map(Pair::short_cid)
        .expect("the candidate path must emit a short-header packet");
    assert_ne!(active, probe);
    let reply_at = pair
        .answer(&mut flight, rebound, at)
        .expect("path fixture operation");
    let route =
        Pair::peer(&mut pair.server, pair.server_id, reply_at).expect("path fixture operation");
    assert_eq!(route, Some(rebound));
    pair.send_server(b"after-validation".to_vec(), reply_at)
        .expect("path fixture operation");
    let after = reply_at + Duration::from_millis(1);
    let mut output =
        dispatch::Capture::output(&mut pair.server, after).expect("path fixture operation");
    assert!(Pair::path(&output, rebound).any(|packet| !packet.payload().is_empty()));
    Pair::relay(&mut output, rebound, SERVER, &mut pair.client, after)
        .expect("path fixture operation");
    Pair::discard(&mut pair.client, after).expect("path fixture operation");
    let streams = vec![(stream.get(), b"survives-paths".to_vec())];
    assert_eq!(pair.client.handler().streams, streams);
    let foreign = pair.client_id;
    let result = Pin::new(&mut pair.server).observe(after, |mut turn| {
        turn.protocol().try_datagram(foreign, Vec::new())
    });
    assert_eq!(result, Err(SendFailure::Closed(Vec::new())));
    for router in [&pair.client, &pair.server] {
        assert!(
            router.handler().errors.is_empty(),
            "{:?}",
            router.handler().errors
        );
    }
}

#[test]
fn new_candidate_supersedes() {
    let pending = Pending::try_new(0x39, 0x81).expect("paths fixture must open");
    let mut pair = pending.establish().expect("path fixture operation");
    let first = SocketAddr::from(([10, 0, 0, 1], 50_001));
    let second = SocketAddr::from(([10, 0, 0, 1], 50_002));
    let first_at = pair.start + Duration::from_millis(20);
    pair.observe(first, vec![0x11; 500], first_at, first_at)
        .expect("path fixture operation");
    let flight =
        dispatch::Capture::output(&mut pair.server, first_at).expect("path fixture operation");
    assert!(Pair::path(&flight, first).next().is_some());
    let next = first_at + Duration::from_millis(20);
    pair.observe(second, vec![0x22; 500], next, next)
        .expect("path fixture operation");
    let mut flight =
        dispatch::Capture::output(&mut pair.server, next).expect("path fixture operation");
    assert!(Pair::path(&flight, second).next().is_some());
    assert!(Pair::path(&flight, first).next().is_none());
    let at = pair
        .answer(&mut flight, second, next)
        .expect("path fixture operation");
    pair.send_server(b"replacement-won".to_vec(), at)
        .expect("path fixture operation");
    let output = dispatch::Capture::output(&mut pair.server, at + Duration::from_millis(1))
        .expect("path fixture operation");
    assert!(Pair::path(&output, second).next().is_some());
    for router in [&pair.client, &pair.server] {
        assert!(
            router.handler().errors.is_empty(),
            "{:?}",
            router.handler().errors
        );
    }
}

#[test]
fn expired_path_restarts() {
    let pending = Pending::try_new(0x39, 0x81).expect("paths fixture must open");
    let mut pair = pending.establish().expect("path fixture operation");
    let peer = SocketAddr::from(([10, 0, 0, 1], 50_001));
    let first = pair.start + Duration::from_millis(20);
    pair.observe(peer, vec![0x33; 500], first, first)
        .expect("path fixture operation");
    let output =
        dispatch::Capture::output(&mut pair.server, first).expect("path fixture operation");
    assert!(Pair::path(&output, peer).next().is_some());
    let expired = first + Duration::from_secs(5);
    let output =
        dispatch::Capture::output(&mut pair.server, expired).expect("path fixture operation");
    assert!(output.iter().all(|packet| packet.addr() == CLIENT));
    pair.send_server(b"old-path-survives".to_vec(), expired)
        .expect("path fixture operation");
    let output = dispatch::Capture::output(&mut pair.server, expired + Duration::from_millis(1))
        .expect("path fixture operation");
    assert!(Pair::path(&output, CLIENT).next().is_some());
    let restart = expired + Duration::from_millis(2);
    pair.observe(peer, vec![0x44; 500], restart, restart)
        .expect("path fixture operation");
    let output =
        dispatch::Capture::output(&mut pair.server, restart).expect("path fixture operation");
    assert!(Pair::path(&output, peer).next().is_some());
    for router in [&pair.client, &pair.server] {
        assert!(
            router.handler().errors.is_empty(),
            "{:?}",
            router.handler().errors
        );
    }
}

#[test]
fn retries_validation() {
    let pending = Pending::try_new(0x39, 0x81).expect("paths fixture must open");
    let mut pair = pending.establish().expect("path fixture operation");
    let peer = SocketAddr::from(([10, 0, 0, 1], 50_001));
    let first = pair.start + Duration::from_millis(20);
    pair.observe(peer, vec![0x55; 500], first, first)
        .expect("path fixture operation");
    let output =
        dispatch::Capture::output(&mut pair.server, first).expect("path fixture operation");
    assert!(Pair::path(&output, peer).next().is_some());
    let (cursor, mut retry) =
        Pair::retry(&mut pair.server, first, 8, Some(peer)).expect("path fixture operation");
    assert!(Pair::path(&retry, peer).next().is_some());
    assert!(Pair::path(&retry, peer).all(|packet| packet.payload().len() >= 1_200));
    let at = pair
        .answer(&mut retry, peer, cursor)
        .expect("path fixture operation");
    pair.send_server(b"retry-validated".to_vec(), at)
        .expect("path fixture operation");
    let output = dispatch::Capture::output(&mut pair.server, at + Duration::from_millis(1))
        .expect("path fixture operation");
    assert!(Pair::path(&output, peer).next().is_some());
    for router in [&pair.client, &pair.server] {
        assert!(
            router.handler().errors.is_empty(),
            "{:?}",
            router.handler().errors
        );
    }
}

#[test]
fn separates_path_budgets() {
    let pending = Pending::try_new(0x39, 0x81).expect("paths fixture must open");
    let mut pair = pending.establish().expect("path fixture operation");
    let first = SocketAddr::from(([10, 0, 0, 1], 51_001));
    let second = SocketAddr::from(([10, 0, 0, 1], 51_002));
    let at = pair.start + Duration::from_millis(20);
    let token = [0x71, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64, 0x31];
    pair.challenge(token, at).expect("path fixture operation");
    let first_n = pair
        .observe(first, vec![0x31; 500], at, at)
        .expect("path fixture operation");
    let next = at + Duration::from_millis(1);
    let second_n = pair
        .observe(second, vec![0x32; 500], next, next)
        .expect("path fixture operation");
    let mut flights =
        dispatch::Capture::output(&mut pair.server, next).expect("path fixture operation");
    flights.extend(
        dispatch::Capture::output(&mut pair.server, next + Duration::from_millis(1))
            .expect("path fixture operation"),
    );
    let first_i = flights
        .iter()
        .position(|packet| packet.addr() == first)
        .expect("the retained PATH_RESPONSE must keep its original destination");
    let second_i = flights
        .iter()
        .position(|packet| packet.addr() == second)
        .expect("replacement validation must keep its independent destination");
    assert!(first_i < second_i);
    assert!(
        flights
            .iter()
            .filter(|packet| packet.addr() == first || packet.addr() == second)
            .all(|packet| packet.packet_count().get() == 1)
    );
    let sent_a = Pair::path(&flights, first)
        .map(|packet| packet.payload().len())
        .sum::<usize>();
    let sent_b = Pair::path(&flights, second)
        .map(|packet| packet.payload().len())
        .sum::<usize>();
    assert!(sent_a <= first_n.saturating_mul(3));
    assert!(sent_b <= second_n.saturating_mul(3));
    for router in [&pair.client, &pair.server] {
        assert!(
            router.handler().errors.is_empty(),
            "{:?}",
            router.handler().errors
        );
    }
}

#[test]
fn responds_on_each_path() {
    let pending = Pending::try_new(0x39, 0x81).expect("paths fixture must open");
    let mut pair = pending.establish().expect("path fixture operation");
    let first = SocketAddr::from(([10, 0, 0, 1], 52_001));
    let second = SocketAddr::from(([10, 0, 0, 1], 52_002));
    let token = [0x72, 0x65, 0x74, 0x72, 0x79, 0x2d, 0x6d, 0x65];
    let at = pair.start + Duration::from_millis(20);
    pair.challenge(token, at).expect("path fixture operation");
    let mut flight =
        dispatch::Capture::output(&mut pair.client, at).expect("path fixture operation");
    assert!(!flight.is_empty());
    Pair::deliver(&mut flight, first, &mut pair.server, at).expect("path fixture operation");
    let (retry_at, mut retry) =
        Pair::retry(&mut pair.client, at, 16, None).expect("path fixture operation");
    assert!(!retry.is_empty());
    Pair::deliver(&mut retry, second, &mut pair.server, retry_at).expect("path fixture operation");
    let mut flights =
        dispatch::Capture::output(&mut pair.server, retry_at).expect("path fixture operation");
    flights.extend(
        dispatch::Capture::output(&mut pair.server, retry_at + Duration::from_millis(1))
            .expect("path fixture operation"),
    );
    let mut output = flights
        .into_iter()
        .filter(|packet| packet.addr() == second)
        .collect::<Vec<_>>();
    assert!(!output.is_empty());
    let at = retry_at + Duration::from_millis(2);
    Pair::deliver(&mut output, SERVER, &mut pair.client, at).expect("path fixture operation");
    assert!(
        Pair::access(&mut pair.client, pair.client_id, at, |conn| {
            conn.view().path().has_token(&token)
        })
        .expect("path fixture operation")
    );
    for router in [&pair.client, &pair.server] {
        assert!(
            router.handler().errors.is_empty(),
            "{:?}",
            router.handler().errors
        );
    }
}
