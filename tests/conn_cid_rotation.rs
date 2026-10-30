use crate::common::peer;
pub mod common;
use common::suite::cid::{Count, INITIAL};
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::runtime::mux::builder::Plan;
use std::{
    net::SocketAddr,
    pin::Pin,
    time::{Duration, Instant},
};

#[test]
fn reuses_rotated_slot() {
    let (signing, key) = peer::raw(0x39).expect("raw identity");
    let mut server =
        Count::server(signing.server().expect("server TLS"), Plan::standard()).expect("CID server");
    let mut client = (Builder::client(Count::default()).build())
        .expect("standard client router plan must be valid");
    let peer = SocketAddr::from(([10, 0, 0, 2], 443));
    let local = SocketAddr::from(([10, 0, 0, 1], 50000));
    let started = Instant::now();
    let outbound = (Count::connect(&mut client, peer, key, INITIAL.to_vec(), started))
        .expect("fixed client connection parameters must be valid");

    for turn in 0..8 {
        let now = started + Duration::from_millis(turn * 10);
        Count::relay_at(&mut client, &mut server, local, now).expect("CID relay_at");
        Count::relay_at(&mut server, &mut client, peer, now).expect("CID relay_at");
    }
    assert_eq!(server.handler().established, 1);
    assert_eq!(client.handler().established, 1);
    let inbound = (server.handler().last_handle)
        .expect("established server must record its connection handle");

    let old_at = started + Duration::from_secs(1);
    assert!(
        Count::send(&mut client, outbound, vec![0x10], old_at).is_ok(),
        "live client connection must accept the first datagram"
    );
    Pin::new(&mut client).observe(old_at, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "fixture client connections must admit the first CID packet"
        );
    });
    let mut flights: Vec<_> =
        Pin::new(&mut client).observe(old_at, |mut turn| turn.output().drain().collect());
    let mut live = (flights
        .iter_mut()
        .flat_map(|outgoing| outgoing.segments_mut())
        .find(|wire| Count::short_cid(wire).is_some())
        .map(|wire| wire.to_vec()))
    .expect("one packet uses the initial server CID");
    for outgoing in flights {
        Pin::new(&mut client).output().recycle(outgoing);
    }
    let old_dcid = (Count::short_cid(&live))
        .expect("selected initial packet must expose its short destination CID");

    let queue_at = old_at + Duration::from_millis(1);
    assert!(
        Count::send(&mut client, outbound, vec![0x11], queue_at).is_ok(),
        "live client connection must accept the held datagram"
    );
    let stale_at = match Pin::new(&mut client).observe(queue_at, |turn| turn.deadline()) {
        Some(deadline) => deadline.max(queue_at),
        None => queue_at,
    };
    Pin::new(&mut client).observe(stale_at, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "fixture client connections must admit the held CID packet"
        );
    });
    let mut flights: Vec<_> =
        Pin::new(&mut client).observe(stale_at, |mut turn| turn.output().drain().collect());
    let mut stale = (flights
        .iter_mut()
        .flat_map(|outgoing| outgoing.segments_mut())
        .find(|wire| Count::short_cid(wire).is_some())
        .map(|wire| wire.to_vec()))
    .expect("a second packet uses the initial server CID");
    for outgoing in flights {
        Pin::new(&mut client).output().recycle(outgoing);
    }
    assert_eq!(Count::short_cid(&stale), Some(old_dcid));

    let start = stale_at + Duration::from_millis(1);
    assert!(matches!(
        Count::rotate(&mut server, inbound, start),
        Ok(dope_quic::conn::scope::path::Rotation::Queued)
    ));
    assert!(
        matches!(
            Count::rotate(&mut server, inbound, start),
            Ok(dope_quic::conn::scope::path::Rotation::Unavailable)
        ),
        "a rotation remains singular until its retirement arrives",
    );
    let mut dropped = 0;
    for turn in 0..4 {
        let now = start + Duration::from_millis(turn * 10);
        Pin::new(&mut server).observe(now, |mut turn| {
            assert!(
                turn.output().drive().is_ok(),
                "fixture server connections must admit CID rotation output"
            );
        });
        dropped += Pin::new(&mut server).observe(now, |mut turn| turn.output().drain().count());
    }
    assert_ne!(dropped, 0, "the first rotation flight is dropped");

    let live_at = start + Duration::from_millis(31);
    assert!(
        Count::receive(&mut server, local, &mut live, live_at).is_ok(),
        "packet on the live initial route must be accepted"
    );
    Pin::new(&mut server).observe(live_at, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "fixture server connections must admit live-route output"
        );
    });
    assert_eq!(
        server.handler().datagrams,
        1,
        "the old route remains valid before its retirement arrives",
    );
    Pin::new(&mut server).observe(live_at, |mut turn| turn.output().drain().count());
    let deadline = (server
        .conn(inbound)
        .and_then(|conn| conn.view().recovery().next_timer()))
    .expect("lost rotation control arms PTO");
    let probe_at = deadline + Duration::from_millis(1);
    let rotation = Count::relay_at(&mut server, &mut client, peer, probe_at).expect("CID relay_at");
    assert!(!rotation.is_empty(), "PTO retransmits the rotation control");

    let retire = probe_at + Duration::from_millis(1);
    let wires = Count::relay_at(&mut client, &mut server, local, retire).expect("CID relay_at");
    let mut active = (Count::changed_cid(&wires, old_dcid)).expect("RETIRE uses a replacement CID");

    let fill_at = retire + Duration::from_millis(1);
    let flights = Count::relay_at(&mut server, &mut client, peer, fill_at).expect("CID relay_at");
    assert!(!flights.is_empty(), "retirement replenishes a local CID");
    let conn =
        (server.conn(inbound)).expect("established server connection must survive CID retirement");
    assert!(
        conn.view()
            .path()
            .local_cids()
            .values()
            .all(|cid| cid != old_dcid),
        "the retired CID leaves the connection's local set",
    );
    assert_eq!(
        server.handler().datagrams,
        1,
        "control exchange does not replay the held application packet",
    );
    assert!(
        Count::receive(&mut server, local, &mut stale, fill_at).is_ok(),
        "packet on the retired route must reach router input"
    );
    Pin::new(&mut server).observe(fill_at, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "fixture server connections must admit retired-route output"
        );
    });
    assert_eq!(server.handler().datagrams, 1, "the retired route is gone");
    Pin::new(&mut server).observe(fill_at, |mut turn| turn.output().drain().count());

    let mut cycle_at = fill_at;
    for _ in 0..3 {
        let start = cycle_at + Duration::from_millis(100);
        let conn = (server.conn(inbound))
            .expect("established server connection must survive repeated CID rotation");
        let retiring = (conn
            .view()
            .path()
            .local_cids()
            .entries()
            .map(|entry| entry.0)
            .min())
        .expect("live server connection must own at least one local CID");
        assert!(matches!(
            Count::rotate(&mut server, inbound, start),
            Ok(dope_quic::conn::scope::path::Rotation::Queued)
        ));
        let mut done = None;
        let mut now = start;
        for _ in 0..16 {
            Count::relay_at(&mut server, &mut client, peer, now).expect("CID relay_at");
            let wires =
                Count::relay_at(&mut client, &mut server, local, now).expect("CID relay_at");
            if let Some(changed) = Count::changed_cid(&wires, active) {
                active = changed;
            }
            let conn = (server.conn(inbound))
                .expect("established server connection must remain during CID retirement");
            let retired = conn
                .view()
                .path()
                .local_cids()
                .entries()
                .all(|entry| entry.0 != retiring);
            if retired {
                done = Some(now);
                break;
            }
            let deadline = ([
                Pin::new(&mut server).observe(now, |turn| turn.deadline()),
                Pin::new(&mut client).observe(now, |turn| turn.deadline()),
                server
                    .conn(inbound)
                    .and_then(|conn| conn.view().recovery().next_timer()),
                client
                    .conn(outbound)
                    .and_then(|conn| conn.view().recovery().next_timer()),
            ]
            .into_iter()
            .flatten()
            .filter(|deadline| *deadline > now)
            .min())
            .expect("an incomplete CID rotation owns a future deadline");
            now = deadline;
        }
        let done = (done).expect("rotation reaches RETIRE_CONNECTION_ID");
        let deadline = (Pin::new(&mut server).observe(done, |turn| turn.deadline()))
            .expect("retirement replenishment owns a mux deadline");
        let fill_at = deadline.max(done);
        Count::relay_at(&mut server, &mut client, peer, fill_at).expect("CID relay_at");
        cycle_at = fill_at;
    }
    let conn =
        (server.conn(inbound)).expect("established server connection must survive slot reuse");
    assert!(
        conn.view()
            .path()
            .local_cids()
            .entries()
            .any(|(sequence, cid)| sequence.get() >= 4 && cid == active),
        "the peer eventually selects a CID stored in a generation-reused slot",
    );

    let final_at = cycle_at + Duration::from_millis(100);
    assert!(
        Count::send(&mut client, outbound, vec![0x30], final_at).is_ok(),
        "live client connection must accept the final datagram"
    );
    let deadline = (Pin::new(&mut client).observe(final_at, |turn| turn.deadline()))
        .expect("application datagram owns a mux deadline");
    let send_at = deadline.max(final_at);
    let wires = Count::relay_at(&mut client, &mut server, local, send_at).expect("CID relay_at");
    assert!(
        wires
            .iter()
            .filter_map(|wire| Count::short_cid(wire))
            .any(|cid| cid == active)
    );
    Pin::new(&mut server).observe(send_at, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "fixture server connections must admit final CID output"
        );
    });
    assert_eq!(server.handler().datagrams, 2);
}
