use crate::common::peer;
use common::suite::peers::tls;
pub mod common;
use common::suite::cid::{Count, INITIAL};
use dope_quic::errors::{Access, Code};
use dope_quic::proto::cid::Rotation;
use dope_quic::runtime::mux::builder::{Builder, Plan};
use std::cell::Cell;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::num::NonZero;
use std::pin::Pin;
use std::time::{Duration, Instant};

#[test]
fn routes_handshake() {
    let (signing, key) = peer::raw(0x39).expect("raw identity");
    let mut server =
        Count::server(signing.server().expect("server TLS"), Plan::standard()).expect("CID server");
    let mut client = Builder::client(Count::default())
        .build()
        .expect("default client router plan must be valid");
    let peer: SocketAddr = "10.0.0.2:443"
        .parse()
        .expect("server test address must be valid");
    let local: SocketAddr = "10.0.0.1:50000"
        .parse()
        .expect("client test address must be valid");

    let now = Instant::now();
    assert!(
        Pin::new(&mut client)
            .observe(now, |mut turn| {
                turn.protocol().connect(
                    peer,
                    &tls::client(key).expect("client TLS authority"),
                    Count::options().expect("CID options"),
                    INITIAL.to_vec(),
                )
            })
            .is_ok(),
        "fresh client connection must be accepted"
    );

    Count::relay(&mut client, &mut server, local).expect("CID relay");
    Count::relay(&mut server, &mut client, peer).expect("CID relay");
    Count::relay(&mut client, &mut server, local).expect("CID relay");
    Count::relay(&mut server, &mut client, peer).expect("CID relay");

    assert_eq!(server.handler().established, 1);
    assert_eq!(client.handler().established, 1);
}

#[test]
fn rotates_before_retiring() {
    let (signing, key) = peer::raw(0x39).expect("raw identity");
    let mut server =
        Count::server(signing.server().expect("server TLS"), Plan::standard()).expect("CID server");
    let mut client = Builder::client(Count::default())
        .build()
        .expect("default client router plan must be valid");
    let peer: SocketAddr = "10.0.0.2:443"
        .parse()
        .expect("server test address must be valid");
    let local: SocketAddr = "10.0.0.1:50000"
        .parse()
        .expect("client test address must be valid");
    let started = Instant::now();
    assert!(
        Pin::new(&mut client)
            .observe(started, |mut turn| {
                turn.protocol().connect(
                    peer,
                    &tls::client(key).expect("client TLS authority"),
                    Count::options().expect("CID options"),
                    INITIAL.to_vec(),
                )
            })
            .is_ok(),
        "fresh client connection must be accepted"
    );
    for turn in 0..8 {
        let now = started + Duration::from_millis(turn * 10);
        Count::relay_at(&mut client, &mut server, local, now).expect("CID relay_at");
        Count::relay_at(&mut server, &mut client, peer, now).expect("CID relay_at");
        if server.handler().established == 1 {
            break;
        }
    }
    assert_eq!(server.handler().established, 1);

    let mut rotation = Pin::new(&mut server).observe(started, |turn| {
        turn.plan_cid(
            Rotation::try_periodic(
                Duration::from_secs(1),
                NonZero::<u16>::new(1024).expect("rotation budget"),
            )
            .expect("one-second rotation period"),
        )
    });
    let first = Pin::new(&mut server).observe(started + Duration::from_secs(1), |mut turn| {
        turn.maintain_cid(&mut rotation)
    });
    assert_eq!(first.visited(), 1);
    assert_eq!(first.started(), 1);
    assert!(first.is_complete());
    for turn in 0..8 {
        let now = started + Duration::from_secs(1) + Duration::from_millis(turn * 10);
        Count::relay_at(&mut server, &mut client, peer, now).expect("CID relay_at");
        Count::relay_at(&mut client, &mut server, local, now).expect("CID relay_at");
    }
    let early = Pin::new(&mut server).observe(started + Duration::from_millis(1500), |mut turn| {
        turn.maintain_cid(&mut rotation)
    });
    assert_eq!(early.visited(), 0);
    assert_eq!(early.started(), 0);

    let mut next = Builder::client(Count::default())
        .build()
        .expect("replacement client router plan must be valid");
    let next_at = started + Duration::from_secs(2);
    assert!(
        Pin::new(&mut next)
            .observe(next_at, |mut turn| {
                turn.protocol().connect(
                    peer,
                    &tls::client(key).expect("client TLS authority"),
                    Count::options().expect("CID options"),
                    [0x53; 8].to_vec(),
                )
            })
            .is_ok(),
        "replacement client connection must be accepted"
    );
    for turn in 0..8 {
        let now = started + Duration::from_secs(2) + Duration::from_millis(turn * 10);
        Count::relay_at(&mut next, &mut server, local, now).expect("CID relay_at");
        Count::relay_at(&mut server, &mut next, peer, now).expect("CID relay_at");
        if server.handler().established == 2 {
            break;
        }
    }
    assert_eq!(server.handler().established, 2);
    assert_eq!(server.active_conns(), 2);
    assert_eq!(client.active_conns(), 1);
    assert_eq!(next.active_conns(), 1);

    let close_at = started + Duration::from_secs(3);
    let handle = client
        .handler()
        .last_handle
        .expect("established client must retain its connection handle");
    Pin::new(&mut client)
        .observe(close_at, |mut turn| {
            turn.protocol().with_conn(handle, |mut scope| {
                scope.lifecycle().close(Code::ZERO, Vec::new());
            })
        })
        .expect("established client handle must resolve for close");
    for turn in 0..8 {
        let now = close_at + Duration::from_millis(turn * 10);
        Count::relay_at(&mut client, &mut server, local, now).expect("CID relay_at");
        Count::relay_at(&mut server, &mut client, peer, now).expect("CID relay_at");
        if client.active_conns() == 0 && server.active_conns() == 1 {
            break;
        }
    }
    assert_eq!(client.active_conns(), 0);
    assert_eq!(server.active_conns(), 1);
    assert_eq!(next.active_conns(), 1);
}

#[test]
fn demuxes_shared_address() {
    let (signing, key) = peer::raw(0x39).expect("raw identity");
    let mut server =
        Count::server(signing.server().expect("server TLS"), Plan::standard()).expect("CID server");

    let mut client_a = Builder::client(Count::default())
        .build()
        .expect("first client router plan must be valid");
    let mut client_b = Builder::client(Count::default())
        .build()
        .expect("second client router plan must be valid");

    let peer: SocketAddr = "10.0.0.2:443"
        .parse()
        .expect("server test address must be valid");
    let shared: SocketAddr = "10.0.0.1:50000"
        .parse()
        .expect("shared client test address must be valid");

    let now = Instant::now();
    let ha = Count::connect(&mut client_a, peer, key, vec![0xAA; 8], now)
        .expect("first client connection must be accepted");
    let hb = Count::connect(&mut client_b, peer, key, vec![0xBB; 8], now)
        .expect("second client connection must be accepted");

    let called = Cell::new(false);
    let at = Instant::now();
    let bad_a = Pin::new(&mut client_b).observe(at, |mut turn| {
        turn.protocol().with_conn(ha, |scope| {
            called.set(true);
            scope.view().lifecycle().is_opening()
        })
    });
    let bad_b = Pin::new(&mut client_a).observe(at, |mut turn| {
        turn.protocol().with_conn(hb, |scope| {
            called.set(true);
            scope.view().lifecycle().is_opening()
        })
    });
    assert_eq!(bad_a, Err(Access::InvalidHandle));
    assert_eq!(bad_b, Err(Access::InvalidHandle));
    assert!(matches!(
        Count::rotate(&mut client_a, hb, at),
        Err(Access::InvalidHandle)
    ));
    assert!(matches!(
        Count::rotate(&mut client_b, ha, at),
        Err(Access::InvalidHandle)
    ));
    assert!(!called.get(), "foreign handles must not enter the callback");
    for client in [&mut client_a, &mut client_b] {
        for _ in 0..16 {
            Count::relay(client, &mut server, shared).expect("CID relay");
            Count::relay(&mut server, client, peer).expect("CID relay");
            if client.handler().established == 1 {
                Count::relay(client, &mut server, shared).expect("CID relay");
                break;
            }
        }
        assert_eq!(client.handler().established, 1);
    }

    let handles = server.handler().handles.clone();
    assert_eq!(handles.len(), 2);
    for handle in handles {
        assert_eq!(
            Pin::new(&mut server).observe(Instant::now(), |mut turn| {
                turn.protocol()
                    .with_conn(handle, |scope| scope.view().lifecycle().is_ready())
            }),
            Ok(true),
        );
    }
}

#[test]
fn projects_unique_cids() {
    let (signing, key) = peer::raw(0x39).expect("raw identity");
    let mut server =
        Count::server(signing.server().expect("server TLS"), Plan::standard()).expect("CID server");
    let mut client = Builder::client(Count::default())
        .limits(Plan::try_new(4, 64, 1 << 20).expect("four-connection client limits are valid"))
        .build()
        .expect("four-connection client router plan must be valid");
    let peer: SocketAddr = "10.0.0.2:443"
        .parse()
        .expect("server test address must be valid");
    let local: SocketAddr = "10.0.0.1:50000"
        .parse()
        .expect("client test address must be valid");
    let started = Instant::now();
    let mut handles = Vec::new();
    for ordinal in 0..4u64 {
        handles.push(
            Count::connect(
                &mut client,
                peer,
                key,
                (ordinal + 1).to_be_bytes().to_vec(),
                started,
            )
            .expect("each fresh client connection must be accepted"),
        );
    }

    for turn in 0..12 {
        let now = started + Duration::from_millis(turn * 10);
        Count::relay_at(&mut client, &mut server, local, now).expect("CID relay_at");
        Count::relay_at(&mut server, &mut client, peer, now).expect("CID relay_at");
        if client.handler().established == 4 && server.handler().established == 4 {
            break;
        }
    }
    assert_eq!(client.handler().established, 4);
    assert_eq!(server.handler().established, 4);

    let mut seen = HashSet::new();
    for handle in server.handler().handles.iter().copied() {
        let conn = server
            .conn(handle)
            .expect("each established server handle must resolve");
        let cids = conn.view().path().local_cids();
        assert_eq!(cids.values().count(), 4);
        for cid in cids.values() {
            assert!(
                seen.insert(cid.to_vec()),
                "every live receive CID must own one exact mux route"
            );
        }
    }
    assert_eq!(seen.len(), 16);

    let data_at = started + Duration::from_secs(1);
    for (ordinal, handle) in handles.into_iter().enumerate() {
        Count::send(&mut client, handle, vec![ordinal as u8], data_at)
            .expect("each established client handle must queue its datagram");
    }
    for turn in 0..8 {
        let now = data_at + Duration::from_millis(turn * 10);
        Count::relay_at(&mut client, &mut server, local, now).expect("CID relay_at");
        Count::relay_at(&mut server, &mut client, peer, now).expect("CID relay_at");
        if server.handler().datagrams == 4 {
            break;
        }
    }
    assert_eq!(server.handler().datagrams, 4);
}
