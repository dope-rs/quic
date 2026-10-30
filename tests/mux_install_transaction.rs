use crate::common::peer;
pub mod common;

use common::suite::mux::install::{self, Counter};
use common::suite::peers::tls;
use dope_quic::conn::life::{accept, options::Options};
use dope_quic::errors;
use dope_quic::proto::param;
use dope_quic::runtime::mux::{builder::Builder, manage::config::ResizeError, router};
use dope_quic::wire::packet::long::initial;
use std::{mem, net::SocketAddr, pin::Pin, time::Instant};

#[test]
fn installs_then_rebinds() {
    let mut mux = install::server().expect("install server");
    let peer: SocketAddr = "127.0.0.1:51000"
        .parse()
        .expect("fixed peer address must parse");
    let now = Instant::now();
    let dcid = [0x31; 8];
    let scid = [0x42; 8];

    install::admit(&mut mux, peer, &dcid, &scid, now).expect("install admit");
    let first = mux
        .sole()
        .expect("first Initial must install one connection");
    assert_eq!(mux.handler().created, 1);

    install::admit(&mut mux, peer, &dcid, &scid, now).expect("install admit");
    assert!(mux.sole() == Some(first));
    assert_eq!(mux.handler().created, 1);

    assert_eq!(install::close(&mut mux, first, now), Ok(()));
    assert_eq!(mux.active_conns(), 0);
    assert!(mux.conn(first).is_none());

    install::admit(&mut mux, peer, &dcid, &scid, now).expect("install admit");
    let second = mux
        .sole()
        .expect("retired generation must admit a replacement");
    assert!(second != first);
    assert_eq!(mux.handler().created, 2);
}

#[test]
fn rejects_foreign_close() {
    let mut muxes = [
        install::server().expect("first server"),
        install::server().expect("second server"),
    ];
    let peer: SocketAddr = "127.0.0.1:51001".parse().expect("peer address");
    let now = Instant::now();
    for mux in &mut muxes {
        install::admit(mux, peer, &[0x31; 8], &[0x42; 8], now).expect("install admit");
    }
    let first = muxes[0].sole().expect("first connection");
    let second = muxes[1].sole().expect("second connection");
    assert_eq!(first.position(), second.position());
    assert_eq!(first.generation(), second.generation());
    assert_ne!(first.domain(), second.domain());

    assert_eq!(
        install::close(&mut muxes[0], second, now),
        Err(errors::Access::InvalidHandle)
    );
    for (mux, handle) in muxes.iter_mut().zip([first, second]) {
        assert_eq!(mux.active_conns(), 1);
        assert!(mux.handler().closed.is_empty());
        install::admit(mux, peer, &[0x31; 8], &[0x42; 8], now).expect("same Initial");
        assert_eq!(mux.sole(), Some(handle));
        assert_eq!(mux.handler().created, 1);
        assert_eq!(install::close(mux, handle, now), Ok(()));
        assert_eq!(mux.handler().closed.as_slice(), &[handle]);
        assert_eq!(mux.active_conns(), 0);
    }
}

#[test]
fn resize_preserves_epochs() {
    let mut mux = install::server().expect("install server");
    let peer: SocketAddr = "127.0.0.1:51002".parse().expect("peer address");
    let now = Instant::now();
    for (stage, capacity) in [4, 1, 4].into_iter().enumerate() {
        assert!(Pin::new(&mut mux).config().try_resize(capacity).is_ok());
        let old = mux.handler().handles.clone();
        for ordinal in 0..capacity as u8 {
            install::admit(
                &mut mux,
                peer,
                &[0x50, ordinal, 2, 3, 4, 5, 6, 7],
                &[0x60, ordinal, 9, 10, 11, 12, 13, 14],
                now,
            )
            .expect("install after resize");
        }
        let added = mux.handler().handles[old.len()..].to_vec();
        assert_eq!(added.len(), capacity);
        if stage == 0 {
            assert!(matches!(
                Pin::new(&mut mux).config().try_resize(1),
                Err(ResizeError::Active { actual }) if actual.get() == 4
            ));
        }
        if capacity == 1 {
            assert_eq!(added[0].index(), 0);
            let mut packet = install::initial(
                &[0x50, 1, 2, 3, 4, 5, 6, 7],
                &[0x60, 1, 9, 10, 11, 12, 13, 14],
            )
            .expect("inactive suffix Initial");
            install::receive(&mut mux, peer, &mut packet, now)
                .expect("full prefix drops a new Initial");
            assert_eq!(mux.sole(), Some(added[0]));
            assert_eq!(mux.handler().created, old.len() + 1);
        }
        for handle in old {
            assert_eq!(
                install::close(&mut mux, handle, now),
                Err(errors::Access::InvalidHandle)
            );
        }
        assert_eq!(mux.active_conns(), capacity);
        for handle in added {
            assert_eq!(install::close(&mut mux, handle, now), Ok(()));
        }
        assert_eq!(mux.active_conns(), 0);
        assert_eq!(
            mux.handler().closed.as_slice(),
            mux.handler().handles.as_slice()
        );
    }
}

#[test]
fn closes_all_generations() {
    let mut mux = install::server().expect("install server");
    assert!(
        Pin::new(&mut mux).config().try_resize(4).is_ok(),
        "resize fixture mux to four entries"
    );
    let now = Instant::now();

    for ordinal in 0_u8..4 {
        let peer: SocketAddr = format!("127.0.0.1:{}", 52_000 + u16::from(ordinal))
            .parse()
            .expect("generated peer address must parse");
        install::admit(
            &mut mux,
            peer,
            &[0x50, ordinal, 2, 3, 4, 5, 6, 7],
            &[0x60, ordinal, 9, 10, 11, 12, 13, 14],
            now,
        )
        .expect("install admit");
    }
    assert_eq!(mux.active_conns(), 4);
    let first = mux.handler().handles.clone();

    assert_eq!(install::close(&mut mux, first[1], now), Ok(()));
    assert_eq!(install::close(&mut mux, first[3], now), Ok(()));
    assert_eq!(mux.active_conns(), 2);

    for ordinal in 4_u8..6 {
        let peer: SocketAddr = format!("127.0.0.1:{}", 52_000 + u16::from(ordinal))
            .parse()
            .expect("generated peer address must parse");
        install::admit(
            &mut mux,
            peer,
            &[0x50, ordinal, 2, 3, 4, 5, 6, 7],
            &[0x60, ordinal, 9, 10, 11, 12, 13, 14],
            now,
        )
        .expect("install admit");
    }
    assert_eq!(mux.active_conns(), 4);
    let created = mux.handler().handles.clone();
    assert_eq!(created.len(), 6);
    assert!(created[4..].iter().all(|new| !first.contains(new)));
    assert!(
        created[4..]
            .iter()
            .all(|new| { new.index() == first[1].index() || new.index() == first[3].index() })
    );

    Pin::new(&mut mux).observe(now, |turn| {
        assert!(matches!(turn.try_quiesce(), Err(router::observed::Open)));
    });
    assert_eq!(mux.active_conns(), 4);
    Pin::new(&mut mux).observe(now, |turn| {
        let size = mem::size_of_val(&turn);
        let mut sealed = turn.seal();
        assert_eq!(mem::size_of_val(&sealed), size);
        assert_eq!(sealed.close_all(), 4);
        assert_eq!(sealed.close_all(), 0);
    });
    assert_eq!(mux.active_conns(), 0);
    assert_eq!(mux.handler().closed.len(), 6);
    for handle in created {
        assert_eq!(
            mux.handler()
                .closed
                .iter()
                .filter(|closed| **closed == handle)
                .count(),
            1,
            "each installed generation closes exactly once"
        );
    }

    Pin::new(&mut mux).observe(now, |turn| {
        let mut sealed = turn
            .try_quiesce()
            .ok()
            .expect("sealed admission remains closed");
        assert_eq!(sealed.close_all(), 0);
    });
    assert_eq!(
        install::close(&mut mux, first[1], now),
        Err(errors::Access::InvalidHandle)
    );
    assert_eq!(
        install::close(&mut mux, first[3], now),
        Err(errors::Access::InvalidHandle)
    );

    let peer: SocketAddr = "127.0.0.1:52999"
        .parse()
        .expect("fixed peer address must parse");
    assert!(
        install::receive(
            &mut mux,
            peer,
            &mut install::initial(&[0x70; 8], &[0x71; 8]).expect("install initial"),
            now
        )
        .is_ok()
    );
    assert_eq!(mux.active_conns(), 0);
    assert_eq!(mux.handler().created, 6);
}

/// Admission excludes the first CID formerly generated by a fresh mux.
/// A retransmission through the client-selected alias retains its generation.
#[test]
fn excludes_initial_alias() {
    let mut mux = install::server().expect("install server");
    let peer: SocketAddr = "127.0.0.1:53000"
        .parse()
        .expect("fixed peer address must parse");
    let now = Instant::now();

    let dcid = [1_u8, 1, 2, 3, 4, 5, 6, 7];
    let scid = [0x91_u8; 8];

    install::admit(&mut mux, peer, &dcid, &scid, now).expect("install admit");

    let handle = mux.sole().expect("the Initial must install one connection");
    assert_eq!(mux.handler().created, 1);

    let cids: Vec<Vec<u8>> = mux
        .conn(handle)
        .expect("installed connection must remain live")
        .view()
        .path()
        .local_cids()
        .values()
        .map(<[u8]>::to_vec)
        .collect();

    assert_eq!(cids.len(), 1);
    assert!(
        cids.iter().all(|cid| cid.as_slice() != dcid.as_slice()),
        "the TLS-bound server CID must exclude the incoming Initial DCID"
    );

    install::admit(&mut mux, peer, &dcid, &scid, now).expect("install admit");

    assert!(mux.sole() == Some(handle));
    assert_eq!(mux.handler().created, 1);
}

#[test]
fn shares_server_cid() {
    let (signing, pubkey) = peer::raw(0x7a).expect("server signing key");
    let config = signing.server().expect("server TLS configuration");
    let srv_opts = Options::builder()
        .transport(|cfg| cfg.params(param::Set::default()))
        .security(|security| security.reset(Some([0x5c; 32])))
        .try_build();
    let srv_opts = (srv_opts).expect("fixture server options must be valid");
    let cli_opts = Options::try_from(param::Set::default()).expect("fixture connection options");
    let auth =
        accept::Authority::new(config, srv_opts).expect("fixed test authority must be valid");
    let mut server = Builder::server(Counter::default(), auth)
        .build()
        .expect("test server must build");
    let mut client = Builder::client(Counter::default())
        .build()
        .expect("test client must build");
    let srv_addr: SocketAddr = "127.0.0.1:443"
        .parse()
        .expect("fixed server address must parse");
    let cli_addr: SocketAddr = "127.0.0.1:53001"
        .parse()
        .expect("fixed client address must parse");
    let now = Instant::now();
    let dcid = [1_u8, 1, 2, 3, 4, 5, 6, 7];
    let auth = tls::client(pubkey).expect("client TLS authority");
    let cli = Pin::new(&mut client)
        .observe(now, |mut turn| {
            turn.protocol()
                .connect(srv_addr, &auth, cli_opts, dcid.to_vec())
        })
        .expect("client connection must install");

    install::transfer(&mut client, &mut server, cli_addr, now).expect("install transfer");
    let flight = install::relay(&mut server, &mut client, srv_addr, now).expect("install relay");
    let scid = flight
        .iter()
        .find_map(|wire| {
            initial::Prefix::decode(wire)
                .ok()
                .map(|header| header.scid.into_owned())
        })
        .expect("server must emit an Initial flight")
        .as_slice()
        .to_vec();

    assert_ne!(scid.as_slice(), dcid.as_slice());

    for _ in 0..5 {
        install::transfer(&mut client, &mut server, cli_addr, now).expect("install transfer");
        install::transfer(&mut server, &mut client, srv_addr, now).expect("install transfer");
    }

    let srv = server
        .sole()
        .expect("server connection must remain installed");
    let matched = server
        .conn(srv)
        .expect("server connection must remain live")
        .view()
        .path()
        .local_cids()
        .values()
        .any(|cid| cid == scid.as_slice());
    assert!(matched);

    let conn = client
        .conn(cli)
        .expect("client connection must remain live");
    assert!(conn.view().lifecycle().is_ready());
    assert!(
        server
            .conn(srv)
            .expect("server connection must remain live")
            .view()
            .lifecycle()
            .is_ready()
    );
    assert_eq!(
        conn.view()
            .peer()
            .params()
            .and_then(|params| params.identity().initial())
            .map(|cid| cid.as_slice()),
        Some(scid.as_slice())
    );
}
