pub mod common;
use crate::common::peer;
use std::time::{Duration, Instant};

use dope_quic::conn;
use dope_quic::wire::packet::cid;
use peer::Receiver as _;
use peer::{Config, Pair, sealer};
use rustls::crypto::aws_lc_rs::cipher_suite;

#[test]
fn retains_reordered_epoch() {
    for suite in [
        cipher_suite::TLS13_AES_128_GCM_SHA256,
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ] {
        let mut pair = Pair::try_config(
            Config::default().try_build().expect("server transport"),
            Config::default().try_build().expect("client transport"),
            cid::Id::try_from([0x71; 8]).expect("fixture connection ID"),
            |config, _| sealer::suite(config, suite).expect("native QUIC cipher suite"),
        )
        .expect("the peers must open");
        let mut now = Instant::now();
        pair.exchange(now, 6).expect("the peers must establish");
        let Pair {
            mut server,
            mut client,
            mut work,
        } = pair;
        assert!(client.view().lifecycle().is_confirmed(), "{suite:?}");
        assert!(server.view().lifecycle().is_confirmed(), "{suite:?}");

        server
            .with_scope(|mut scope| scope.datagrams().try_send(b"peer old phase".to_vec()))
            .expect("the peer's old-phase datagram must be admitted");
        now = server.view().recovery().send_at(now);
        let (mut peer_old, send_result) = server.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("the peer's old-phase datagram must enter a packet");
        assert_eq!(server.inspection().tx_queued(), 0);

        assert!(
            client
                .with_scope(|mut scope| scope.datagrams().try_send(b"old phase".to_vec()))
                .is_ok()
        );
        now = client.view().recovery().send_at(now);
        let (mut old, send_result) = client.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("the old-phase datagram must enter a packet");
        assert_eq!(client.inspection().tx_queued(), 0);
        assert!(
            client
                .with_scope(|mut scope| scope.security().at(now).update())
                .is_ok()
        );
        assert!(matches!(
            client.with_scope(|mut scope| scope.security().at(now).update()),
            Err(conn::Error::KeyUpdate),
        ));

        for packet in &mut peer_old {
            client
                .receive(&mut work, packet, now)
                .expect("local key update must retain the peer's previous generation");
        }
        assert_eq!(
            client
                .with_scope(|mut scope| scope.datagrams().recv())
                .as_deref(),
            Some(b"peer old phase".as_slice()),
        );

        assert!(
            client
                .with_scope(|mut scope| scope.datagrams().try_send(b"new phase".to_vec()))
                .is_ok()
        );
        now = client.view().recovery().send_at(now);
        assert!(server.receive_from(&mut work, &mut client, now).is_ok());
        assert_eq!(
            server
                .with_scope(|mut scope| scope.datagrams().recv())
                .as_deref(),
            Some(b"new phase".as_slice()),
        );
        for packet in &mut old {
            assert!(server.receive(&mut work, packet, now).is_ok());
        }
        assert_eq!(
            server
                .with_scope(|mut scope| scope.datagrams().recv())
                .as_deref(),
            Some(b"old phase".as_slice()),
        );

        assert!(
            server
                .with_scope(|mut scope| scope.datagrams().try_send(b"response phase".to_vec()))
                .is_ok()
        );
        now = server.view().recovery().send_at(now);
        assert!(client.receive_from(&mut work, &mut server, now).is_ok());
        assert_eq!(
            client
                .with_scope(|mut scope| scope.datagrams().recv())
                .as_deref(),
            Some(b"response phase".as_slice()),
        );

        let next = client
            .view()
            .recovery()
            .send_at(now + Duration::from_secs(10));
        assert!(
            client
                .with_scope(|mut scope| scope.security().at(next).update())
                .is_ok()
        );
        assert!(
            client
                .with_scope(|mut scope| scope.datagrams().try_send(b"second update".to_vec()))
                .is_ok()
        );
        assert!(server.receive_from(&mut work, &mut client, next).is_ok());
        assert_eq!(
            server
                .with_scope(|mut scope| scope.datagrams().recv())
                .as_deref(),
            Some(b"second update".as_slice()),
        );
    }
}
