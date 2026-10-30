use std::{
    cell::Cell,
    env,
    time::{Duration, Instant},
};

use dope_test::harness::support::file;

pub mod common;
use common::suite::openssl::{Identity, Peer, Server};

#[test]
#[ignore = "external: requires OpenSSL with QUIC support"]
fn verified_handshake() {
    let base = env::temp_dir();
    let cleanup = Cell::new(None);
    let root = file::Directory::try_with(&base, "quic-openssl", |result| cleanup.set(Some(result)))
        .expect("temporary path");
    let identity = Identity::new(root.path()).expect("OpenSSL identity");
    let mut server = Server::new(&identity).expect("QUIC server");
    let stopped = Cell::new(None);
    let mut peer = Peer::new(
        root.path(),
        server.addr().expect("bound address"),
        |result| stopped.set(Some(result)),
    )
    .expect("OpenSSL peer");
    let deadline = Instant::now() + Duration::from_secs(10);
    let handle = loop {
        server.poll().expect("QUIC progress");
        if let Some(handle) = server.router.handler().established.first().copied()
            && peer.verified().expect("verification diagnostic")
        {
            break handle;
        }
        assert!(
            Instant::now() < deadline,
            "OpenSSL handshake timeout: received={}, sent={}, peer={}",
            server.received,
            server.sent,
            peer.diagnostic().expect("peer diagnostic"),
        );
        assert!(
            peer.status().expect("peer status").is_none(),
            "OpenSSL exited before verification: {}",
            peer.diagnostic().expect("peer diagnostic")
        );
    };
    let conn = server.router.conn(handle).expect("established connection");
    assert!(conn.view().path().mtu() >= 1200);
    assert!(server.received > 0 && server.sent > 0);
    assert_eq!(server.router.handler().established.len(), 1);
    assert_eq!(server.router.handler().certificates, 0);
    drop(peer);
    stopped
        .take()
        .expect("child teardown observed")
        .expect("stop and reap OpenSSL");
    drop(root);
    cleanup
        .take()
        .expect("directory teardown observed")
        .expect("temporary directory removed");
}
