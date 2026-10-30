use crate::common::peer;
pub mod common;

use common::suite::mux::pinned::{self, Capture, Counts};
use common::suite::peers::tls;
use dope_quic::conn::life::{accept, options::Options};
use dope_quic::proto::param;
use dope_quic::runtime::mux::{
    self,
    builder::{Builder, Plan},
};
use dope_test::harness::observe::VecCellExt as _;
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

#[test]
fn pin_keeps_address() {
    let local = Counts::default();
    let peer = Counts::default();
    let (signing, key) = peer::raw(0x51).expect("fixture server identity");
    let config = signing.server().expect("fixture server TLS configuration");
    let auth = tls::client(key).expect("fixture client authority");
    let params = param::Set::builder()
        .idle_ms(30_000)
        .datagram(Some(65_535))
        .try_build()
        .expect("fixture transport parameters");
    let cli_hook = Capture::new(&local);
    let srv_hook = Capture::new(&peer);
    let limits = (Plan::try_new(1, 8, 16 << 10)).expect("lifetime fixture limits must be valid");
    let client = (Builder::client(cli_hook).limits(limits).build())
        .expect("the borrowed client handler must build");
    let server = (accept::Authority::new(
        config,
        Options::try_from(params.clone()).expect("fixture connection options"),
    ))
    .expect("the fixture server authority must be valid");
    let server = (Builder::server(srv_hook, server).limits(limits).build())
        .expect("the borrowed server handler must build");
    let mut client = Box::pin(client);
    let mut server = Box::pin(server);
    let cli_addr = SocketAddr::from(([127, 0, 0, 1], 50_000));
    let srv_addr = SocketAddr::from(([127, 0, 0, 1], 443));
    let mut now = Instant::now();
    let handle = client.as_mut().observe(now, |mut turn| {
        turn.protocol().connect(
            srv_addr,
            &auth,
            Options::try_from(params).expect("fixture connection options"),
            vec![0x42; 8],
        )
    });
    let handle = handle.expect("the borrowed handler must create its connection");

    for _ in 0..12 {
        pinned::relay(client.as_mut(), server.as_mut(), cli_addr, now).expect("client relay");
        pinned::relay(server.as_mut(), client.as_mut(), srv_addr, now).expect("server relay");
        now += Duration::from_millis(10);
        if local.ready.len() == 1 && peer.ready.len() == 1 {
            break;
        }
    }
    assert_eq!(local.created.get(), 1);
    assert_eq!(peer.created.get(), 1);
    for counts in [&local, &peer] {
        let ready = counts.ready.take();
        assert_eq!(ready, [0]);
        counts.ready.set(ready);
    }

    let sent = client.as_mut().observe(now, |mut turn| {
        turn.protocol().try_datagram(handle, b"pinned e2e".to_vec())
    });
    assert!(
        sent.is_ok(),
        "the retained connection must admit its datagram"
    );
    for _ in 0..64 {
        pinned::relay(client.as_mut(), server.as_mut(), cli_addr, now).expect("datagram relay");
        if peer.bytes.len() == 1 {
            break;
        }
        now += Duration::from_millis(10);
    }
    assert_eq!(peer.bytes.len(), 1);

    assert_eq!(
        client
            .as_mut()
            .observe(now, |mut turn| turn.protocol().try_close(handle)),
        Ok(())
    );
    for (trace, expected) in [(&local.shutting, (1, 0)), (&local.retired, (2, 1))] {
        let values = trace.take();
        assert_eq!(values, [expected]);
        trace.set(values);
    }
    assert!(
        server
            .as_mut()
            .observe(now, |mut turn| turn.lifecycle().advance())
            == mux::manage::Status::Complete
    );
    assert_eq!(peer.shutting.take(), [(1, 0)]);
    assert_eq!(peer.retired.take(), [(2, 1)]);
    assert_eq!(local.certificates.get(), 0);
    assert_eq!(peer.certificates.get(), 0);
    for counts in [&local, &peer] {
        let sites = counts.sites.take();
        let first = sites.first().expect("handler observed");
        assert!(sites.iter().all(|site| site == first));
        assert_eq!(counts.ready.take(), [0]);
        assert!(counts.bytes.take().iter().all(|data| data == b"pinned e2e"));
    }
}
