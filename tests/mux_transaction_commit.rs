use crate::common::peer;
use dope_quic::conn::life::options::Options;
pub mod common;
use common::suite::peers::tls;
use common::suite::{mux::install, retry::Capture};

use dope_quic::conn::life::accept;
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::runtime::mux::builder::Plan;
use std::{pin::Pin, time::Instant};

use dope_quic::{errors::Code, proto::param};

#[test]
fn error_keeps_terminal() {
    let srv_addr = "127.0.0.1:443"
        .parse()
        .expect("test server address must be valid");
    let cli_addr = "127.0.0.1:50000"
        .parse()
        .expect("test client address must be valid");
    let (signing, key) = peer::raw(0x61).expect("server signing key");
    let config = signing.server().expect("server TLS configuration");
    let params = param::Set::default();
    let auth = accept::Authority::new(
        config,
        Options::try_from(params.clone()).expect("fixture connection options"),
    )
    .expect("test certificate source and options must form a server authority");
    let mut server = Builder::server(Capture { certificates: 0 }, auth)
        .build()
        .expect("default test server router plan must be valid");
    let mut client = Builder::client(Capture { certificates: 0 })
        .limits(Plan::try_new(1, 8, 16 << 10).expect("transaction fixture limits are valid"))
        .build()
        .expect("test client router plan must be valid");
    let now = Instant::now();
    let auth = tls::client(key).expect("client TLS authority");
    let handle = Pin::new(&mut client)
        .observe(now, |mut turn| {
            turn.protocol().connect(
                srv_addr,
                &auth,
                Options::try_from(params).expect("fixture connection options"),
                vec![0x51; 8],
            )
        })
        .expect("test peer, key, options, and CID must start a connection");
    install::forward(&mut client, &mut server, cli_addr, now).expect("install forward");
    install::forward(&mut server, &mut client, srv_addr, now).expect("install forward");
    install::forward(&mut client, &mut server, cli_addr, now).expect("install forward");
    Pin::new(&mut server).observe(now, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "fixture server connection must admit settled transaction output"
        );
    });
    Pin::new(&mut client).observe(now, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "fixture client connection must admit settled transaction output"
        );
    });
    assert!(
        client
            .conn(handle)
            .is_some_and(|conn| conn.view().lifecycle().is_ready())
    );

    let result = Pin::new(&mut client)
        .observe(now, |mut turn| {
            turn.protocol().with_conn(handle, |mut scope| {
                scope
                    .lifecycle()
                    .close(Code::from_u8(7), b"normal error".to_vec());
                Err::<(), u8>(7)
            })
        })
        .expect("established test handle must resolve in its owning router");

    assert_eq!(result, Err(7));
    let terminal = Pin::new(&mut client).observe(now, |mut turn| {
        assert!(
            turn.output().drive().is_ok(),
            "closed fixture connection must admit its terminal packet"
        );
        turn.output().drain().collect::<Vec<_>>()
    });
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0].packet_count().get(), 1);
}
