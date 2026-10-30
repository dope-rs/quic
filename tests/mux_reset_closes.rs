pub mod common;

use common::{
    peer,
    runtime::{
        Error,
        reap::{CLIENT, Capture, SERVER},
    },
};
use dope_quic::{
    conn::life::{accept::Authority, options::Options},
    proto::param,
    runtime::mux::{builder::Builder, manage},
};
use std::{net::SocketAddr, pin::Pin, time::Instant};

#[test]
fn reset_closes_match() -> Result<(), Error> {
    let wrong: SocketAddr = "10.0.0.3:443".parse().expect("unrelated test address");
    let (signing, key) = peer::raw(0x39).expect("raw identity");
    let source = signing.server().expect("server TLS");
    let tp = param::Set::builder()
        .idle_ms(30_000)
        .datagram(Some(65_535))
        .try_build();
    let tp = tp.expect("reap parameters");
    let server_h = Capture::default();
    let srv_opts = Options::builder()
        .transport(|net| net.params(tp.clone()))
        .security(|security| security.reset(Some([0xA5; 32])))
        .try_build();
    let srv_opts = (srv_opts).expect("fixture server options must be valid");
    let auth = Authority::new(source, srv_opts)
        .expect("test certificate source and options must form an authority");
    let mut server = Builder::server(server_h, auth)
        .build()
        .expect("test server router plan must be valid");
    let client_h = Capture::default();
    let cli_log = client_h.events.clone();
    let mut client = Builder::client(client_h)
        .build()
        .expect("test client router plan must be valid");
    let now = Instant::now();
    let handle = Capture::handshake(
        &mut server,
        &mut client,
        key,
        tp.clone(),
        SERVER,
        CLIENT,
        now,
    )?;
    let token = client
        .conn(handle)
        .and_then(|conn| conn.view().peer().params())
        .and_then(|params| params.identity().reset())
        .expect("server stateless reset token");
    let mut reset = vec![0; 30];
    reset[0] = 0x40;
    reset[1..9].copy_from_slice(&[0xA7; 8]);
    let tail = reset.len() - 16;
    reset[tail..].copy_from_slice(&token);

    assert!(
        Capture::receive(&mut client, wrong, &mut reset, now).is_ok(),
        "client must process unrelated reset"
    );
    assert!(
        client
            .conn(handle)
            .is_some_and(|conn| conn.view().lifecycle().is_ready()),
        "a token received from an unrelated address must be ignored",
    );

    assert!(
        Capture::receive(&mut client, SERVER, &mut reset, now).is_ok(),
        "client must process matching reset"
    );
    assert!(
        client
            .conn(handle)
            .is_some_and(|conn| conn.view().path().is_reset()),
        "the mux must route an unknown-DCID reset to the matching connection",
    );
    assert!(
        client
            .conn(handle)
            .is_some_and(|conn| conn.view().lifecycle().is_closed())
    );

    Capture::drive(&mut client, now).map_err(Error::Output)?;
    assert!(client.conn(handle).is_none());
    assert!(cli_log.borrow().closed == vec![handle]);

    let remote = server.sole().expect("single server connection");
    Capture::close(&mut server, remote, now).expect("close the first server connection");
    let retained = Capture::handshake(&mut server, &mut client, key, tp, SERVER, CLIENT, now)?;
    let conn = client.conn(retained).expect("reconnected client");
    assert!(conn.view().lifecycle().is_ready());
    assert!(
        conn.view()
            .peer()
            .params()
            .and_then(|params| params.identity().reset())
            .is_some()
    );
    assert!((0..=u16::MAX).any(|_| {
        Pin::new(&mut client).observe(now, |mut turn| turn.lifecycle().advance())
            == manage::Status::Complete
    }));
    assert!(client.conn(retained).is_none());
    assert!(cli_log.borrow().closed == vec![handle, retained]);
    assert!(!client.handler().events.borrow().release_after_close);
    assert!(!server.handler().events.borrow().release_after_close);
    Ok(())
}
