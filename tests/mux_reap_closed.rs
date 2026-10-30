use dope_quic::conn::life::options::Options;
use dope_quic::conn::stream::SendOutcome;
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::stream::release::Cause;
use dope_quic::stream::send;
use o3::buffer::storage;
pub mod common;
use common::runtime::{
    Error,
    reap::{CID, CLIENT, Capture, Pair, SERVER},
};
use dope_quic::{
    errors::{self, SendFailure},
    runtime::mux::manage,
};
use std::{
    pin::Pin,
    time::{Duration, Instant},
};
#[test]
fn idle_timeout_closes() -> Result<(), Error> {
    let Pair {
        mut server,
        srv_log,
        mut client,
        cli_log,
        key,
        params: tp,
    } = Capture::build_pair(50)?;

    let t0 = Instant::now();
    let handle = Capture::handshake(&mut server, &mut client, key, tp, SERVER, CLIENT, t0)?;
    assert_eq!(srv_log.borrow().established.len(), 1);
    assert!(cli_log.borrow().established == vec![handle]);

    let t_past = t0 + Duration::from_millis(150);
    Capture::drive(&mut server, t_past).map_err(Error::Output)?;
    Capture::drive(&mut client, t_past).map_err(Error::Output)?;

    assert_eq!(
        srv_log.borrow().closed.len(),
        1,
        "server must fire close exactly once",
    );
    assert_eq!(
        cli_log.borrow().closed.len(),
        1,
        "client must fire close exactly once",
    );
    assert!(!client.handler().events.borrow().release_after_close);
    assert!(!server.handler().events.borrow().release_after_close);
    Ok(())
}

#[test]
fn reap_is_idempotent() -> Result<(), Error> {
    let Pair {
        mut server,
        srv_log,
        mut client,
        cli_log: _,
        key,
        params: tp,
    } = Capture::build_pair(50)?;

    let t0 = Instant::now();
    let handle = Capture::handshake(&mut server, &mut client, key, tp, SERVER, CLIENT, t0)?;
    assert!(
        client.conn(handle).is_some(),
        "completed client handshake must retain its addressable handle",
    );

    let t_past = t0 + Duration::from_millis(200);
    Capture::drive(&mut server, t_past).map_err(Error::Output)?;
    Capture::drive(&mut server, t_past).map_err(Error::Output)?;
    Capture::drive(&mut server, t_past + Duration::from_millis(100)).map_err(Error::Output)?;

    assert_eq!(
        srv_log.borrow().closed.len(),
        1,
        "subsequent reaps must not double-fire close",
    );
    assert!(!client.handler().events.borrow().release_after_close);
    assert!(!server.handler().events.borrow().release_after_close);
    Ok(())
}

#[test]
fn active_is_not_reaped() -> Result<(), Error> {
    let Pair {
        mut server,
        srv_log,
        mut client,
        cli_log: _,
        key,
        params: tp,
    } = Capture::build_pair(100)?;

    let t0 = Instant::now();
    let handle = Capture::handshake(&mut server, &mut client, key, tp, SERVER, CLIENT, t0)?;

    let t1 = t0 + Duration::from_millis(80);
    Capture::send(&mut client, handle, b"keepalive".to_vec(), t1)
        .expect("established test connection must accept a keepalive DATAGRAM");
    Capture::relay_once(&mut client, &mut server, CLIENT, t1)?;

    let t2 = t1 + Duration::from_millis(50);
    Capture::drive(&mut server, t2).map_err(Error::Output)?;
    Capture::drive(&mut client, t2).map_err(Error::Output)?;

    assert!(
        srv_log.borrow().closed.is_empty(),
        "active server conn must not be reaped",
    );
    assert!(!client.handler().events.borrow().release_after_close);
    assert!(!server.handler().events.borrow().release_after_close);
    Ok(())
}

#[test]
fn explicit_close_is_once() -> Result<(), Error> {
    let Pair {
        mut server,
        srv_log: _,
        mut client,
        cli_log,
        key,
        params: tp,
    } = Capture::build_pair(30_000)?;

    let t0 = Instant::now();
    let handle = Capture::handshake(&mut server, &mut client, key, tp, SERVER, CLIENT, t0)?;

    assert_eq!(Capture::close(&mut client, handle, t0), Ok(()));
    assert_eq!(cli_log.borrow().closed.len(), 1);

    Capture::drive(&mut client, t0).map_err(Error::Output)?;
    assert_eq!(
        cli_log.borrow().closed.len(),
        1,
        "reap after explicit close must be a no-op",
    );
    assert!(!client.handler().events.borrow().release_after_close);
    assert!(!server.handler().events.borrow().release_after_close);
    Ok(())
}

#[test]
fn close_releases_owners() -> Result<(), Error> {
    let Pair {
        mut server,
        mut client,
        cli_log,
        key,
        params,
        ..
    } = Capture::build_pair(30_000)?;
    let now = Instant::now();
    let handle = Capture::handshake(&mut server, &mut client, key, params, SERVER, CLIENT, now)?;
    let stream = Capture::with_conn(&mut client, handle, now, |mut conn| {
        let mut streams = conn.streams();
        let mut send = streams.send();
        let stream = send.open_bidi().expect("stream");
        let body = storage::Shared::try_copy(b"retained").expect("body");
        assert!(matches!(
            send.try_buffer(stream.send(), send::Buffer::Retained(body)),
            SendOutcome::Accepted
        ));
        stream.id()
    })
    .expect("connection");
    Pin::new(&mut client).observe(now, |turn| {
        let mut sealed = turn.seal();
        assert_eq!(sealed.close_all(), 1);
        assert_eq!(sealed.close_all(), 0);
    });
    let events = cli_log.borrow();
    assert_eq!(events.released.len(), 1);
    let (owner, release) = &events.released[0];
    assert!(*owner == handle);
    assert_eq!(release.source.id(), stream);
    assert!(matches!(release.cause, Cause::Closed));
    assert_eq!(release.charge.logical_bytes, b"retained".len());
    assert_eq!(release.charge.owners, 1);
    assert!(events.closed == [handle]);
    assert!(!client.handler().events.borrow().release_after_close);
    assert!(!server.handler().events.borrow().release_after_close);
    Ok(())
}

#[test]
fn pto_retransmits() -> Result<(), Error> {
    let mut client = Builder::client(Capture::default())
        .build()
        .expect("default test client router plan must be valid");
    let t0 = Instant::now();
    Capture::connect(
        &mut client,
        SERVER,
        [7; 32],
        Options::default(),
        CID.to_vec(),
        t0,
    )
    .expect("test peer, key, options, and CID must start a connection");
    assert_eq!(
        Capture::output(&mut client, Instant::now())
            .map_err(Error::Output)?
            .len(),
        1
    );
    let deadline = Pin::new(&mut client)
        .observe(t0, |turn| turn.deadline())
        .expect("PTO deadline");
    assert!(deadline > t0);
    Capture::drive(&mut client, deadline + Duration::from_millis(1)).map_err(Error::Output)?;
    assert!(!Pin::new(&mut client).output().is_empty());
    assert!(!client.handler().events.borrow().release_after_close);
    Ok(())
}

#[test]
fn peer_close_reaps() -> Result<(), Error> {
    let Pair {
        mut server,
        srv_log,
        mut client,
        cli_log,
        key,
        params: tp,
    } = Capture::build_pair(30_000)?;

    let t0 = Instant::now();
    let h0 = Capture::handshake(&mut server, &mut client, key, tp, SERVER, CLIENT, t0)?;

    Capture::with_conn(&mut client, h0, t0, |mut scope| {
        scope
            .lifecycle()
            .close(errors::Code::ZERO, b"client-side close".to_vec())
    })
    .expect("established client handle must resolve in its owning router");

    Capture::drive(&mut client, t0).map_err(Error::Output)?;
    assert_eq!(
        cli_log.borrow().closed.len(),
        1,
        "client must surface its own close exactly once",
    );

    Capture::relay_once(&mut client, &mut server, CLIENT, t0)?;

    Capture::drive(&mut server, t0).map_err(Error::Output)?;
    assert_eq!(
        srv_log.borrow().closed.len(),
        1,
        "peer CONNECTION_CLOSE → reap fires close on server",
    );
    assert!(!client.handler().events.borrow().release_after_close);
    assert!(!server.handler().events.borrow().release_after_close);
    Ok(())
}

#[test]
fn stale_handle_rejected() -> Result<(), Error> {
    let Pair {
        mut server,
        srv_log: _,
        mut client,
        cli_log: _,
        key,
        params: tp,
    } = Capture::build_pair(50)?;

    let t0 = Instant::now();
    let h0 = Capture::handshake(
        &mut server,
        &mut client,
        key,
        tp.clone(),
        SERVER,
        CLIENT,
        t0,
    )?;

    let t_past = t0 + Duration::from_millis(200);
    Capture::drive(&mut client, t_past).map_err(Error::Output)?;

    let mut alt_cid = CID;
    alt_cid[0] = 0x99;
    let h1 = Capture::connect(
        &mut client,
        SERVER,
        key,
        Options::try_from(tp).expect("reap options"),
        alt_cid.to_vec(),
        t_past,
    )
    .expect("recycled test slot must accept the next connection");
    assert!(h0 != h1);
    assert!(client.conn(h0).is_none());
    assert_eq!(
        Capture::send(&mut client, h0, b"stale".to_vec(), t_past),
        Err(SendFailure::Closed(b"stale".to_vec()))
    );
    assert_eq!(
        Capture::close(&mut client, h0, t_past),
        Err(errors::Access::InvalidHandle)
    );
    assert!(client.conn(h1).is_some());
    assert_eq!(client.active_conns(), 1);
    assert!(!client.handler().events.borrow().release_after_close);
    assert!(!server.handler().events.borrow().release_after_close);
    Ok(())
}

#[test]
fn scope_commits() -> Result<(), Error> {
    let mut client = Builder::client(Capture::default())
        .build()
        .expect("default test client router plan must be valid");
    let now = Instant::now();
    let handle = Capture::connect(
        &mut client,
        SERVER,
        [7; 32],
        Options::default(),
        CID.to_vec(),
        now,
    )
    .expect("test peer, key, options, and CID must start a connection");

    Capture::with_conn(&mut client, handle, now, |mut scope| {
        scope
            .lifecycle()
            .close(errors::Code::ZERO, b"lexical-commit".to_vec());
    })
    .expect("new test handle must resolve in its owning router");

    assert!(client.conn(handle).is_some());
    Capture::drive(&mut client, now).map_err(Error::Output)?;
    assert!(
        !Pin::new(&mut client).output().is_empty(),
        "normal return must cross the lexical commit boundary"
    );
    assert!(client.conn(handle).is_none());
    assert!(client.handler().events.borrow().closed == vec![handle]);
    assert_eq!(
        Capture::close(&mut client, handle, now),
        Err(errors::Access::InvalidHandle)
    );
    assert_eq!(client.active_conns(), 0);
    assert!(!client.handler().events.borrow().release_after_close);
    Ok(())
}

#[test]
fn shutdown_retires() -> Result<(), Error> {
    let Pair {
        mut server,
        srv_log: _,
        mut client,
        cli_log,
        key,
        params,
    } = Capture::build_pair(30_000)?;

    let now = Instant::now();
    let handle = Capture::handshake(&mut server, &mut client, key, params, SERVER, CLIENT, now)?;
    assert_eq!(client.active_conns(), 1);
    assert!(
        Pin::new(&mut client)
            .observe(now, |turn| turn.deadline())
            .is_some()
    );

    let mut turns = 1;
    while Pin::new(&mut client).observe(Instant::now(), |mut turn| turn.lifecycle().advance())
        == manage::Status::Pending
    {
        turns += 1;
    }

    assert!(
        turns > 1,
        "shutdown unexpectedly drained the arena in one turn"
    );
    assert_eq!(client.active_conns(), 0);
    assert_eq!(Pin::new(&mut client).output().len(), 0);
    assert_eq!(Pin::new(&mut client).output().bytes(), 0);
    assert_eq!(
        Pin::new(&mut client).observe(now, |turn| turn.deadline()),
        None
    );
    assert_eq!(cli_log.borrow().closed.len(), 1);
    assert!(client.conn(handle).is_none());
    assert_eq!(
        Capture::send(&mut client, handle, b"late".to_vec(), now),
        Err(SendFailure::Closed(b"late".to_vec()))
    );
    assert!(matches!(
        Capture::connect(
            &mut client,
            SERVER,
            key,
            Options::default(),
            CID.to_vec(),
            now,
        ),
        Err(Error::Connect(errors::Connect::Closed))
    ));
    assert!(
        Capture::output(&mut client, Instant::now())
            .map_err(Error::Output)?
            .is_empty()
    );
    assert!(!client.handler().events.borrow().release_after_close);
    assert!(!server.handler().events.borrow().release_after_close);
    Ok(())
}
