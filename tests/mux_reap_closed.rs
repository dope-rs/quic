pub mod support;

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dope_quic::conn::Handle;
use dope_quic::{Handler, Mux, TrySendError, conn, conn::session::Connection, transport_params};

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];

#[derive(Default)]
struct Events {
    established: Vec<Handle>,
    datagrams: Vec<(Handle, Vec<u8>)>,
    closed: Vec<Handle>,
}

#[derive(Clone, Default)]
struct CapturingHandler {
    events: Rc<RefCell<Events>>,
}

impl Handler<0> for CapturingHandler {
    type Connection = ();

    fn create_connection(&mut self, _conn: &mut Connection, _handle: Handle) {}

    fn established(&mut self, _connection: &mut (), _conn: &mut Connection, h: Handle) {
        self.events.borrow_mut().established.push(h);
    }
    fn datagram(&mut self, _connection: &mut (), _conn: &mut Connection, h: Handle, data: Vec<u8>) {
        self.events.borrow_mut().datagrams.push((h, data.to_vec()));
    }
    fn close(&mut self, _connection: (), h: Handle) {
        self.events.borrow_mut().closed.push(h);
    }
}

fn relay_once(
    src: &mut Mux<CapturingHandler>,
    dst: &mut Mux<CapturingHandler>,
    src_addr: SocketAddr,
    now: Instant,
) -> usize {
    let pkts: Vec<_> = src.output().drain().collect();
    let n = pkts.len();
    for mut out in pkts {
        dst.protocol()
            .recv(src_addr, out.payload_mut(), now)
            .expect("recv");
    }
    n
}

struct Pair {
    server: Mux<CapturingHandler>,
    server_events: Rc<RefCell<Events>>,
    client: Mux<CapturingHandler>,
    client_events: Rc<RefCell<Events>>,
    server_pubkey: [u8; 32],
    params: transport_params::Params,
}

fn build_pair(idle_ms: u64) -> Pair {
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();

    let tp = transport_params::Params {
        max_idle_timeout_ms: idle_ms,
        max_datagram_frame_size: Some(65535),
        ..transport_params::Params::default()
    };

    let server_h = CapturingHandler::default();
    let server_events = server_h.events.clone();
    let server =
        dope_quic::mux::setup::Server::accept(server_h, signing, tp.clone().into()).unwrap();

    let client_h = CapturingHandler::default();
    let client_events = client_h.events.clone();
    let client = dope_quic::mux::setup::Client::new(client_h)
        .build()
        .unwrap();

    Pair {
        server,
        server_events,
        client,
        client_events,
        server_pubkey,
        params: tp,
    }
}

fn complete_handshake(
    server: &mut Mux<CapturingHandler>,
    client: &mut Mux<CapturingHandler>,
    server_pubkey: [u8; 32],
    tp: transport_params::Params,
    server_addr: SocketAddr,
    client_addr: SocketAddr,
    now: Instant,
) -> Handle {
    let client_handle = client
        .protocol()
        .connect(server_addr, server_pubkey, tp.into(), CID.to_vec(), now)
        .unwrap();
    relay_once(client, server, client_addr, now);
    relay_once(server, client, server_addr, now);
    relay_once(client, server, client_addr, now);
    server.output().drive_bounded(now);
    client.output().drive_bounded(now);
    client_handle
}

#[test]
fn idle_timeout_fires_close_via_reap() {
    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();
    let Pair {
        mut server,
        server_events,
        mut client,
        client_events,
        server_pubkey,
        params: tp,
    } = build_pair(50);

    let t0 = Instant::now();
    let _ = complete_handshake(
        &mut server,
        &mut client,
        server_pubkey,
        tp,
        server_addr,
        client_addr,
        t0,
    );
    assert_eq!(server_events.borrow().established.len(), 1);
    assert_eq!(client_events.borrow().established.len(), 1);

    let t_past = t0 + Duration::from_millis(150);
    server.output().drive_bounded(t_past);
    client.output().drive_bounded(t_past);

    assert_eq!(
        server_events.borrow().closed.len(),
        1,
        "server must fire close exactly once",
    );
    assert_eq!(
        client_events.borrow().closed.len(),
        1,
        "client must fire close exactly once",
    );
}

#[test]
fn unknown_dcid_stateless_reset_closes_matching_mux_connection() {
    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();
    let wrong_addr: SocketAddr = "10.0.0.3:443".parse().unwrap();
    let signing = support::signing_key(0x39);
    let server_pubkey = *signing.pubkey().unwrap();
    let tp = transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(65_535),
        ..transport_params::Params::default()
    };
    let server_h = CapturingHandler::default();
    let mut server = dope_quic::mux::setup::Server::accept(
        server_h,
        signing,
        conn::config::Options {
            transport_params: tp.clone(),
            stateless_reset_secret: Some([0xA5; 32]),
            ..conn::config::Options::default()
        },
    )
    .unwrap();
    let client_h = CapturingHandler::default();
    let client_events = client_h.events.clone();
    let mut client = dope_quic::mux::setup::Client::new(client_h)
        .build()
        .unwrap();
    let now = Instant::now();
    let handle = complete_handshake(
        &mut server,
        &mut client,
        server_pubkey,
        tp,
        server_addr,
        client_addr,
        now,
    );
    let token = client
        .conn(handle)
        .and_then(|connection| connection.status().peer_transport_params())
        .and_then(|params| params.stateless_reset_token)
        .expect("server stateless reset token");
    let mut reset = vec![0x40; 30];
    reset[1..9].copy_from_slice(&[0xA7; 8]);
    let tail = reset.len() - 16;
    reset[tail..].copy_from_slice(&token);

    client.protocol().recv(wrong_addr, &mut reset, now).unwrap();
    assert!(
        client
            .conn(handle)
            .is_some_and(|connection| connection.status().is_established()),
        "a token received from an unrelated address must be ignored",
    );

    client
        .protocol()
        .recv(server_addr, &mut reset, now)
        .unwrap();
    assert!(
        client
            .conn(handle)
            .is_some_and(|connection| connection.status().was_stateless_reset()),
        "the mux must route an unknown-DCID reset to the matching connection",
    );
    assert!(
        client
            .conn(handle)
            .is_some_and(|connection| connection.status().is_closed())
    );

    client.output().drive_bounded(now);
    assert!(client.conn(handle).is_none());
    assert_eq!(client_events.borrow().closed, vec![handle]);
}

#[test]
fn reap_is_idempotent() {
    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();
    let Pair {
        mut server,
        server_events,
        mut client,
        client_events: _,
        server_pubkey,
        params: tp,
    } = build_pair(50);

    let t0 = Instant::now();
    let _ = complete_handshake(
        &mut server,
        &mut client,
        server_pubkey,
        tp,
        server_addr,
        client_addr,
        t0,
    );

    let t_past = t0 + Duration::from_millis(200);
    server.output().drive_bounded(t_past);
    server.output().drive_bounded(t_past);
    server
        .output()
        .drive_bounded(t_past + Duration::from_millis(100));

    assert_eq!(
        server_events.borrow().closed.len(),
        1,
        "subsequent reaps must not double-fire close",
    );
}

#[test]
fn active_conn_is_not_reaped() {
    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();
    let Pair {
        mut server,
        server_events,
        mut client,
        client_events: _,
        server_pubkey,
        params: tp,
    } = build_pair(100);

    let t0 = Instant::now();
    let client_handle = complete_handshake(
        &mut server,
        &mut client,
        server_pubkey,
        tp,
        server_addr,
        client_addr,
        t0,
    );

    let t1 = t0 + Duration::from_millis(80);
    client
        .protocol()
        .try_send_datagram(client_handle, b"keepalive".to_vec(), t1)
        .unwrap();
    relay_once(&mut client, &mut server, client_addr, t1);

    let t2 = t1 + Duration::from_millis(50);
    server.output().drive_bounded(t2);
    client.output().drive_bounded(t2);

    assert!(
        server_events.borrow().closed.is_empty(),
        "active server conn must not be reaped",
    );
}

#[test]
fn explicit_close_then_reap_does_not_double_fire() {
    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();
    let Pair {
        mut server,
        server_events: _,
        mut client,
        client_events,
        server_pubkey,
        params: tp,
    } = build_pair(30_000);

    let t0 = Instant::now();
    let client_handle = complete_handshake(
        &mut server,
        &mut client,
        server_pubkey,
        tp,
        server_addr,
        client_addr,
        t0,
    );

    client.protocol().close(client_handle);
    assert_eq!(client_events.borrow().closed.len(), 1);

    client.output().drive_bounded(t0);
    assert_eq!(
        client_events.borrow().closed.len(),
        1,
        "reap after explicit close must be a no-op",
    );
}

#[test]
fn pto_deadline_retransmits_without_external_io_completion() {
    let mut client = dope_quic::mux::setup::Client::new(CapturingHandler::default())
        .build()
        .unwrap();
    let t0 = Instant::now();
    client
        .protocol()
        .connect(
            "10.0.0.2:443".parse().unwrap(),
            [7; 32],
            dope_quic::conn::config::Options::default(),
            CID.to_vec(),
            t0,
        )
        .unwrap();
    assert_eq!(client.output().drain().count(), 1);
    let deadline = client.next_deadline(t0).expect("PTO deadline");
    assert!(deadline > t0);
    client
        .output()
        .drive_bounded(deadline + Duration::from_millis(1));
    assert!(!client.output().is_empty());
}

#[test]
fn peer_connection_close_makes_reap_fire_close() {
    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();
    let Pair {
        mut server,
        server_events,
        mut client,
        client_events,
        server_pubkey,
        params: tp,
    } = build_pair(30_000);

    let t0 = Instant::now();
    let _ = complete_handshake(
        &mut server,
        &mut client,
        server_pubkey,
        tp,
        server_addr,
        client_addr,
        t0,
    );

    let h0 = Handle(0);
    if let Some(mut conn) = client.protocol().conn_mut(h0) {
        conn.close(0, b"client-side close".to_vec());
    }

    client.output().drive_bounded(t0);
    assert_eq!(
        client_events.borrow().closed.len(),
        1,
        "client must surface its own close exactly once",
    );

    relay_once(&mut client, &mut server, client_addr, t0);

    server.output().drive_bounded(t0);
    assert_eq!(
        server_events.borrow().closed.len(),
        1,
        "peer CONNECTION_CLOSE → reap fires close on server",
    );
}

#[test]
fn recycled_slot_rejects_stale_generation_handle() {
    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();
    let Pair {
        mut server,
        server_events: _,
        mut client,
        client_events: _,
        server_pubkey,
        params: tp,
    } = build_pair(50);

    let t0 = Instant::now();
    let h0 = complete_handshake(
        &mut server,
        &mut client,
        server_pubkey,
        tp.clone(),
        server_addr,
        client_addr,
        t0,
    );

    let t_past = t0 + Duration::from_millis(200);
    client.output().drive_bounded(t_past);

    let mut alt_cid = CID;
    alt_cid[0] = 0x99;
    let h1 = client
        .protocol()
        .connect(
            server_addr,
            server_pubkey,
            tp.into(),
            alt_cid.to_vec(),
            t_past,
        )
        .unwrap();
    assert_eq!(h0.0 as u32, h1.0 as u32);
    assert_ne!(h0, h1);
    assert!(client.protocol().conn_mut(h0).is_none());
    assert_eq!(
        client
            .protocol()
            .try_send_datagram(h0, b"stale".to_vec(), t_past),
        Err(TrySendError::Closed(b"stale".to_vec()))
    );
    client.protocol().flush(h0, t_past);
    client.protocol().close(h0);
    assert!(client.protocol().conn_mut(h1).is_some());
    assert_eq!(client.active_conns(), 1);
}

#[test]
fn forgotten_connection_guard_is_reconciled_on_the_next_exclusive_borrow() {
    let mut client = dope_quic::mux::setup::Client::new(CapturingHandler::default())
        .build()
        .unwrap();
    let now = Instant::now();
    let handle = client
        .protocol()
        .connect(
            "10.0.0.2:443".parse().unwrap(),
            [7; 32],
            conn::config::Options::default(),
            CID.to_vec(),
            now,
        )
        .unwrap();

    let guard = client.protocol().conn_mut(handle).unwrap();
    std::mem::forget(guard);

    assert!(client.protocol().conn_mut(handle).is_some());
    client.protocol().close(handle);
    assert_eq!(client.active_conns(), 0);
}

#[test]
fn shutdown_retires_connections_deadlines_and_outgoing() {
    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();
    let Pair {
        mut server,
        server_events: _,
        mut client,
        client_events,
        server_pubkey,
        params,
    } = build_pair(30_000);

    let now = Instant::now();
    let client_handle = complete_handshake(
        &mut server,
        &mut client,
        server_pubkey,
        params,
        server_addr,
        client_addr,
        now,
    );
    assert_eq!(client.active_conns(), 1);
    assert!(client.next_deadline(now).is_some());

    let mut shutdown_turns = 1;
    while !client.lifecycle().bounded() {
        shutdown_turns += 1;
    }

    assert!(
        shutdown_turns > 1,
        "shutdown unexpectedly drained the arena in one turn"
    );
    assert_eq!(client.active_conns(), 0);
    assert_eq!(client.output().len(), 0);
    assert_eq!(client.output().bytes(), 0);
    assert_eq!(client.next_deadline(now), None);
    assert_eq!(client_events.borrow().closed.len(), 1);
    assert!(client.protocol().conn_mut(client_handle).is_none());
    assert_eq!(
        client
            .protocol()
            .try_send_datagram(client_handle, b"late".to_vec(), now),
        Err(TrySendError::Closed(b"late".to_vec()))
    );
    assert_eq!(
        client.protocol().connect(
            server_addr,
            server_pubkey,
            conn::config::Options::default(),
            CID.to_vec(),
            now,
        ),
        Err(dope_quic::ConnectError::Closed)
    );
    assert!(client.output().drain().next().is_none());
}
