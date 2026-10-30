pub mod common;

use common::peer::Receiver as _;
use common::runtime::{
    Error,
    reap::{CID, CLIENT, Capture, Credit, Pair, SERVER},
};
use common::suite::peers::life;
use dope_quic::{
    conn::{life::options::Options, wire::packet::Batch},
    errors::Code,
};
use std::{
    pin::Pin,
    time::{Duration, Instant},
};

#[test]
fn validation_follows_role() {
    let pair = life::try_pair(0).expect("anti-amplification fixture must open");
    assert!(!pair.server.view().path().is_valid());
    assert!(pair.client.view().path().is_valid());
}

#[test]
fn server_respects_limit() {
    let t0 = Instant::now();
    let (mut server, mut client, mut work) = life::try_pair(0)
        .expect("anti-amplification fixture must open")
        .into_parts();

    let (mut initial, send_result) = client.with_scope(|mut scope| scope.output().send(t0));
    send_result.expect("fresh client journals must admit its Initial");
    let saved = initial.clone();
    let recv: u64 = initial
        .iter_mut()
        .map(|p| {
            server
                .receive(&mut work, p, t0)
                .expect("server must receive the emitted client Initial");
            p.len() as u64
        })
        .sum();

    let mut response = Batch::default();
    server
        .with_scope(|mut scope| scope.output().send_batch(&mut response, t0, 2, 1200))
        .expect("fresh server journals must admit its anti-amplified response");
    assert_eq!(response.packets(), 2);
    let response: Vec<_> = response.iter().map(|packet| packet.to_vec()).collect();
    let sent: u64 = response.iter().map(|p| p.len() as u64).sum();

    assert_eq!(server.view().path().received(), recv);
    assert!(
        sent <= 3 * recv,
        "server emitted {sent} bytes vs allowance {}",
        3 * recv
    );
    assert!(!server.view().path().is_valid(), "still pre-validation");
    assert!(sent != 0, "the server must emit a protected response");
    let mut total = sent;
    let mut retries = 0;
    let mut blocked = false;
    let mut now = t0;
    for round in 0..16 {
        if let Some(deadline) = server.view().recovery().next_timer() {
            now = now.max(deadline) + Duration::from_millis(1);
            assert_eq!(
                server.with_scope(|mut scope| scope.recovery().try_loss(now)),
                Ok(())
            );
        }
        let (retry, send_result) = server.with_scope(|mut scope| scope.output().send(now));
        send_result.expect("loss recovery preserves amplification admission");
        retries += usize::from(!retry.is_empty());
        blocked |= retry.is_empty();
        total += retry.iter().map(|packet| packet.len() as u64).sum::<u64>();
        assert!(
            total <= 3 * recv,
            "unvalidated round {round} sent {total} bytes vs allowance {}",
            3 * recv
        );
        assert_eq!(server.view().path().received(), recv);
        assert!(!server.view().path().is_valid());
        if blocked {
            break;
        }
    }
    assert!(
        retries != 0,
        "PTO must retransmit within the available allowance"
    );
    assert!(blocked, "the exhausted allowance must suspend PTO output");
    if total == 3 * recv {
        server
            .receive(&mut work, &mut [0u8], now)
            .expect("one raw byte contributes insufficient positive credit");
    }
    assert!(total < 3 * server.view().path().received());
    for _ in 0..2 {
        assert_eq!(
            server.view().recovery().next_timer(),
            None,
            "insufficient positive credit must not retain a PTO deadline"
        );
        now += Duration::from_secs(24 * 60 * 60);
        assert_eq!(
            server.with_scope(|mut scope| scope.recovery().try_loss(now)),
            Ok(())
        );
        assert!(
            {
                let (emitted_packets, send_result) =
                    server.with_scope(|mut scope| scope.output().send(now));
                send_result.expect("blocked probes preserve their pending owners");
                emitted_packets
            }
            .is_empty()
        );
    }
    assert_eq!(server.view().recovery().next_timer(), None);
    let before = server.view().path().received();
    server
        .receive(&mut work, &mut [0u8; 1200], now)
        .expect("raw ingress restores credit without ACK or TLS changes");
    assert_eq!(server.view().path().received(), before + 1200);
    assert!(!server.view().path().is_valid());
    let due = server
        .view()
        .recovery()
        .next_timer()
        .expect("raw credit restores the retained PTO deadline");
    now = now.max(due) + Duration::from_millis(1);
    assert_eq!(
        server.with_scope(|mut scope| scope.recovery().try_loss(now)),
        Ok(())
    );
    let (raw, send_result) = server.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("raw ingress credit resumes protected output");
    assert!(!raw.is_empty());
    total += raw.iter().map(|packet| packet.len() as u64).sum::<u64>();
    let received = server.view().path().received();
    assert!(total <= 3 * received);
    now += Duration::from_millis(1);
    for mut packet in saved {
        server
            .receive(&mut work, &mut packet, now)
            .expect("a repeated Initial still contributes received datagram bytes");
    }
    assert_eq!(server.view().path().received(), received + recv);
    assert!(!server.view().path().is_valid());
    let due = server
        .view()
        .recovery()
        .next_timer()
        .expect("repeated Initial credit admits the next PTO");
    now = now.max(due) + Duration::from_millis(1);
    assert_eq!(
        server.with_scope(|mut scope| scope.recovery().try_loss(now)),
        Ok(())
    );
    let (resumed, send_result) = server.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("new ingress allowance admits the suspended PTO");
    assert!(!resumed.is_empty(), "new ingress credit must resume output");
    total += resumed
        .iter()
        .map(|packet| packet.len() as u64)
        .sum::<u64>();
    assert!(total <= 3 * server.view().path().received());
    for mut packet in response.into_iter().chain(raw).chain(resumed) {
        client
            .receive(&mut work, &mut packet, now)
            .expect("protected output remains decryptable after the allowance resumes");
    }
}

#[test]
fn close_waits_for_credit() -> Result<(), Error> {
    let Pair {
        mut server,
        mut client,
        srv_log,
        key,
        params,
        ..
    } = Capture::build_pair(0)?;
    let now = Instant::now();
    Capture::connect(
        &mut client,
        SERVER,
        key,
        Options::try_from(params).map_err(Error::Options)?,
        CID.to_vec(),
        now,
    )?;
    Capture::relay_once(&mut client, &mut server, CLIENT, now)?;
    let handle = server.sole().expect("one unvalidated server connection");
    let mut raw = [0u8; 1200];
    let cid = server
        .conn(handle)
        .expect("server")
        .view()
        .path()
        .local_cids()
        .values()
        .next()
        .expect("routable server CID");
    assert_eq!(cid.len(), 8);
    raw[1..9].copy_from_slice(cid);
    let credit =
        Credit::exhaust(&mut server, handle, &mut raw, now).expect("finite amplification fixture");
    assert_eq!(credit.deadline, None);
    assert!(credit.blocked < raw.len());
    assert_eq!(credit.probes, [1, 1]);
    let now = credit.now;
    let received = credit.received;
    let mut total = credit.sent;
    assert!(total <= 3 * received);
    assert!((1..29).contains(&(3 * received - total)));
    let conn = server.conn(handle).expect("server");
    assert_eq!(conn.view().path().received(), received);
    assert_eq!(conn.view().recovery().next_timer(), None);
    assert!(!conn.view().path().is_valid());
    Capture::with_conn(&mut server, handle, now, |mut scope| {
        scope.lifecycle().close(Code::ZERO, Vec::new());
    })
    .map_err(Error::Access)?;
    assert!(
        Capture::output(&mut server, now)
            .map_err(Error::Output)?
            .is_empty()
    );
    assert!(
        server
            .conn(handle)
            .expect("pending close owner")
            .view()
            .lifecycle()
            .is_closing()
    );
    assert_eq!(
        Pin::new(&mut server).observe(now, |turn| turn.deadline()),
        None
    );
    assert_eq!(Capture::drive(&mut server, now).map_err(Error::Output)?, 0);

    Capture::receive(&mut server, CLIENT, &mut raw, now)?;
    assert_eq!(
        server
            .conn(handle)
            .expect("pending close owner")
            .view()
            .path()
            .received(),
        received + 1200
    );
    assert_eq!(
        Pin::new(&mut server).observe(now, |turn| turn.deadline()),
        Some(now)
    );
    let close = Capture::output(&mut server, now).map_err(Error::Output)?;
    assert_eq!(
        close
            .iter()
            .map(|flight| flight.packet_count().get())
            .sum::<usize>(),
        1
    );
    total += close
        .iter()
        .map(|flight| flight.payload().len() as u64)
        .sum::<u64>();
    assert!(total <= 3 * (received + 1200));
    assert!(server.conn(handle).is_none());
    assert_eq!(srv_log.borrow().closed, [handle]);
    Ok(())
}

#[test]
fn handshake_validates() {
    let t0 = Instant::now();
    let (mut server, mut client, mut work) = life::try_pair(0)
        .expect("anti-amplification fixture must open")
        .into_parts();

    server
        .receive_from(&mut work, &mut client, t0)
        .expect("server receives client Initial");
    assert!(!server.view().path().is_valid());
    client
        .receive_from(&mut work, &mut server, t0)
        .expect("client receives server handshake flight");
    server
        .receive_from(&mut work, &mut client, t0)
        .expect("server receives client handshake flight");

    assert!(server.view().path().is_valid());
}

#[test]
fn validation_lifts_limit() {
    let t0 = Instant::now();
    let mut pair = life::try_pair(0).expect("anti-amplification fixture must open");
    pair.exchange(t0, 4).expect("fixture handshake flights");
    let (mut server, mut client, mut work) = pair.into_parts();
    assert!(server.view().lifecycle().is_ready());
    assert!(server.view().path().is_valid());

    for i in 0..50u8 {
        server
            .with_scope(|mut scope| scope.datagrams().try_send(vec![i; 100]))
            .expect("established server must accept each test DATAGRAM");
    }
    let mut received = 0;
    for step in 1..=128 {
        let now = t0 + Duration::from_millis(step * 10);
        client
            .receive_from(&mut work, &mut server, now)
            .expect("client receives validated-path DATAGRAM");
        client.with_scope(|mut scope| {
            let mut dgrams = scope.datagrams();
            while dgrams.recv().is_some() {
                received += 1;
            }
        });
        server
            .receive_from(&mut work, &mut client, now)
            .expect("server receives congestion feedback");
        if received == 50 {
            break;
        }
    }
    assert_eq!(
        received, 50,
        "validation removes anti-amplification without bypassing congestion or pacing"
    );
}
