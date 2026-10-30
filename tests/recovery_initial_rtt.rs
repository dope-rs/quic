pub mod common;

use common::suite::{
    mux::{dispatch, paths},
    peers::path,
};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

#[test]
fn initial_pto_has_variance() {
    let mut client = path::try_initial().expect("initial client");
    let now = Instant::now();
    assert!(
        !client
            .with_scope(|mut scope| {
                let (packets, result) = scope.output().send(now);
                result.expect("Initial");
                packets
            })
            .is_empty()
    );
    let recovery = client.view().recovery();
    assert_eq!(recovery.smoothed_rtt(), None);
    assert_eq!(recovery.min_rtt(), None);
    assert_eq!(
        recovery.next_timer(),
        Some(now + Duration::from_millis(999))
    );
}

#[test]
fn migration_resets_rtt() {
    let mut pair = paths::Pending::try_new(0x39, 0x81)
        .expect("path peers")
        .establish()
        .expect("established path");
    let rebound = SocketAddr::from(([10, 0, 0, 1], 50_001));
    let at = pair.start + Duration::from_millis(20);
    pair.observe(rebound, vec![0x41; 500], at, at)
        .expect("new path traffic");
    let mut probe = dispatch::Capture::output(&mut pair.server, at).expect("path challenge");
    let valid = pair.answer(&mut probe, rebound, at).expect("path response");
    assert_eq!(
        paths::Pair::peer(&mut pair.server, pair.server_id, valid),
        Ok(Some(rebound))
    );
    let recovery = pair
        .server
        .conn(pair.server_id)
        .expect("server connection")
        .view()
        .recovery();
    assert_eq!(recovery.smoothed_rtt(), None);
    assert_eq!(recovery.min_rtt(), None);

    let sent = valid + Duration::from_millis(1);
    pair.send_server(vec![0x42; 128], sent)
        .expect("new path datagram");
    let mut flight = dispatch::Capture::output(&mut pair.server, sent).expect("new path flight");
    assert!(!flight.is_empty());
    assert_eq!(
        pair.server
            .conn(pair.server_id)
            .expect("server connection")
            .view()
            .recovery()
            .next_timer(),
        Some(sent + Duration::from_millis(1_024)),
        "the unsampled path includes initial variance and the peer's 25 ms ACK allowance",
    );
    paths::Pair::relay(
        &mut flight,
        rebound,
        paths::SERVER,
        &mut pair.client,
        sent + Duration::from_millis(10),
    )
    .expect("new path delivery");
    let acked = sent + Duration::from_millis(40);
    let mut ack = dispatch::Capture::output(&mut pair.client, acked).expect("new path ACK");
    paths::Pair::deliver(&mut ack, rebound, &mut pair.server, acked).expect("new path feedback");
    assert_eq!(
        pair.server
            .conn(pair.server_id)
            .expect("server connection")
            .view()
            .recovery()
            .smoothed_rtt(),
        Some(Duration::from_millis(40)),
        "the first new-path sample replaces the initial estimate",
    );
}
