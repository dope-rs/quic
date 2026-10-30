pub mod common;
use common::peer::Pair;
use common::suite::peers::receive::datagram::{try_burst, try_drain, try_pair};
use std::time::Instant;

#[test]
fn drains_without_loss() {
    let (recv, iters, sim) = try_drain(0, 1000).expect("drain datagrams without loss");
    eprintln!(
        "congestion controlled 0% loss: recv={} iters={} sim={:?}",
        recv, iters, sim
    );
    assert!(
        recv >= 950,
        "expected ≥950 / 1000 received in 0% loss, got {recv}"
    );
}

#[test]
fn drains_under_loss() {
    let (recv, iters, sim) =
        try_drain(300_000, 1000).expect("drain datagrams with thirty percent loss");
    eprintln!(
        "congestion controlled 30% loss: recv={} iters={} sim={:?}",
        recv, iters, sim
    );
    let min = 600;
    let max = 800;
    assert!(
        (min..=max).contains(&recv),
        "expected {min}..={max} recv at 30% loss, got {recv}"
    );
}

#[test]
fn burst_respects_cwnd() {
    let Pair {
        mut client,
        server: _server,
        work: _work,
    } = try_pair().expect("establish datagram peers");
    try_burst(&mut client).expect("queue the congestion-window burst");
    let now = Instant::now();
    let (first, send_result) = client.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("warmed client journals must admit its congestion-window burst");
    assert!(!first.is_empty());
    assert!(first.len() < 64);
    let (second, send_result) = client.with_scope(|mut scope| scope.output().send(now));
    send_result.expect("warmed client journals must remain admissible at the pacing boundary");
    assert!(second.is_empty());
}
