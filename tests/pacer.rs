use std::time::{Duration, Instant};

use dope_quic::pacer::Pacer;

const SRTT: Duration = Duration::from_millis(100);
const CWND: u64 = 12_000;
const PKT: u64 = 1200;

#[test]
fn fresh_pacer_allows_immediate_send() {
    let now = Instant::now();
    let p = Pacer::new(now);
    assert!(p.allows_send(now));
}

#[test]
fn first_ten_packets_are_burst_credit() {
    let now = Instant::now();
    let mut p = Pacer::new(now);
    for _ in 0..10 {
        assert!(p.allows_send(now));
        p.on_packet_sent(PKT, now, CWND, SRTT);
    }
    let release = p.next_release_time();
    assert!(
        release <= now,
        "burst credit keeps next_release at or before now",
    );
}

#[test]
fn eleventh_packet_advances_release_time() {
    let now = Instant::now();
    let mut p = Pacer::new(now);
    for _ in 0..10 {
        p.on_packet_sent(PKT, now, CWND, SRTT);
    }
    p.on_packet_sent(PKT, now, CWND, SRTT);
    let release = p.next_release_time();
    let interval = release - now;
    let expected = (PKT as u128) * (SRTT.as_nanos()) * 4 / (CWND as u128 * 5);
    let actual = interval.as_nanos();
    let tolerance = expected / 100;
    assert!(
        actual.abs_diff(expected) <= tolerance,
        "interval {} ns, expected {} ns",
        actual,
        expected,
    );
}

#[test]
fn allows_send_blocks_until_release_then_unblocks() {
    let now = Instant::now();
    let mut p = Pacer::new(now);
    for _ in 0..11 {
        p.on_packet_sent(PKT, now, CWND, SRTT);
    }
    let release = p.next_release_time();
    assert!(release > now, "post-burst release in the future");
    assert!(!p.allows_send(now));
    assert!(p.allows_send(release));
}

#[test]
fn higher_cwnd_yields_shorter_interval() {
    let now = Instant::now();
    let drain = |cwnd: u64| -> Duration {
        let mut p = Pacer::new(now);
        for _ in 0..11 {
            p.on_packet_sent(PKT, now, cwnd, SRTT);
        }
        p.next_release_time() - now
    };
    let small = drain(CWND);
    let large = drain(CWND * 4);
    assert!(large < small, "4x cwnd ⇒ ~1/4 interval");
}
