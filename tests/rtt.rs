use std::time::Duration;

use dope_quic::rtt::{K_GRANULARITY, K_INITIAL_RTT, RttTracker};

#[test]
fn first_sample_seeds_smoothed_and_rttvar() {
    let mut r = RttTracker::default();
    r.update(Duration::from_millis(100), Duration::ZERO);
    assert_eq!(r.latest_rtt, Some(Duration::from_millis(100)));
    assert_eq!(r.min_rtt, Some(Duration::from_millis(100)));
    assert_eq!(r.smoothed_rtt, Some(Duration::from_millis(100)));
    assert_eq!(r.rttvar, Duration::from_millis(50));
}

#[test]
fn second_sample_applies_ewma() {
    let mut r = RttTracker::default();
    r.update(Duration::from_millis(100), Duration::ZERO);
    r.update(Duration::from_millis(200), Duration::ZERO);
    let smoothed = r.smoothed_rtt.unwrap();
    assert!(
        smoothed >= Duration::from_millis(112) && smoothed <= Duration::from_millis(113),
        "smoothed = {smoothed:?}"
    );
}

#[test]
fn min_rtt_tracks_minimum() {
    let mut r = RttTracker::default();
    r.update(Duration::from_millis(100), Duration::ZERO);
    r.update(Duration::from_millis(50), Duration::ZERO);
    r.update(Duration::from_millis(200), Duration::ZERO);
    assert_eq!(r.min_rtt, Some(Duration::from_millis(50)));
}

#[test]
fn ack_delay_is_subtracted_when_safe() {
    let mut r = RttTracker::default();
    r.update(Duration::from_millis(100), Duration::ZERO);
    let before = r.smoothed_rtt.unwrap();
    r.update(Duration::from_millis(200), Duration::from_millis(50));
    let after = r.smoothed_rtt.unwrap();
    assert!(after > before);
    assert!(after < Duration::from_millis(110));
}

#[test]
fn ack_delay_ignored_when_would_violate_min_rtt() {
    let mut r = RttTracker::default();
    r.update(Duration::from_millis(100), Duration::ZERO);
    r.update(Duration::from_millis(120), Duration::from_millis(50));
    let s = r.smoothed_rtt.unwrap();
    assert!(s >= Duration::from_millis(102) && s <= Duration::from_millis(103));
}

#[test]
fn pto_period_uses_initial_rtt_when_no_sample() {
    let r = RttTracker::default();
    let pto = r.pto_period(Duration::ZERO);
    assert_eq!(pto, K_INITIAL_RTT + K_GRANULARITY);
}

#[test]
fn pto_period_after_sample() {
    let mut r = RttTracker::default();
    r.update(Duration::from_millis(40), Duration::ZERO);
    let pto = r.pto_period(Duration::from_millis(25));
    assert_eq!(pto, Duration::from_millis(145));
}
