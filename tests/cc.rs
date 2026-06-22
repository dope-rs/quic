use std::time::Instant;

use dope_quic::new_reno::{K_INITIAL_WINDOW, K_MAX_DATAGRAM_SIZE, K_MINIMUM_WINDOW, NewReno};

#[test]
fn newreno_starts_at_initial_window() {
    let cc = NewReno::default();
    assert_eq!(cc.cwnd, K_INITIAL_WINDOW);
    assert_eq!(cc.ssthresh, u64::MAX);
    assert_eq!(cc.bytes_in_flight, 0);
    assert!(cc.allows_send());
}

#[test]
fn slow_start_grows_cwnd_by_acked_bytes() {
    let mut cc = NewReno::default();
    cc.on_packet_sent(1200, true);
    cc.on_packet_acked(1200, true);
    assert_eq!(cc.cwnd, K_INITIAL_WINDOW + 1200);
    assert_eq!(cc.bytes_in_flight, 0);
}

#[test]
fn loss_halves_cwnd_floored_at_minimum() {
    let mut cc = NewReno::default();
    cc.on_packet_sent(1200, true);
    let t = Instant::now();
    cc.on_packets_lost(1200, t);
    assert_eq!(cc.cwnd, K_INITIAL_WINDOW / 2);
    assert_eq!(cc.ssthresh, K_INITIAL_WINDOW / 2);
}

#[test]
fn loss_does_not_double_count_within_recovery() {
    let mut cc = NewReno::default();
    let t = Instant::now();
    cc.on_packet_sent(1200, true);
    cc.on_packet_sent(1200, true);
    cc.on_packets_lost(1200, t);
    let cwnd_after_first_loss = cc.cwnd;
    cc.on_packets_lost(1200, t);
    assert_eq!(cc.cwnd, cwnd_after_first_loss);
}

#[test]
fn cwnd_floor_at_minimum_window() {
    let mut cc = NewReno {
        cwnd: K_MINIMUM_WINDOW + 100,
        ..Default::default()
    };
    let t = Instant::now();
    cc.on_packet_sent(K_MAX_DATAGRAM_SIZE, true);
    cc.on_packets_lost(K_MAX_DATAGRAM_SIZE, t);
    assert_eq!(cc.cwnd, K_MINIMUM_WINDOW);
}

#[test]
fn allows_send_blocks_when_in_flight_exceeds_cwnd() {
    let mut cc = NewReno {
        bytes_in_flight: K_INITIAL_WINDOW,
        ..Default::default()
    };
    assert!(!cc.allows_send());
    cc.bytes_in_flight = K_INITIAL_WINDOW - 1;
    assert!(cc.allows_send());
}
