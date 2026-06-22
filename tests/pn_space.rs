use std::time::{Duration, Instant};

use dope_quic::pn_space::{AckedFrames, PnSpace, SentPacket, StreamFrameInfo};

fn now() -> Instant {
    Instant::now()
}

fn empty_frames() -> AckedFrames {
    AckedFrames::default()
}

#[test]
fn build_ranges_for_contiguous_run() {
    let mut s = PnSpace::default();
    for pn in 0..=5 {
        s.record_received(pn, true, now());
    }
    let (largest, first_range, extra) = s.build_ack_ranges().unwrap();
    assert_eq!(largest, 5);
    assert_eq!(first_range, 5);
    assert_eq!(extra, vec![]);
}

#[test]
fn build_ranges_for_two_disjoint_runs() {
    let mut s = PnSpace::default();
    for &pn in &[0u64, 1, 2, 5, 6, 7] {
        s.record_received(pn, true, now());
    }
    let (largest, first_range, extra) = s.build_ack_ranges().unwrap();
    assert_eq!(largest, 7);
    assert_eq!(first_range, 2);
    assert_eq!(extra, vec![(1, 2)]);
}

#[test]
fn build_ranges_for_three_disjoint_runs() {
    let mut s = PnSpace::default();
    for &pn in &[0u64, 1, 4, 5, 8, 9, 10] {
        s.record_received(pn, true, now());
    }
    let (largest, first_range, extra) = s.build_ack_ranges().unwrap();
    assert_eq!(largest, 10);
    assert_eq!(first_range, 2);
    assert_eq!(extra, vec![(1, 1), (1, 1)]);
}

#[test]
fn build_ranges_empty_returns_none() {
    let s = PnSpace::default();
    assert!(s.build_ack_ranges().is_none());
}

#[test]
fn process_ack_drops_acked_sent_packets() {
    let mut s = PnSpace::default();
    let t = now();
    for pn in 0..5 {
        s.record_sent(SentPacket {
            pn,
            sent_time: t,
            ack_eliciting: true,
            in_flight: true,
            frames: empty_frames(),
            bytes_sent: 0,
        });
    }

    let acked = s.process_ack(4, 4, &[]);
    assert_eq!(acked.len(), 5);
    assert!(s.sent.is_empty());
    assert_eq!(s.largest_acked, Some(4));
}

#[test]
fn process_ack_handles_disjoint_ranges() {
    let mut s = PnSpace::default();
    let t = now();
    for pn in 0..10 {
        s.record_sent(SentPacket {
            pn,
            sent_time: t,
            ack_eliciting: true,
            in_flight: true,
            frames: empty_frames(),
            bytes_sent: 0,
        });
    }
    let acked = s.process_ack(9, 2, &[(3, 2)]);
    let mut acked_pns: Vec<u64> = acked.iter().map(|p| p.pn).collect();
    acked_pns.sort();
    assert_eq!(acked_pns, vec![0u64, 1, 2, 7, 8, 9]);
    let still_sent: Vec<u64> = s.sent.keys().copied().collect();
    assert_eq!(still_sent, vec![3, 4, 5, 6]);
}

#[test]
fn record_received_sets_largest_and_ack_pending() {
    let mut s = PnSpace::default();
    s.record_received(5, true, now());
    assert_eq!(s.largest_received, Some(5));
    assert!(s.ack_pending);

    s.record_received(3, true, now());
    assert_eq!(s.largest_received, Some(5));
}

#[test]
fn non_eliciting_packet_does_not_set_ack_pending() {
    let mut s = PnSpace::default();
    s.record_received(0, false, now());
    assert!(!s.ack_pending);
    assert_eq!(s.largest_received, Some(0));
}

fn stream_frames(stream_id: u64, offset: u64, len: u64, fin: bool) -> AckedFrames {
    AckedFrames {
        crypto: None,
        stream: vec![StreamFrameInfo {
            stream_id,
            offset,
            len,
            fin,
        }],
    }
}

#[test]
fn stream_ack_clears_inflight_without_retransmit() {
    let mut s = PnSpace::default();
    s.stream_inflight.insert((4, 0), (3, true, 7));
    s.record_sent(SentPacket {
        pn: 7,
        sent_time: now(),
        ack_eliciting: true,
        in_flight: true,
        frames: stream_frames(4, 0, 3, true),
        bytes_sent: 30,
    });
    s.process_ack(7, 0, &[]);
    assert!(s.stream_inflight.is_empty());
    assert!(s.stream_retransmit.is_empty());
}

#[test]
fn stream_loss_requeues_for_retransmit() {
    let mut s = PnSpace::default();
    let old = now() - Duration::from_secs(10);
    s.stream_inflight.insert((4, 0), (3, false, 0));
    s.record_sent(SentPacket {
        pn: 0,
        sent_time: old,
        ack_eliciting: true,
        in_flight: true,
        frames: stream_frames(4, 0, 3, false),
        bytes_sent: 30,
    });
    s.record_sent(SentPacket {
        pn: 5,
        sent_time: now(),
        ack_eliciting: true,
        in_flight: true,
        frames: empty_frames(),
        bytes_sent: 30,
    });
    s.process_ack(5, 0, &[]);
    let (lost, _) = s.detect_lost(Duration::from_millis(1), now());
    assert_eq!(lost.len(), 1);
    assert!(s.stream_inflight.is_empty());
    assert_eq!(s.stream_retransmit, vec![(4u64, 0u64, 3u64, false)]);
}

#[test]
fn pto_requeues_stream_inflight() {
    let mut s = PnSpace::default();
    s.stream_inflight.insert((8, 100), (2, true, 3));
    s.requeue_inflight_stream();
    assert!(s.stream_inflight.is_empty());
    assert_eq!(s.stream_retransmit, vec![(8u64, 100u64, 2u64, true)]);
}
