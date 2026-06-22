use std::time::{Duration, Instant};

use dope_quic::pn_space::{AckedFrames, PnSpace, SentPacket};
use dope_quic::rtt::{K_GRANULARITY, K_PACKET_THRESHOLD, RttTracker};

fn empty_frames() -> AckedFrames {
    AckedFrames::default()
}

fn crypto_frames(offset: u64, len: usize) -> AckedFrames {
    AckedFrames {
        crypto: Some((offset, len)),
        stream: Vec::new(),
    }
}

#[test]
fn packet_threshold_declares_oldest_lost() {
    let mut s = PnSpace::default();
    let t0 = Instant::now();
    for pn in 0..=4 {
        s.record_sent(SentPacket {
            pn,
            sent_time: t0,
            ack_eliciting: true,
            in_flight: true,
            frames: empty_frames(),
            bytes_sent: 0,
        });
    }
    let _ = s.process_ack(4, 3, &[]);
    assert_eq!(s.largest_acked, Some(4));

    let (lost, _) = s.detect_lost(Duration::from_secs(1), t0);
    let lost_pns: Vec<u64> = lost.iter().map(|p| p.pn).collect();
    assert_eq!(lost_pns, vec![0]);
    assert!(
        s.sent.is_empty(),
        "all packets either acked or declared lost"
    );
}

#[test]
fn packet_threshold_keeps_packets_within_window() {
    let mut s = PnSpace::default();
    let t0 = Instant::now();
    for pn in 0..=2 {
        s.record_sent(SentPacket {
            pn,
            sent_time: t0,
            ack_eliciting: true,
            in_flight: true,
            frames: empty_frames(),
            bytes_sent: 0,
        });
    }
    let _ = s.process_ack(2, 0, &[]);
    let (lost, _) = s.detect_lost(Duration::from_secs(1), t0);
    assert!(lost.is_empty());
    assert_eq!(s.sent.len(), 2, "0 and 1 still in flight");
    let _ = K_PACKET_THRESHOLD;
}

#[test]
fn time_threshold_declares_old_packets_lost() {
    let mut s = PnSpace::default();
    let t0 = Instant::now();
    s.record_sent(SentPacket {
        pn: 0,
        sent_time: t0,
        ack_eliciting: true,
        in_flight: true,
        frames: empty_frames(),
        bytes_sent: 0,
    });
    s.record_sent(SentPacket {
        pn: 1,
        sent_time: t0 + Duration::from_millis(100),
        ack_eliciting: true,
        in_flight: true,
        frames: empty_frames(),
        bytes_sent: 0,
    });
    let _ = s.process_ack(1, 0, &[]);

    let now = t0 + Duration::from_millis(200);
    let (lost, _) = s.detect_lost(Duration::from_millis(50), now);
    let lost_pns: Vec<u64> = lost.iter().map(|p| p.pn).collect();
    assert_eq!(lost_pns, vec![0]);
}

#[test]
fn lost_packet_crypto_moves_to_retransmit_queue() {
    let mut s = PnSpace::default();
    let t0 = Instant::now();
    let original = b"client-hello-bytes".to_vec();
    s.crypto_inflight.insert(0, (original.clone(), 0));
    s.record_sent(SentPacket {
        pn: 0,
        sent_time: t0,
        ack_eliciting: true,
        in_flight: true,
        frames: crypto_frames(0, original.len()),
        bytes_sent: 0,
    });
    for pn in 1..=3 {
        s.record_sent(SentPacket {
            pn,
            sent_time: t0,
            ack_eliciting: true,
            in_flight: true,
            frames: empty_frames(),
            bytes_sent: 0,
        });
    }
    let _ = s.process_ack(3, 2, &[]);
    let (lost, _) = s.detect_lost(Duration::from_secs(1), t0);
    assert_eq!(lost.len(), 1);
    assert_eq!(s.crypto_retransmit, vec![(0, original)]);
    assert!(s.crypto_inflight.is_empty());
}

#[test]
fn detect_lost_reports_next_loss_time_for_packets_in_window() {
    let mut s = PnSpace::default();
    let t0 = Instant::now();
    s.record_sent(SentPacket {
        pn: 0,
        sent_time: t0,
        ack_eliciting: true,
        in_flight: true,
        frames: empty_frames(),
        bytes_sent: 0,
    });
    s.record_sent(SentPacket {
        pn: 1,
        sent_time: t0 + Duration::from_millis(10),
        ack_eliciting: true,
        in_flight: true,
        frames: empty_frames(),
        bytes_sent: 0,
    });
    let _ = s.process_ack(1, 0, &[]);

    let now = t0 + Duration::from_millis(20);
    let loss_delay = Duration::from_millis(100);
    let (lost, next) = s.detect_lost(loss_delay, now);
    assert!(lost.is_empty(), "packet 0 not yet old enough");
    let next = next.expect("packet 0 has a future loss time");
    assert_eq!(next, t0 + loss_delay);
    let _ = K_GRANULARITY;
}

#[test]
fn rtt_loss_delay_uses_max_of_smoothed_and_latest() {
    let mut r = RttTracker::default();
    r.update(Duration::from_millis(100), Duration::ZERO);
    let d = r.loss_delay();
    assert!(d >= Duration::from_millis(112) && d <= Duration::from_millis(113));
}
