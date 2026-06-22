use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::rtt::K_PACKET_THRESHOLD;

#[derive(Debug, Clone)]
pub struct StreamFrameInfo {
    pub stream_id: u64,
    pub offset: u64,
    pub len: u64,
    pub fin: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AckedFrames {
    pub crypto: Option<(u64, usize)>,
    pub stream: Vec<StreamFrameInfo>,
}

#[derive(Debug, Clone)]
pub struct SentPacket {
    pub pn: u64,
    pub sent_time: Instant,
    pub ack_eliciting: bool,
    pub in_flight: bool,
    pub frames: AckedFrames,
    pub bytes_sent: usize,
}

#[derive(Debug, Default)]
pub struct PnSpace {
    pub next_pn: u64,
    pub sent: BTreeMap<u64, SentPacket>,
    pub received: BTreeMap<u64, ()>,
    pub largest_received: Option<u64>,
    pub largest_received_time: Option<Instant>,
    pub ack_eliciting_received: bool,
    pub ack_pending: bool,
    pub largest_acked: Option<u64>,
    pub crypto_inflight: BTreeMap<u64, (Vec<u8>, u64)>,
    pub crypto_retransmit: Vec<(u64, Vec<u8>)>,
    pub crypto_next_offset: u64,
    pub stream_inflight: BTreeMap<(u64, u64), (u64, bool, u64)>,
    pub stream_retransmit: Vec<(u64, u64, u64, bool)>,
    pub time_of_last_ack_eliciting: Option<Instant>,
    pub ack_eliciting_in_flight: usize,
}

impl PnSpace {
    pub fn in_flight_bytes(&self) -> u64 {
        self.sent
            .values()
            .filter(|p| p.in_flight)
            .map(|p| p.bytes_sent as u64)
            .sum()
    }

    pub fn record_received(&mut self, pn: u64, ack_eliciting: bool, now: Instant) {
        self.received.insert(pn, ());
        match self.largest_received {
            Some(prev) if prev >= pn => {}
            _ => {
                self.largest_received = Some(pn);
                self.largest_received_time = Some(now);
            }
        }
        if ack_eliciting {
            self.ack_eliciting_received = true;
            self.ack_pending = true;
        }
    }

    pub fn record_sent(&mut self, packet: SentPacket) {
        if !packet.in_flight && !packet.ack_eliciting {
            return;
        }
        if packet.ack_eliciting {
            self.time_of_last_ack_eliciting = Some(packet.sent_time);
            self.ack_eliciting_in_flight += 1;
        }
        self.sent.insert(packet.pn, packet);
    }

    #[allow(clippy::type_complexity)]
    pub fn build_ack_ranges(&self) -> Option<(u64, u64, Vec<(u64, u64)>)> {
        let largest = self.largest_received?;

        let pns: Vec<u64> = self.received.keys().rev().copied().collect();
        if pns.is_empty() {
            return None;
        }

        let mut ranges: Vec<(u64, u64)> = Vec::new();
        let mut iter = pns.iter().copied();
        let first = iter.next().expect("non-empty");
        let mut cur_largest = first;
        let mut cur_smallest = first;
        for pn in iter {
            if pn + 1 == cur_smallest {
                cur_smallest = pn;
            } else {
                ranges.push((cur_largest, cur_smallest));
                cur_largest = pn;
                cur_smallest = pn;
            }
        }
        ranges.push((cur_largest, cur_smallest));

        let (top_lg, top_sm) = ranges[0];
        debug_assert_eq!(top_lg, largest);
        let first_range = top_lg - top_sm;

        let mut additional = Vec::with_capacity(ranges.len().saturating_sub(1));
        let mut prev_smallest = top_sm;
        for &(lg, sm) in ranges.iter().skip(1) {
            let gap = prev_smallest - lg - 2;
            let range_len = lg - sm;
            additional.push((gap, range_len));
            prev_smallest = sm;
        }
        Some((largest, first_range, additional))
    }

    pub fn requeue_inflight_crypto(&mut self) {
        for (offset, (data, _pn)) in std::mem::take(&mut self.crypto_inflight) {
            self.crypto_retransmit.push((offset, data));
        }
    }

    pub fn requeue_inflight_stream(&mut self) {
        for ((stream_id, offset), (len, fin, _pn)) in std::mem::take(&mut self.stream_inflight) {
            self.stream_retransmit.push((stream_id, offset, len, fin));
        }
    }

    pub fn detect_lost(
        &mut self,
        loss_delay: Duration,
        now: Instant,
    ) -> (Vec<SentPacket>, Option<Instant>) {
        let Some(largest_acked) = self.largest_acked else {
            return (Vec::new(), None);
        };
        let lost_send_time = now.checked_sub(loss_delay).unwrap_or(now);

        let mut lost_pns = Vec::new();
        let mut earliest_loss_time: Option<Instant> = None;
        for (&pn, p) in &self.sent {
            if pn > largest_acked {
                continue;
            }
            let by_pn = largest_acked.saturating_sub(pn) >= K_PACKET_THRESHOLD;
            let by_time = p.sent_time <= lost_send_time;
            if by_pn || by_time {
                lost_pns.push(pn);
            } else {
                let when = p.sent_time + loss_delay;
                earliest_loss_time = Some(match earliest_loss_time {
                    Some(prev) if prev < when => prev,
                    _ => when,
                });
            }
        }

        let mut lost = Vec::with_capacity(lost_pns.len());
        for pn in lost_pns {
            if let Some(p) = self.sent.remove(&pn) {
                if let Some((offset, _len)) = p.frames.crypto
                    && let Some((data, _carrier_pn)) = self.crypto_inflight.remove(&offset)
                {
                    self.crypto_retransmit.push((offset, data));
                }
                for sf in &p.frames.stream {
                    if let Some((len, fin, _carrier_pn)) =
                        self.stream_inflight.remove(&(sf.stream_id, sf.offset))
                    {
                        self.stream_retransmit
                            .push((sf.stream_id, sf.offset, len, fin));
                    }
                }
                if p.ack_eliciting && p.in_flight {
                    self.ack_eliciting_in_flight = self.ack_eliciting_in_flight.saturating_sub(1);
                }
                lost.push(p);
            }
        }
        (lost, earliest_loss_time)
    }

    pub fn process_ack(
        &mut self,
        largest: u64,
        first_range: u64,
        additional: &[(u64, u64)],
    ) -> Vec<SentPacket> {
        let mut acked = Vec::new();

        let first_smallest = largest.saturating_sub(first_range);
        for pn in first_smallest..=largest {
            if let Some(p) = self.sent.remove(&pn) {
                acked.push(p);
            }
        }

        let mut prev_smallest = first_smallest;
        for &(gap, range_len) in additional {
            let next_largest = prev_smallest.saturating_sub(gap + 2);
            let next_smallest = next_largest.saturating_sub(range_len);
            for pn in next_smallest..=next_largest {
                if let Some(p) = self.sent.remove(&pn) {
                    acked.push(p);
                }
            }
            prev_smallest = next_smallest;
        }

        if let Some(prev) = self.largest_acked {
            self.largest_acked = Some(prev.max(largest));
        } else {
            self.largest_acked = Some(largest);
        }

        for p in &acked {
            if p.ack_eliciting && p.in_flight {
                self.ack_eliciting_in_flight = self.ack_eliciting_in_flight.saturating_sub(1);
            }
        }

        let acked_pns: Vec<u64> = acked.iter().map(|p| p.pn).collect();
        self.crypto_inflight
            .retain(|_, (_, pn)| !acked_pns.contains(pn));
        self.stream_inflight
            .retain(|_, (_, _, pn)| !acked_pns.contains(pn));

        acked
    }
}
