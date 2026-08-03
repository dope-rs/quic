use std::borrow::Borrow;
use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};

use crate::frame::MAX_ACK_RANGES;
use crate::rtt::PACKET_THRESHOLD;

#[derive(Debug, Default)]
struct ReceivedPackets {
    ranges: BTreeMap<u64, u64>,
}

pub(crate) struct AckRangeSet {
    pub(crate) largest: u64,
    pub(crate) first_range: u64,
    pub(crate) additional: Vec<(u64, u64)>,
}

impl ReceivedPackets {
    fn contains(&self, pn: u64) -> bool {
        self.ranges
            .range(..=pn)
            .next_back()
            .is_some_and(|(_, &largest)| pn <= largest)
    }

    fn insert(&mut self, pn: u64) -> bool {
        if self.contains(pn) {
            return false;
        }

        let previous = self
            .ranges
            .range(..pn)
            .next_back()
            .map(|(&smallest, &largest)| (smallest, largest));
        let next = self
            .ranges
            .range(pn..)
            .next()
            .map(|(&smallest, &largest)| (smallest, largest));
        let joins_previous =
            previous.is_some_and(|(_, largest)| largest.checked_add(1) == Some(pn));
        let joins_next = next.is_some_and(|(smallest, _)| pn.checked_add(1) == Some(smallest));

        match (previous, next, joins_previous, joins_next) {
            (Some((previous_smallest, _)), Some((next_smallest, next_largest)), true, true) => {
                self.ranges.insert(previous_smallest, next_largest);
                self.ranges.remove(&next_smallest);
            }
            (Some((previous_smallest, _)), _, true, false) => {
                self.ranges.insert(previous_smallest, pn);
            }
            (_, Some((next_smallest, next_largest)), false, true) => {
                self.ranges.remove(&next_smallest);
                self.ranges.insert(pn, next_largest);
            }
            _ => {
                self.ranges.insert(pn, pn);
            }
        }

        while self.ranges.len() > MAX_ACK_RANGES {
            let Some(oldest) = self.ranges.first_key_value().map(|(&smallest, _)| smallest) else {
                break;
            };
            self.ranges.remove(&oldest);
        }
        true
    }

    fn ack_ranges(&self) -> Option<AckRangeSet> {
        let mut ranges = self.ranges.iter().rev();
        let (&first_smallest, &largest) = ranges.next()?;
        let first_range = largest - first_smallest;
        let mut previous_smallest = first_smallest;
        let mut additional = Vec::with_capacity(self.ranges.len().saturating_sub(1));
        for (&smallest, &range_largest) in ranges {
            let gap = previous_smallest - range_largest - 2;
            additional.push((gap, range_largest - smallest));
            previous_smallest = smallest;
        }
        Some(AckRangeSet {
            largest,
            first_range,
            additional,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SentPacket {
    pub pn: u64,
    pub sent_time: Instant,
    pub ack_eliciting: bool,
    pub in_flight: bool,
    pub bytes_sent: usize,
}

#[derive(Debug, Default)]
pub struct PnSpace {
    pub next_pn: u64,
    pub sent: BTreeMap<u64, SentPacket>,
    received: ReceivedPackets,
    pub largest_received: Option<u64>,
    pub largest_received_time: Option<Instant>,
    pub ack_eliciting_received: bool,
    pub ack_pending: bool,
    pub largest_acked: Option<u64>,
    pub crypto_inflight: BTreeMap<u64, (Vec<u8>, u64)>,
    pub crypto_retransmit: Vec<(u64, Vec<u8>)>,
    pub crypto_next_offset: u64,
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

    pub fn expected_pn(&self) -> u64 {
        self.largest_received
            .and_then(|pn| pn.checked_add(1))
            .unwrap_or(0)
    }

    pub fn has_received(&self, pn: u64) -> bool {
        self.received.contains(pn)
    }

    pub fn record_received(&mut self, pn: u64, ack_eliciting: bool, now: Instant) -> bool {
        if !self.received.insert(pn) {
            return false;
        }
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
        true
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

    pub(crate) fn build_ack_ranges(&self) -> Option<AckRangeSet> {
        self.received.ack_ranges()
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
            let by_pn = largest_acked.saturating_sub(pn) >= PACKET_THRESHOLD;
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
                if p.ack_eliciting && p.in_flight {
                    self.ack_eliciting_in_flight = self.ack_eliciting_in_flight.saturating_sub(1);
                }
                lost.push(p);
            }
        }
        (lost, earliest_loss_time)
    }

    pub fn process_ack<I>(
        &mut self,
        largest: u64,
        first_range: u64,
        additional: I,
    ) -> Vec<SentPacket>
    where
        I: IntoIterator,
        I::Item: Borrow<(u64, u64)>,
    {
        let mut acked = Vec::new();

        let first_smallest = largest.saturating_sub(first_range);
        self.remove_sent_range(first_smallest, largest, &mut acked);

        let mut prev_smallest = first_smallest;
        for range in additional {
            let &(gap, range_len) = range.borrow();
            let next_largest = prev_smallest.saturating_sub(gap + 2);
            let next_smallest = next_largest.saturating_sub(range_len);
            self.remove_sent_range(next_smallest, next_largest, &mut acked);
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

        let acked_pns: HashSet<u64> = acked.iter().map(|p| p.pn).collect();
        self.crypto_inflight
            .retain(|_, (_, pn)| !acked_pns.contains(pn));
        acked
    }

    fn remove_sent_range(&mut self, smallest: u64, largest: u64, removed: &mut Vec<SentPacket>) {
        loop {
            let next = self
                .sent
                .range(smallest..=largest)
                .next()
                .map(|(&pn, _)| pn);
            let Some(pn) = next else {
                break;
            };
            if let Some(packet) = self.sent.remove(&pn) {
                removed.push(packet);
            }
        }
    }
}
