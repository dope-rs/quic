use std::{mem, time};

use crate::conn::recovery::deliveries;
use crate::{conn, stream};

#[derive(Default)]
struct Lost {
    packets: usize,
    bytes: u64,
    latest_sent: Option<time::Instant>,
}

impl Lost {
    fn record(&mut self, bytes: usize, sent_time: time::Instant) {
        let bytes = bytes as u64;
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
        self.latest_sent = Some(
            self.latest_sent
                .map_or(sent_time, |latest| latest.max(sent_time)),
        );
    }

    fn merge(&mut self, other: Self) {
        self.packets = self.packets.saturating_add(other.packets);
        self.bytes = self.bytes.saturating_add(other.bytes);
        if let Some(sent_time) = other.latest_sent {
            self.latest_sent = Some(
                self.latest_sent
                    .map_or(sent_time, |latest| latest.max(sent_time)),
            );
        }
    }
}

pub(super) struct Detector<'operation, 'state, const DOMAIN: u8, B: stream::ReceiveBuffer, C> {
    deliveries: &'operation mut deliveries::Deliveries<'state, DOMAIN, B, C>,
}

impl<'operation, 'state, const DOMAIN: u8, B: stream::ReceiveBuffer, C: conn::control::Write>
    Detector<'operation, 'state, DOMAIN, B, C>
{
    pub(super) fn new(
        deliveries: &'operation mut deliveries::Deliveries<'state, DOMAIN, B, C>,
    ) -> Self {
        Self { deliveries }
    }

    pub(super) fn run(&mut self, now: time::Instant) -> usize {
        let mut lost = Lost::default();
        for index in 0..=conn::Epoch::Application as usize {
            lost.merge(self.detect(conn::Epoch::from_index(index), now));
        }
        let packets = lost.packets;
        if let Some(latest_sent) = lost.latest_sent {
            self.deliveries
                .egress
                .cc
                .packets_lost(lost.bytes, latest_sent);
        }
        packets
    }

    fn detect(&mut self, epoch: conn::Epoch, now: time::Instant) -> Lost {
        let Some(largest_acked) = self.deliveries.egress.spaces[epoch as usize].largest_acked
        else {
            return Lost::default();
        };
        let loss_delay = self.deliveries.egress.rtt.loss_delay();
        let lost_send_time = match now.checked_sub(loss_delay) {
            Some(instant) => instant,
            None => now,
        };
        let mut journals = mem::take(&mut self.deliveries.egress.packet_journals);
        let mut lost = Lost::default();
        journals.drain_lost(
            epoch,
            largest_acked,
            lost_send_time,
            |journal, controls, streams| {
                if journal.transmission.ack_eliciting() && journal.transmission.in_flight() {
                    self.deliveries.egress.spaces[epoch as usize].ack_eliciting_in_flight =
                        self.deliveries.egress.spaces[epoch as usize]
                            .ack_eliciting_in_flight
                            .saturating_sub(1);
                }
                self.deliveries.lose(journal, controls, streams);
                lost.record(journal.bytes_sent, journal.sent_time);
                if epoch == conn::Epoch::Application
                    && Some(journal.pn) == self.deliveries.egress.pmtud_probe_pn
                {
                    self.deliveries.egress.pmtud.probe_lost();
                    self.deliveries.egress.pmtud_probe_pn = None;
                }
            },
        );
        self.deliveries.egress.packet_journals = journals;
        lost
    }
}
