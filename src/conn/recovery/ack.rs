use std::{mem, time};

use crate::conn::recovery::{deliveries, losses, timer};
use crate::{conn, frame, stream};

pub(in crate::conn) struct Receipt<'a> {
    pub(in crate::conn) largest: u64,
    pub(in crate::conn) delay_microseconds: u64,
    pub(in crate::conn) first_range: u64,
    pub(in crate::conn) additional_ranges: frame::ack_ranges::Ranges<'a>,
}

pub(in crate::conn) struct Ack<'a, const DOMAIN: u8, B: stream::ReceiveBuffer, C> {
    deliveries: deliveries::Deliveries<'a, DOMAIN, B, C>,
}

impl<'a, const DOMAIN: u8, B: stream::ReceiveBuffer, C: conn::control::Write>
    Ack<'a, DOMAIN, B, C>
{
    pub(in crate::conn) fn new(
        egress: &'a mut conn::egress::Egress,
        control: &'a mut C,
        handshake: &'a mut conn::handshake::Handshake<DOMAIN>,
        streams: &'a mut conn::streams::State<B>,
        stream_events: &'a mut conn::event_queue::Events,
        is_client: bool,
    ) -> Self {
        Self {
            deliveries: deliveries::Deliveries::new(
                egress,
                control,
                handshake,
                streams,
                stream_events,
                is_client,
            ),
        }
    }

    pub(in crate::conn) fn apply(
        &mut self,
        epoch: conn::Epoch,
        receipt: Receipt<'_>,
        now: time::Instant,
    ) {
        self.acknowledge_journals(epoch, receipt, now);
        losses::Detector::new(&mut self.deliveries).run(now);
        timer::Timer::update(self.deliveries.egress);
    }

    fn acknowledge_journals(
        &mut self,
        epoch: conn::Epoch,
        receipt: Receipt<'_>,
        now: time::Instant,
    ) {
        let mut journals = mem::take(&mut self.deliveries.egress.recovery.packet_journals);
        journals.drain_ack(
            epoch,
            receipt.largest,
            receipt.first_range,
            receipt.additional_ranges,
            |journal, controls, streams| {
                if journal.pn == receipt.largest {
                    let sample = now.saturating_duration_since(journal.sent_time);
                    let delay = if epoch == conn::Epoch::Application {
                        time::Duration::from_micros(receipt.delay_microseconds)
                    } else {
                        time::Duration::ZERO
                    };
                    self.deliveries.egress.recovery.rtt.update(sample, delay);
                }
                if journal.transmission.ack_eliciting() {
                    self.deliveries.egress.recovery.pto_count = 0;
                }
                self.deliveries
                    .acknowledge(epoch, journal, controls, streams);
            },
        );
        self.deliveries.egress.recovery.packet_journals = journals;
    }
}
