use crate::stream::release;
use o3::buffer;

use std::{mem, time};

use crate::conn::output::recovery::{delivery, losses, timer};
use crate::{conn, stream, wire::frame::ack::ranges};

pub(in crate::conn) struct Receipt<'a> {
    pub(in crate::conn) delay: time::Duration,
    pub(in crate::conn) ranges: ranges::Validated<'a>,
    pub(in crate::conn) advanced: bool,
}

pub(in crate::conn) struct Ack<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, E> {
    delivery: delivery::Delivery<'a, DOMAIN, B, D, E>,
}

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, E: release::Sink>
    Ack<'a, DOMAIN, B, D, E>
{
    pub(in crate::conn) fn new(graph: delivery::Graph<'a, DOMAIN, B, D>, proof: E) -> Self {
        Self {
            delivery: delivery::Delivery::new(graph, proof),
        }
    }

    pub(in crate::conn) fn try_apply(
        &mut self,
        epoch: conn::Epoch,
        receipt: Receipt<'_>,
        now: time::Instant,
    ) -> Result<(), conn::Error> {
        let Receipt {
            delay,
            ranges,
            advanced: mut changed,
        } = receipt;
        let largest = ranges.largest();
        let valid = timer::Timer::is_validated(self.delivery.egress, self.delivery.streams.local());
        let mut sample = None;
        let mut elicits = false;
        let mut journals = mem::take(&mut self.delivery.egress.recovery.packet_journals);
        let result = journals
            .space_mut(epoch)
            .try_ack(ranges, |journal, controls, streams| {
                changed = true;
                let elicit = journal.transmission.is_eliciting();
                elicits |= elicit;
                epoch
                    .bind_mut(&mut self.delivery.egress.recovery.streaks)
                    .acknowledged(journal.pn, elicit && journal.transmission.is_flight());
                if journal.pn.get() == largest {
                    sample = Some(now.saturating_duration_since(journal.sent_time));
                }
                if valid && elicit {
                    self.delivery.egress.recovery.probe.count.reset();
                }
                self.delivery.acknowledge(epoch, journal, controls, streams)
            });
        self.delivery.egress.recovery.packet_journals = journals;
        result?;
        if elicits && let Some(sample) = sample {
            self.delivery.egress.recovery.rtt.update(sample, delay);
        }
        let outcome = losses::Detector::new(&mut self.delivery).try_run(now)?;
        if changed || matches!(outcome, losses::Outcome::Lost) {
            self.delivery.try_update(now)?;
        }
        Ok(())
    }
}
