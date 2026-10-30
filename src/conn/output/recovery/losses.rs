use crate::stream::release;
use o3::buffer;

use std::{mem, time};

use crate::conn::output::{
    cc,
    recovery::{self, delivery},
};
use crate::proto::recovery::rtt;
use crate::{conn, stream};

#[derive(Default)]
struct Lost {
    any: bool,
    latest_sent: Option<time::Instant>,
    persistent: bool,
}

impl Lost {
    fn record(&mut self, sent: time::Instant, flight: bool) {
        self.any = true;
        if !flight {
            return;
        }
        self.latest_sent = Some(self.latest_sent.map_or(sent, |latest| latest.max(sent)));
    }

    fn merge(&mut self, other: Self) {
        self.any |= other.any;
        self.persistent |= other.persistent;
        if let Some(sent) = other.latest_sent {
            self.latest_sent = Some(self.latest_sent.map_or(sent, |latest| latest.max(sent)));
        }
    }
}

pub(super) struct Detector<
    'operation,
    'state,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    E,
> {
    delivery: &'operation mut delivery::Delivery<'state, DOMAIN, B, D, E>,
}

pub(super) enum Outcome {
    Clear,
    Lost,
}

impl<'operation, 'state, const DOMAIN: u8, B, D, E> Detector<'operation, 'state, DOMAIN, B, D, E>
where
    B: stream::Recv,
    D: buffer::raw::Segment,
    E: release::Sink,
{
    pub(super) fn new(state: &'operation mut delivery::Delivery<'state, DOMAIN, B, D, E>) -> Self {
        Self { delivery: state }
    }

    pub(super) fn try_run(&mut self, now: time::Instant) -> Result<Outcome, conn::Timing> {
        let recovery = &self.delivery.egress.recovery;
        let largest = conn::Epoch::ALL.map(|epoch| {
            let packets = recovery.packet_journals.space(epoch);
            if packets.count() == 0 {
                None
            } else {
                epoch.bind(&recovery.spaces).largest_acked
            }
        });
        let mut admitted = [None; 3];
        let mut cutoff = None;
        if largest.iter().any(Option::is_some) {
            cutoff = now.checked_sub(recovery.rtt.try_delay()?);
            let pto = recovery.rtt.try_pto(time::Duration::ZERO)?;
            let mut periods = [None; 2];
            for ((epoch, largest), admitted) in
                conn::Epoch::ALL.into_iter().zip(largest).zip(&mut admitted)
            {
                let Some(largest) = largest else { continue };
                let with_ack =
                    epoch == conn::Epoch::Application && !recovery.peer_max_ack_delay.is_zero();
                let period = match periods[with_ack as usize] {
                    Some(period) => period,
                    None => {
                        let period = if with_ack {
                            conn::Timing::try_add(pto, recovery.peer_max_ack_delay)?
                        } else {
                            pto
                        };
                        let period = conn::Timing::try_mul(period, 3)?;
                        periods[with_ack as usize] = Some(period);
                        period
                    }
                };
                *admitted = Some((largest, period));
            }
        }
        let mut lost = Lost::default();
        for (epoch, admitted) in conn::Epoch::ALL.into_iter().zip(admitted) {
            if let Some((largest, period)) = admitted {
                lost.merge(self.detect(epoch, largest, cutoff, period));
            }
        }
        let any = lost.any;
        if let Some(latest) = lost.latest_sent {
            self.delivery.egress.cc.packets_lost(latest, now);
        }
        if lost.persistent {
            self.delivery.egress.cc.collapse();
        }
        let smoothed = self
            .delivery
            .egress
            .recovery
            .rtt
            .smoothed_rtt
            .unwrap_or(rtt::INITIAL_RTT);
        self.delivery.egress.cc.finish(now, smoothed);
        Ok(if any { Outcome::Lost } else { Outcome::Clear })
    }

    fn detect(
        &mut self,
        epoch: conn::Epoch,
        largest: u64,
        cutoff: Option<time::Instant>,
        period: time::Duration,
    ) -> Lost {
        let mut journals = mem::take(&mut self.delivery.egress.recovery.packet_journals);
        let mut lost = Lost::default();
        journals
            .space_mut(epoch)
            .drain_lost(largest, cutoff, |journal, controls, streams| {
                let pn = journal.pn;
                let sent = journal.sent_time;
                let flight = journal.transmission.is_flight();
                let probe = cc::Packet::from_epoch(epoch, pn)
                    .and_then(|packet| self.delivery.egress.cc.packet_lost(packet));
                let reduce = flight && probe.is_none();
                let elicits = journal.transmission.is_eliciting() && reduce;
                if matches!(
                    epoch
                        .bind_mut(&mut self.delivery.egress.recovery.streaks)
                        .lost(pn, sent, elicits, period),
                    recovery::Finding::Persistent
                ) {
                    lost.persistent = true;
                }
                self.delivery.lose(journal, controls, streams);
                lost.record(sent, reduce);
            });
        self.delivery.egress.recovery.packet_journals = journals;
        lost
    }
}
