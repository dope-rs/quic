use crate::stream::release;
use o3::buffer;

use std::time;

use crate::conn::output::{
    control::journal::probes,
    transmit::permit::{self, fit},
};
use crate::wire::packet::header;
use crate::{conn, stream};

pub(in crate::conn) mod ack;
pub(in crate::conn) mod delivery;
pub(in crate::conn) mod early;
pub(in crate::conn) mod epochs;
mod losses;
pub(in crate::conn) mod shift;
pub(in crate::conn) mod timer;

#[derive(Clone, Copy, Default)]
pub(in crate::conn) struct Streak {
    first: Option<(header::Number, time::Instant)>,
    last_pn: Option<header::Number>,
}

pub(super) enum Finding {
    Pending,
    Persistent,
}

impl Streak {
    pub(super) fn acknowledged(&mut self, pn: header::Number, elicits: bool) {
        if elicits && self.first.is_some_and(|entry| pn >= entry.0) {
            *self = Self::default();
        }
    }

    pub(super) fn lost(
        &mut self,
        pn: header::Number,
        sent: time::Instant,
        elicits: bool,
        limit: time::Duration,
    ) -> Finding {
        if self
            .last_pn
            .is_some_and(|previous| previous.get() + 1 != pn.get())
        {
            *self = Self::default();
        }
        self.last_pn = Some(pn);
        if !elicits {
            return Finding::Pending;
        }
        let first = self.first.get_or_insert((pn, sent)).1;
        if sent.saturating_duration_since(first) < limit {
            return Finding::Pending;
        }
        *self = Self::default();
        Finding::Persistent
    }
}

pub struct Progress<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    machine: &'a mut conn::Machine<DOMAIN, B, D>,
}

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Progress<'a, DOMAIN, B, D> {
    pub(in crate::conn) fn new(machine: &'a mut conn::Machine<DOMAIN, B, D>) -> Self {
        Self { machine }
    }

    pub fn try_loss(&mut self, now: time::Instant) -> Result<(), conn::Timing> {
        self.try_advance(now)
            .map_err(|error| self.machine.fail_timing(error))
    }

    fn try_advance(&mut self, now: time::Instant) -> Result<(), conn::Timing> {
        if self.machine.egress.lifecycle.state == conn::State::Closed {
            return Ok(());
        }
        if let Some(idle) = self.machine.egress.recovery.timer.idle
            && now >= idle
        {
            self.machine.egress.lifecycle.state = conn::State::Closed;
            self.machine.peer.reconcile.insert(conn::Effects::LIFECYCLE);
            return Ok(());
        }
        let Some(deadline) = fit::loss_deadline(&permit::Permit::new(self.machine)) else {
            return Ok(());
        };
        if now < deadline {
            return Ok(());
        }

        let conn::Machine {
            egress,
            control,
            handshake: tls,
            streams,
            ..
        } = &mut *self.machine;
        let mut delivery = delivery::Delivery::new(
            delivery::Graph::new(
                egress,
                control,
                tls,
                &mut streams.state,
                &mut streams.events,
            ),
            release::Ignore,
        );
        let outcome = losses::Detector::new(&mut delivery).try_run(now)?;
        if matches!(outcome, losses::Outcome::Clear)
            && let Some(epoch) = delivery.egress.recovery.timer.pto_epoch
        {
            delivery.egress.recovery.probe.epoch = Some(epoch);
            delivery.egress.recovery.probe.allowance.arm();
            if epoch == conn::Epoch::Application {
                delivery
                    .egress
                    .recovery
                    .packet_journals
                    .space_mut(conn::Epoch::Application)
                    .protect_pto();
            }
            delivery.handshake.crypto.arm_probes(epoch);
            if epoch == conn::Epoch::Application {
                probes::Probes::new(&mut *delivery.control).arm(epoch);
                delivery.streams.transmit.arm_probes();
            }
            delivery.egress.recovery.probe.count.increment();
        }
        delivery.try_update(now)
    }
}
