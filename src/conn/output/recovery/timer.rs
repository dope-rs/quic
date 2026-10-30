use o3::buffer;
use std::time;

use crate::{conn, proto::param, stream, wire::stream::Initiator};
use conn::{output, wire::tls::ciphers};

pub(in crate::conn) struct Timer<'a> {
    egress: &'a output::Egress,
    keys: &'a ciphers::State,
    local: Initiator,
    params: &'a Option<param::Set>,
    idle_ms: u64,
}

impl<'a> Timer<'a> {
    pub(in crate::conn) fn new<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>(
        machine: &'a conn::Machine<DOMAIN, B, D>,
    ) -> Self {
        Self {
            egress: &machine.egress,
            keys: &machine.handshake.keys,
            local: machine.peer.local,
            params: &machine.peer.transport_params,
            idle_ms: machine.peer.local_max_idle_ms,
        }
    }

    pub(in crate::conn) fn idle(&self) -> Option<time::Instant> {
        self.egress.recovery.timer.idle
    }

    pub(in crate::conn) fn try_activity(
        &self,
        last: Option<time::Instant>,
        admitted: Option<(time::Duration, time::Duration)>,
    ) -> Result<Option<time::Instant>, conn::Timing> {
        let Some(last) = last else {
            return Ok(None);
        };
        let peer_ms = self
            .params
            .as_ref()
            .map(|params| params.timing().idle_ms())
            .unwrap_or(0);
        let millis = match (self.idle_ms, peer_ms) {
            (0, 0) => return Ok(None),
            (0, peer) => peer,
            (local, 0) => local,
            (local, peer) => local.min(peer),
        };
        let ack = if self.egress.lifecycle.state == conn::State::Established {
            self.egress.recovery.peer_max_ack_delay
        } else {
            time::Duration::ZERO
        };
        let floor = conn::Timing::try_mul(Self::try_pto(self.egress, ack, admitted)?, 3)?;
        conn::Timing::try_deadline(last, time::Duration::from_millis(millis).max(floor)).map(Some)
    }

    pub(in crate::conn) fn try_prepare(
        &self,
        now: time::Instant,
        changed: bool,
        admitted: Option<(time::Duration, time::Duration)>,
    ) -> Result<output::Timer, conn::Timing> {
        let (loss, epoch) =
            Self::try_loss(self.egress, self.keys, self.local, now, None, admitted)?;
        let idle = if changed {
            self.try_activity(self.egress.activity.last_activity, admitted)?
        } else {
            self.idle()
        };
        Ok(output::Timer {
            loss,
            pto_epoch: epoch,
            idle,
        })
    }

    pub(in crate::conn::output) fn try_datagram(
        &self,
        now: time::Instant,
        admitted: Option<(time::Duration, time::Duration)>,
    ) -> Result<output::Timer, conn::Timing> {
        let (loss, epoch) =
            Self::try_loss(self.egress, self.keys, self.local, now, Some(now), admitted)?;
        let idle = if self.egress.activity.ack_eliciting_sent_since_last_receive {
            self.idle()
        } else {
            self.try_activity(Some(now), admitted)?
        };
        Ok(output::Timer {
            loss,
            pto_epoch: epoch,
            idle,
        })
    }

    pub(in crate::conn) fn try_update(
        egress: &mut output::Egress,
        keys: &ciphers::State,
        local: Initiator,
        now: time::Instant,
    ) -> Result<(), conn::Timing> {
        let (loss, epoch) = Self::try_loss(egress, keys, local, now, None, None)?;
        egress.recovery.timer.loss = loss;
        egress.recovery.timer.pto_epoch = epoch;
        Ok(())
    }

    pub(super) fn is_validated(egress: &output::Egress, local: Initiator) -> bool {
        matches!(local, Initiator::Server)
            || egress.lifecycle.handshake_confirmed
            || conn::Epoch::Handshake
                .bind(&egress.recovery.spaces)
                .largest_acked
                .is_some()
    }

    fn try_pto(
        egress: &output::Egress,
        ack: time::Duration,
        admitted: Option<(time::Duration, time::Duration)>,
    ) -> Result<time::Duration, conn::Timing> {
        match admitted {
            Some((delay, pto)) if delay == ack => Ok(pto),
            _ => egress.recovery.rtt.try_pto(ack),
        }
    }

    fn try_loss(
        egress: &output::Egress,
        keys: &ciphers::State,
        local: Initiator,
        now: time::Instant,
        datagram: Option<time::Instant>,
        admitted: Option<(time::Duration, time::Duration)>,
    ) -> Result<(Option<time::Instant>, Option<conn::Epoch>), conn::Timing> {
        let mut rack: Option<time::Instant> = None;
        for (epoch, space) in conn::Epoch::ALL.into_iter().zip(&egress.recovery.spaces) {
            let Some(largest) = space.largest_acked else {
                continue;
            };
            if let Some(sent) = egress
                .recovery
                .packet_journals
                .space(epoch)
                .loss_sent(largest)
            {
                rack = Some(rack.map_or(sent, |previous| previous.min(sent)));
            }
        }
        if let Some(sent) = rack {
            let instant = conn::Timing::try_deadline(sent, egress.recovery.rtt.try_delay()?)?;
            return Ok((Some(instant), None));
        }

        let backoff = egress.recovery.probe.count.backoff();
        let mut pto: Option<(time::Instant, conn::Epoch)> = None;
        let mut periods = [None; 2];
        for (epoch, space) in conn::Epoch::ALL.into_iter().zip(&egress.recovery.spaces) {
            if epoch == conn::Epoch::Application && !egress.lifecycle.handshake_confirmed {
                continue;
            }
            let incoming = (epoch == conn::Epoch::Application)
                .then_some(datagram)
                .flatten();
            if (incoming.is_some() || egress.recovery.packet_journals.space(epoch).has_elicit())
                && let Some(instant) = incoming.or(space.time_of_last_ack_eliciting)
            {
                let with_ack = epoch == conn::Epoch::Application
                    && !egress.recovery.peer_max_ack_delay.is_zero();
                let period = match periods[with_ack as usize] {
                    Some(period) => period,
                    None => {
                        let ack = if with_ack {
                            egress.recovery.peer_max_ack_delay
                        } else {
                            time::Duration::ZERO
                        };
                        let period =
                            conn::Timing::try_mul(Self::try_pto(egress, ack, admitted)?, backoff)?;
                        periods[with_ack as usize] = Some(period);
                        period
                    }
                };
                let deadline = conn::Timing::try_deadline(instant, period)?;
                if pto.is_none_or(|prior| deadline < prior.0) {
                    pto = Some((deadline, epoch));
                }
            }
        }
        if pto.is_none() && egress.lifecycle.sent_initial && !Self::is_validated(egress, local) {
            let epoch = if keys.long.handshake().is_some() {
                conn::Epoch::Handshake
            } else if keys.long.initial().is_some() {
                conn::Epoch::Initial
            } else {
                return Ok((None, None));
            };
            let period = conn::Timing::try_mul(
                Self::try_pto(egress, time::Duration::ZERO, admitted)?,
                backoff,
            )?;
            pto = Some((conn::Timing::try_deadline(now, period)?, epoch));
        }
        Ok(pto.unzip())
    }
}
