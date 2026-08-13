use std::time;

use crate::{conn, stream, transport_params};

pub(in crate::conn) struct Timer<'a> {
    egress: &'a conn::egress::Egress,
    peer_transport_params: &'a Option<transport_params::Params>,
    local_max_idle_timeout: time::Duration,
}

impl<'a> Timer<'a> {
    pub(in crate::conn) fn new<const DOMAIN: u8, B: stream::ReceiveBuffer>(
        connection: &'a conn::session::Connection<DOMAIN, B>,
    ) -> Self {
        Self::from_parts(
            &connection.egress,
            &connection.peer.transport_params,
            connection.peer.local_max_idle_timeout,
        )
    }

    pub(super) fn from_parts(
        egress: &'a conn::egress::Egress,
        peer_transport_params: &'a Option<transport_params::Params>,
        local_max_idle_timeout: time::Duration,
    ) -> Self {
        Self {
            egress,
            peer_transport_params,
            local_max_idle_timeout,
        }
    }

    pub(super) fn idle_deadline(&self) -> Option<time::Instant> {
        let local_ms = self.local_max_idle_timeout.as_millis() as u64;
        let peer_ms = self
            .peer_transport_params
            .as_ref()
            .map(|params| params.max_idle_timeout_ms)
            .unwrap_or(0);
        let effective = match (local_ms, peer_ms) {
            (0, 0) => return None,
            (0, peer) => peer,
            (local, 0) => local,
            (local, peer) => local.min(peer),
        };
        let peer_max_ack_delay = if self.egress.lifecycle.state == conn::State::Established {
            self.peer_transport_params
                .as_ref()
                .map(|params| time::Duration::from_millis(params.max_ack_delay_ms))
                .unwrap_or(time::Duration::ZERO)
        } else {
            time::Duration::ZERO
        };
        let minimum = self
            .egress
            .recovery
            .rtt
            .pto_period(peer_max_ack_delay)
            .saturating_mul(3);
        Some(
            self.egress.activity.last_activity
                + time::Duration::from_millis(effective).max(minimum),
        )
    }

    pub(in crate::conn) fn next_deadline(&self) -> Option<time::Instant> {
        match (self.egress.recovery.loss_timer, self.idle_deadline()) {
            (Some(loss), Some(idle)) => Some(loss.min(idle)),
            (Some(loss), None) => Some(loss),
            (None, Some(idle)) => Some(idle),
            (None, None) => None,
        }
    }

    pub(in crate::conn) fn update(egress: &mut conn::egress::Egress) {
        let loss_delay = egress.recovery.rtt.loss_delay();

        let mut rack_candidate: Option<time::Instant> = None;
        for (index, space) in egress.recovery.spaces.iter().enumerate() {
            let Some(largest_acked) = space.largest_acked else {
                continue;
            };
            if let Some(when) = egress.recovery.packet_journals.loss_candidate(
                conn::Epoch::from_index(index),
                largest_acked,
                loss_delay,
            ) {
                rack_candidate = Some(rack_candidate.map_or(when, |previous| previous.min(when)));
            }
        }
        if let Some(instant) = rack_candidate {
            egress.recovery.loss_timer = Some(instant);
            return;
        }

        let mut pto_base: Option<time::Instant> = None;
        for space in &egress.recovery.spaces {
            if space.ack_eliciting_in_flight > 0
                && let Some(instant) = space.time_of_last_ack_eliciting
            {
                pto_base = Some(match pto_base {
                    Some(previous) => previous.min(instant),
                    None => instant,
                });
            }
        }
        egress.recovery.loss_timer = pto_base.map(|instant| {
            let pto = egress.recovery.rtt.pto_period(time::Duration::ZERO);
            instant + pto * (1u32 << egress.recovery.pto_count.min(16))
        });
    }
}
