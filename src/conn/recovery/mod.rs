use std::time;

use crate::{conn, stream, transport_params};

pub(in crate::conn) mod ack;
mod deliveries;
pub(in crate::conn) mod early;
pub(in crate::conn) mod epochs;
mod losses;
pub(in crate::conn) mod timer;

pub struct Loss<'a, const DOMAIN: u8, B: stream::ReceiveBuffer = Vec<u8>> {
    deliveries: deliveries::Deliveries<'a, DOMAIN, B, conn::control::Pending>,
    peer_transport_params: &'a Option<transport_params::Params>,
    local_max_idle_timeout: time::Duration,
}

impl<'a, const DOMAIN: u8, B: stream::ReceiveBuffer> Loss<'a, DOMAIN, B> {
    pub fn new(connection: &'a mut conn::session::Connection<DOMAIN, B>) -> Self {
        let conn::session::Connection {
            egress,
            control,
            handshake,
            streams,
            peer,
            ..
        } = connection;
        Self {
            deliveries: deliveries::Deliveries::new(
                egress,
                control,
                handshake,
                &mut streams.state,
                &mut streams.events,
                peer.is_client,
            ),
            peer_transport_params: &peer.transport_params,
            local_max_idle_timeout: peer.local_max_idle_timeout,
        }
    }

    pub fn check_loss(&mut self, now: time::Instant) {
        let idle_deadline = timer::Timer::from_parts(
            self.deliveries.egress,
            self.peer_transport_params,
            self.local_max_idle_timeout,
        )
        .idle_deadline();
        if self.deliveries.egress.state != conn::State::Closed
            && let Some(idle) = idle_deadline
            && now >= idle
        {
            self.deliveries.egress.state = conn::State::Closed;
            return;
        }
        let Some(deadline) = self.deliveries.egress.loss_timer else {
            return;
        };
        if now < deadline {
            return;
        }

        let packets_lost = losses::Detector::new(&mut self.deliveries).run(now);
        if packets_lost == 0 && self.arm_pto_probes() {
            self.deliveries.egress.pto_count = self.deliveries.egress.pto_count.saturating_add(1);
        }
        timer::Timer::update(self.deliveries.egress);
    }

    fn arm_pto_probes(&mut self) -> bool {
        let Some(epoch) = self
            .deliveries
            .egress
            .spaces
            .iter()
            .position(|space| space.ack_eliciting_in_flight != 0)
            .map(conn::Epoch::from_index)
        else {
            return false;
        };
        self.deliveries.egress.pto_probe_epoch = Some(epoch);
        self.deliveries.egress.pto_probe_allowance = 2;
        if epoch == conn::Epoch::Application {
            for journal in self
                .deliveries
                .egress
                .packet_journals
                .iter_mut(conn::Epoch::Application)
            {
                if journal.transmission.in_flight() {
                    journal.transmission.protect_pto();
                }
            }
        }
        self.deliveries.handshake.crypto_mut().arm_probes(epoch);
        if epoch == conn::Epoch::Application {
            self.deliveries.control.arm_probes(epoch);
            self.deliveries.streams.transmit.deliveries.arm_probes();
        }
        true
    }
}
