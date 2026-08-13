use std::mem;

use crate::conn::recovery::{deliveries, timer};
use crate::{conn, stream};

pub(in crate::conn) struct EarlyData<'a, const DOMAIN: u8, B: stream::ReceiveBuffer, C> {
    deliveries: deliveries::Deliveries<'a, DOMAIN, B, C>,
}

impl<'a, const DOMAIN: u8, B: stream::ReceiveBuffer, C: conn::control::Write>
    EarlyData<'a, DOMAIN, B, C>
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

    pub(in crate::conn) fn reject(mut self) {
        let mut journals = mem::take(&mut self.deliveries.egress.recovery.packet_journals);
        journals.drain_where(
            |journal| journal.transmission.early_data(),
            |journal, controls, streams| {
                if journal.transmission.ack_eliciting() && journal.transmission.in_flight() {
                    self.deliveries.egress.recovery.spaces[conn::Epoch::Application as usize]
                        .ack_eliciting_in_flight = self.deliveries.egress.recovery.spaces
                        [conn::Epoch::Application as usize]
                        .ack_eliciting_in_flight
                        .saturating_sub(1);
                    self.deliveries
                        .egress
                        .congestion
                        .cc
                        .discard(journal.bytes_sent as u64);
                }
                self.deliveries.lose(journal, controls, streams);
            },
        );
        self.deliveries.egress.recovery.packet_journals = journals;
        timer::Timer::update(self.deliveries.egress);
    }
}
