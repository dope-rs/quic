use crate::stream::release;
use o3::buffer;

use std::{mem, time};

use crate::conn::output::recovery::delivery;
use crate::{conn, stream};

pub(in crate::conn) struct EarlyData<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
{
    delivery: delivery::Delivery<'a, DOMAIN, B, D, release::Ignore>,
}

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> EarlyData<'a, DOMAIN, B, D> {
    pub(in crate::conn) fn new(
        graph: delivery::Graph<'a, DOMAIN, B, D>,
        proof: release::Ignore,
    ) -> Self {
        Self {
            delivery: delivery::Delivery::new(graph, proof),
        }
    }

    pub(in crate::conn) fn try_reject(mut self, now: time::Instant) -> Result<(), conn::Error> {
        if conn::Epoch::Application
            .bind(&self.delivery.egress.recovery.spaces)
            .largest_acked
            .is_some()
        {
            return Err(conn::Error::ProtocolViolation);
        }
        let mut journals = mem::take(&mut self.delivery.egress.recovery.packet_journals);
        journals.space_mut(conn::Epoch::Application).drain_where(
            |journal| journal.transmission.is_early(),
            |journal, controls, streams| {
                self.delivery.lose(journal, controls, streams);
            },
        );
        self.delivery.egress.recovery.packet_journals = journals;
        self.delivery
            .streams
            .transmit
            .reject_early(self.delivery.control)?;
        self.delivery.try_update(now).map_err(conn::Error::from)
    }
}
