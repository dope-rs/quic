use crate::stream::release;
use o3::buffer;

use std::{mem, time};

use crate::conn::output::recovery::delivery;
use crate::proto::recovery::rtt;
use crate::{conn, stream};

/// Retransmits old-path flight before installing fresh recovery state.
pub(in crate::conn) struct Shift<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    delivery: delivery::Delivery<'a, DOMAIN, B, D, release::Ignore>,
}

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Shift<'a, DOMAIN, B, D> {
    pub(in crate::conn) fn new(
        graph: delivery::Graph<'a, DOMAIN, B, D>,
        proof: release::Ignore,
    ) -> Self {
        Self {
            delivery: delivery::Delivery::new(graph, proof),
        }
    }

    pub(in crate::conn) fn try_commit(mut self, now: time::Instant) -> Result<(), conn::Timing> {
        let epoch = conn::Epoch::Application;
        let mut journals = mem::take(&mut self.delivery.egress.recovery.packet_journals);
        journals.space_mut(epoch).drain_where(
            |_| true,
            |journal, controls, streams| {
                self.delivery.lose(journal, controls, streams);
            },
        );
        self.delivery.egress.recovery.packet_journals = journals;
        self.delivery.egress.recovery.probe.count.reset();
        self.delivery.egress.recovery.probe.allowance.clear();
        self.delivery.egress.recovery.probe.epoch = None;
        *epoch.bind_mut(&mut self.delivery.egress.recovery.streaks) = Default::default();
        self.delivery.egress.recovery.rtt = rtt::RttTracker::default();
        self.delivery.egress.cc.restart_path();
        self.delivery.egress.activity.peer_address_validated = true;
        self.delivery.try_update(now)
    }
}
