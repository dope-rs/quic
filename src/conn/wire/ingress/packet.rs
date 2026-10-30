use o3::buffer;
use std::{net, time};

use crate::wire::packet::header;

use crate::conn;
use crate::conn::output::recovery::{epochs, timer};
use crate::proto::recovery::numbers;
use crate::stream;
use crate::wire::stream::Initiator;

/// Authenticated packet whose number is fresh for its epoch.
/// Its exclusive borrow stabilizes admission until commit. Accepted-state
/// effects survive normal drops and errors; only `try_commit` records its number.
#[must_use = "an admitted packet must be committed or deliberately dropped"]
pub(in crate::conn::wire::ingress) struct Packet<
    'connection,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
> {
    connection: &'connection mut conn::Machine<DOMAIN, B, D>,
    epoch: conn::Epoch,
    fresh: numbers::Fresh,
    discard: epochs::Discarded,
    peer: Option<net::SocketAddr>,
    pending: conn::Effects,
}

impl<'connection, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    Packet<'connection, DOMAIN, B, D>
{
    pub(in crate::conn::wire::ingress) fn begin(
        machine: &'connection mut conn::Machine<DOMAIN, B, D>,
        epoch: conn::Epoch,
        pn: header::Number,
    ) -> Option<Self> {
        if machine.is_closing() {
            return None;
        }
        let fresh = epoch
            .bind(&machine.receive.packet_numbers.spaces)
            .admit(pn)?;
        let peer = machine.path.ingress().peer();
        Some(Self {
            connection: machine,
            epoch,
            fresh,
            discard: epochs::Discarded::default(),
            peer,
            pending: conn::Effects::none(),
        })
    }

    pub(in crate::conn::wire::ingress) fn state(
        &mut self,
    ) -> (&mut conn::Machine<DOMAIN, B, D>, &mut epochs::Discarded) {
        (&mut *self.connection, &mut self.discard)
    }

    fn effects(&self, mut effects: conn::Effects) -> conn::Effects {
        if self.connection.path.ingress().peer() != self.peer
            || self.connection.path.local.is_dirty()
            || self.connection.path.peer.is_dirty()
        {
            effects.insert(conn::Effects::ROUTING);
        }
        effects
    }

    pub(in crate::conn::wire::ingress) fn record(&mut self, effects: conn::Effects) {
        self.pending.merge(effects);
    }

    pub(in crate::conn::wire::ingress) fn close(&mut self, error: &conn::Error) -> conn::Effects {
        self.discard
            .apply(&mut self.connection.receive.packet_numbers);
        let mut effects = self.pending.take();
        if let Some(change) = self.connection.close(error) {
            effects.merge(change.effects());
        }
        if matches!(error, conn::Error::Timing(_)) {
            effects.insert(conn::Effects::LIFECYCLE);
        }
        self.effects(effects)
    }

    pub(in crate::conn::wire::ingress) fn try_drop(
        &mut self,
    ) -> Result<conn::Effects, conn::Timing> {
        self.connection.try_idle()?;
        self.discard
            .apply(&mut self.connection.receive.packet_numbers);
        let effects = self.pending.take();
        Ok(self.effects(effects))
    }

    pub(in crate::conn::wire::ingress) fn try_commit(
        mut self,
        elicits: bool,
        now: time::Instant,
    ) -> Result<conn::Effects, (Self, conn::Timing)> {
        let idle = match timer::Timer::new(&*self.connection).try_activity(Some(now), None) {
            Ok(idle) => idle,
            Err(error) => return Err((self, error)),
        };
        if self.epoch == conn::Epoch::Handshake
            && matches!(self.connection.peer.local, Initiator::Server)
            && self.connection.handshake.keys.long.initial().is_some()
        {
            epochs::Epochs::new(self.connection).discard(conn::Epoch::Initial);
            self.pending.insert(conn::Effects::RECOVERY);
            if let Err(error) = timer::Timer::try_update(
                &mut self.connection.egress,
                &self.connection.handshake.keys,
                self.connection.peer.local,
                now,
            ) {
                return Err((self, error));
            }
        }
        let Self {
            connection: machine,
            epoch,
            fresh,
            discard,
            peer,
            pending: mut effects,
        } = self;
        let schedule = machine
            .receive
            .packet_numbers
            .commit(epoch, fresh, elicits, now);
        discard.apply(&mut machine.receive.packet_numbers);
        match schedule {
            numbers::Schedule::Same => {}
            numbers::Schedule::Changed => {
                effects.insert(conn::Effects::OUTPUT);
                effects.project(conn::DeadlineMode::Earlier);
            }
        }
        machine.egress.activity.last_activity = Some(now);
        machine.egress.recovery.timer.idle = idle;
        machine
            .egress
            .activity
            .ack_eliciting_sent_since_last_receive = false;
        if machine.path.ingress().peer() != peer
            || machine.path.local.is_dirty()
            || machine.path.peer.is_dirty()
        {
            effects.insert(conn::Effects::ROUTING);
        }
        Ok(effects)
    }
}
