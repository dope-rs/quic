use std::{net, time};

use o3::buffer::{self, storage::Shared};

pub(in crate::conn) mod storage;

use crate::{conn, stream, wire::varint};
use conn::stream::Streams;
use conn::{output, wire};
use output::{control, recovery};
use path::reset;
use recovery::timer;
use wire::{path, tls};

pub(crate) enum Reset {
    Ignore,
    Accept,
}

#[must_use]
pub(in crate::conn) struct CloseChange;

impl CloseChange {
    pub(in crate::conn) fn effects(self) -> conn::Effects {
        conn::Effects::from_bits(conn::Effects::LIFECYCLE)
    }
}

pub(crate) struct Machine<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment = Shared> {
    pub(in crate::conn) egress: output::Egress,
    pub(in crate::conn) control: control::Pending,
    pub(in crate::conn) handshake: tls::Handshake<DOMAIN>,
    pub(in crate::conn) path: path::State,
    pub(in crate::conn) streams: Streams<B, D>,
    pub(in crate::conn) receive: conn::ReceiveState<B>,
    pub(in crate::conn) scratch: conn::Scratch,
    pub(in crate::conn) peer: conn::PeerState,
}

impl<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Machine<DOMAIN, B, D> {
    pub(in crate::conn) fn deadline(&self) -> Option<time::Instant> {
        if self.is_closing() {
            None
        } else {
            self.peer.application_deadline
        }
    }

    pub(in crate::conn) fn is_closing(&self) -> bool {
        self.egress.lifecycle.state == conn::State::Closed
            || self.egress.lifecycle.pending_close.is_some()
    }

    pub(in crate::conn) fn set_deadline(&mut self, due: Option<time::Instant>) -> conn::Mutation {
        let due = due.filter(|_| !self.is_closing());
        if self.peer.application_deadline == due && !self.peer.application_timeout {
            return conn::Mutation::Unchanged;
        }
        self.peer.application_deadline = due;
        self.peer.application_timeout = false;
        if due.is_some() {
            conn::Mutation::Replaced
        } else {
            conn::Mutation::Cleared
        }
    }

    pub(in crate::conn) fn try_pto(
        &mut self,
    ) -> Result<(time::Duration, time::Duration), conn::Timing> {
        let delay = match &self.peer.transport_params {
            Some(params) => time::Duration::from_millis(u64::from(params.timing().ack_ms())),
            None => time::Duration::ZERO,
        };
        self.egress
            .recovery
            .rtt
            .try_pto(delay)
            .map(|pto| (delay, pto))
            .map_err(|error| self.fail_timing(error))
    }

    pub(in crate::conn) fn try_timers(
        &mut self,
        now: time::Instant,
        changed: bool,
        admitted: Option<(time::Duration, time::Duration)>,
    ) -> Result<(), conn::Timing> {
        let timer = timer::Timer::new(self)
            .try_prepare(now, changed, admitted)
            .map_err(|error| self.fail_timing(error))?;
        self.egress.recovery.timer = timer;
        Ok(())
    }

    pub(in crate::conn) fn try_idle(&mut self) -> Result<(), conn::Timing> {
        let idle = timer::Timer::new(self)
            .try_activity(self.egress.activity.last_activity, None)
            .map_err(|error| self.fail_timing(error))?;
        self.egress.recovery.timer.idle = idle;
        Ok(())
    }

    pub(in crate::conn) fn fail_timing(&mut self, error: conn::Timing) -> conn::Timing {
        self.egress.lifecycle.state = conn::State::Closed;
        self.set_deadline(None);
        self.peer.reconcile.set_ready(false);
        self.peer.reconcile.insert(conn::Effects::LIFECYCLE);
        error
    }

    pub(in crate::conn) fn record<const RECONCILE: bool>(&mut self, bits: u8) {
        if RECONCILE {
            self.peer.reconcile.insert(bits);
        }
    }

    pub(in crate::conn) fn reset(
        &mut self,
        source: Option<net::SocketAddr>,
        token: reset::Token,
    ) -> Reset {
        if self.egress.lifecycle.state != conn::State::Established
            || !self.path.ingress().has_reset(source, token)
        {
            return Reset::Ignore;
        }
        self.egress.lifecycle.state = conn::State::Closed;
        self.control.queue().reset();
        Reset::Accept
    }

    pub(in crate::conn) fn close(&mut self, error: &conn::Error) -> Option<CloseChange> {
        if let conn::Error::Timing(error) = error {
            let changed = self.egress.lifecycle.state != conn::State::Closed;
            self.fail_timing(*error);
            return changed.then_some(CloseChange);
        }
        let code = error.close_code()?;
        self.queue_close(output::PendingClose::transport(code, varint::VarInt::ZERO))
    }

    pub(in crate::conn) fn queue_close(
        &mut self,
        close: output::PendingClose,
    ) -> Option<CloseChange> {
        if self.is_closing() {
            return None;
        }
        self.egress.lifecycle.pending_close = Some(close);
        self.set_deadline(None);
        self.peer.reconcile.set_ready(false);
        Some(CloseChange)
    }
}
