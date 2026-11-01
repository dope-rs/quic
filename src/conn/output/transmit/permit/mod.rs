use o3::buffer;
use std::{num::NonZero, time};

use crate::{
    conn::{
        self,
        output::transmit::{builder, packet::seals},
        stream::state::{receive, streams, transmit::queue},
    },
    proto::recovery::numbers,
    stream::{self, send},
    wire::packet::{header, header::widths, kind},
};
use builder::app::terminal;

pub(in crate::conn) mod fit;

#[inline]
pub(in crate::conn) fn earliest(
    first: Option<time::Instant>,
    second: Option<time::Instant>,
) -> Option<time::Instant> {
    match (first, second) {
        (Some(first), Some(second)) => Some(first.min(second)),
        (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
        (None, None) => None,
    }
}

/// Exact builder capability selected by the shared readiness projection.
/// ACK-only variants cannot append ack-eliciting frames. Required Initial
/// padding still participates in congestion control.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::conn) enum CryptoIntent {
    AckOnly,
    CongestionControlledPacket,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::conn) enum AppIntent {
    AckOnly,
    CongestionControlledPacket,
    CongestionControlledDatagram,
}

pub(crate) struct Permit<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> {
    pub(super) connection: &'a conn::Machine<DOMAIN, B, D>,
}

/// One isolated pooled send's checked header and positive wire ceiling.
pub(in crate::conn::output::transmit) struct Admitted {
    phase: bool,
    number: numbers::Packet,
    limit: NonZero<usize>,
}

impl Admitted {
    pub(in crate::conn::output::transmit) fn into_parts(
        self,
    ) -> (bool, numbers::Packet, NonZero<usize>) {
        (self.phase, self.number, self.limit)
    }
}

pub(in crate::conn::output::transmit) enum Pooled {
    Ready(Admitted),
    Paced(time::Instant),
}

/// Dirty work requests a projection; only an armed, admitted retry is an event.
pub(crate) fn reconcile<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>(
    conn: &mut conn::Machine<DOMAIN, B, D>,
    now: time::Instant,
) -> Option<time::Instant> {
    if !conn.streams.events.has_retry() {
        return None;
    }
    if conn.is_closing() {
        conn.streams.events.clear_retry();
        conn.record::<true>(conn::Effects::SCHEDULER);
        return None;
    }
    match Permit::new(conn).pooled(now, NonZero::<usize>::MAX)? {
        Pooled::Paced(due) => return Some(due),
        Pooled::Ready(_) => {}
    }
    conn.streams.events.clear_retry();
    conn.streams.events.set_writable();
    conn.record::<true>(conn::Effects::NOTIFY | conn::Effects::SCHEDULER);
    None
}

impl<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Permit<'_, DOMAIN, B, D> {
    pub(crate) fn new(conn: &conn::Machine<DOMAIN, B, D>) -> Permit<'_, DOMAIN, B, D> {
        Permit { connection: conn }
    }

    pub(crate) fn is_isolated(&self) -> bool {
        let conn = self.connection;
        conn.egress.lifecycle.state != conn::State::Closed
            && !conn.egress.derived.is_pending()
            && !receive::Status::new(&conn.streams.state).has_ctrl()
            && !conn
                .control
                .ready()
                .has_sendable(&conn.streams.local_initiated, conn.streams.local())
            && conn.handshake.keys.has_write()
            && !conn.egress.recovery.probe.allowance.is_armed()
            && conn.egress.lifecycle.pending_close.is_none()
            && (!conn.handshake.crypto.has_sendable(conn::Epoch::Initial)
                && !conn.receive.packet_numbers.has_ack::<kind::Initial>())
            && (!conn.handshake.crypto.has_sendable(conn::Epoch::Handshake)
                && !conn.receive.packet_numbers.has_ack::<kind::Handshake>())
            && !conn.control.probe().has_work()
            && !conn.handshake.crypto.has_sendable(conn::Epoch::Application)
            && !conn.streams.transmit.deliveries().has_retry()
            && !conn.streams.transmit.map().view().has_pending()
            && conn.egress.cc.metrics().next_probe().is_none()
    }

    pub(in crate::conn::output::transmit) fn can_track(&self) -> bool {
        let conn = self.connection;
        let pn = conn::Epoch::Application
            .bind(&conn.egress.recovery.spaces)
            .next_pn;
        let journals = &conn.egress.recovery.packet_journals;
        let groups = conn.streams.transmit.deliveries();
        journals.space(conn::Epoch::Application).has_room_for(pn, 2)
            && journals.has_carriers(
                conn::PACKET_CONTROL_CAPACITY * 2,
                conn::PACKET_STREAM_CAPACITY * 2,
            )
            && (groups.has_retry() || groups.has_room(conn::PACKET_STREAM_CAPACITY * 2))
    }

    /// Shares admission between direct publication and externally retained retries.
    pub(in crate::conn::output::transmit) fn pooled(
        &self,
        now: time::Instant,
        max: NonZero<usize>,
    ) -> Option<Pooled> {
        let conn = self.connection;
        if !conn.egress.datagrams.pending_datagrams.is_empty() || !self.is_isolated() {
            return None;
        }
        let phase = conn.handshake.keys.write()?.is_key_phase();
        let number = conn::Epoch::Application
            .bind(&conn.egress.recovery.spaces)
            .next()?;
        if !self.can_track() {
            return None;
        }
        let normal = max
            .get()
            .min(conn.egress.cc.metrics().current_mtu() as usize);
        let limit = NonZero::new(self.send_limit(normal)?)?;
        let flight = conn.egress.recovery.in_flight()?;
        if !conn.egress.cc.allows_send(now, flight) {
            if conn.egress.cc.has_window(flight) {
                return conn.egress.cc.release().map(Pooled::Paced);
            }
            return None;
        }
        Some(Pooled::Ready(Admitted {
            phase,
            number,
            limit,
        }))
    }

    pub(crate) fn retry_at(&self, now: time::Instant) -> Option<time::Instant> {
        if !self.connection.streams.events.has_retry() {
            return None;
        }
        match self.pooled(now, NonZero::<usize>::MAX)? {
            Pooled::Ready(_) => Some(now),
            Pooled::Paced(due) => Some(due),
        }
    }

    /// Selects GSO only when exact byte ledgers predict a useful train.
    pub(crate) fn is_gso_ready(&self, bytes: usize, packets: usize) -> bool {
        let queue = &self.connection.egress.datagrams.pending_datagrams;
        if packets <= 1 {
            return true;
        }
        if queue.is_empty() {
            let streams = &self.connection.streams.transmit;
            let pn_len = conn::Epoch::Application
                .bind(&self.connection.egress.recovery.spaces)
                .next()
                .map_or(usize::from(conn::MAX_PACKET_NUMBER_LEN), |number| {
                    usize::from(number.encoded_len())
                });
            let payload = bytes
                .saturating_sub(1 + self.connection.path.peer.id().len() + pn_len + conn::TAG_LEN);
            return streams.deliveries().has_floor(payload, packets)
                || streams.map().view().pending() > bytes.saturating_mul(packets - 1);
        }
        self.connection.egress.datagrams.bytes() > bytes.saturating_mul(packets - 1)
    }

    /// Returns an isolated DATAGRAM wire size safe for cross-connection GSO.
    pub(crate) fn gso_len(&self, now: time::Instant, max: usize) -> Option<usize> {
        let conn = self.connection;
        if !self.is_isolated()
            || conn.receive.packet_numbers.has_ack::<kind::OneRtt>()
            || conn.path.output().has_output(&conn.control)
            || !self.can_send(now)
        {
            return None;
        }
        let payload = conn.egress.datagrams.pending_datagrams.front()?.len();
        let number = conn::Epoch::Application
            .bind(&conn.egress.recovery.spaces)
            .next()?;
        let width = widths::Width::from_pn(number.encoding());
        let body = header::Payload::new(payload + 1, width).get();
        let packet = 1 + conn.path.peer.id().len() + width.get() + body + conn::TAG_LEN;
        let normal = max.min(conn.egress.cc.metrics().current_mtu() as usize);
        let allowed = self.send_limit(normal)?;
        (packet <= allowed).then_some(packet)
    }

    pub(in crate::conn) fn can_send(&self, now: time::Instant) -> bool {
        let Some(flight) = self.connection.egress.recovery.in_flight() else {
            return false;
        };
        self.connection.egress.activity.amp_credit() != 0
            && self.connection.egress.cc.allows_send(now, flight)
    }

    pub(in crate::conn::output::transmit) fn plan_crypto<
        K: numbers::AckSpace + seals::LongKind<DOMAIN>,
    >(
        &self,
        now: time::Instant,
    ) -> Option<CryptoIntent> {
        let conn = self.connection;
        K::write_key(conn.handshake.keys())?;
        let intent = if conn.handshake.crypto.has_sendable(K::EPOCH) && self.can_send(now) {
            CryptoIntent::CongestionControlledPacket
        } else if conn.receive.packet_numbers.is_ack_ready::<K>(now)
            && conn.egress.activity.amp_credit() != 0
        {
            CryptoIntent::AckOnly
        } else {
            return None;
        };
        fit::can_crypto::<K, DOMAIN, B, D>(self, now, intent).then_some(intent)
    }

    /// Projects one Application-space send from authoritative owner ledgers.
    /// Ordering preserves ACK coalescing when an in-flight packet may be sent,
    /// but falls back to a physically ACK-only packet when cwnd/pacing blocks.
    pub(in crate::conn) fn plan_one_rtt(&self, now: time::Instant) -> Option<AppIntent> {
        let conn = self.connection;
        if !conn.handshake.keys.has_write() {
            return None;
        }
        let ack = conn
            .receive
            .packet_numbers
            .is_ack_ready::<kind::OneRtt>(now)
            && fit::can_app::<true, DOMAIN, B, D>(self, now, AppIntent::AckOnly);
        if ack && conn.path.output().has_output(&conn.control) {
            return Some(AppIntent::AckOnly);
        }
        let can_send = self.can_send(now);
        let packet = conn
            .control
            .ready()
            .has_sendable(&conn.streams.local_initiated, conn.streams.local())
            || conn.handshake.crypto.has_sendable(conn::Epoch::Application)
            || conn.streams.transmit.deliveries().has_retry()
            || conn.streams.transmit.has_snapshot();
        let intent = if can_send && packet {
            AppIntent::CongestionControlledPacket
        } else if can_send && !conn.egress.datagrams.pending_datagrams.is_empty() {
            AppIntent::CongestionControlledDatagram
        } else if ack {
            return Some(AppIntent::AckOnly);
        } else {
            return None;
        };
        fit::can_app::<true, DOMAIN, B, D>(self, now, intent).then_some(intent)
    }

    pub(crate) fn has_pending(&self) -> bool {
        let conn = self.connection;
        if conn.egress.lifecycle.state == conn::State::Closed {
            return false;
        }
        if self.has_close() || conn.egress.recovery.probe.allowance.is_armed() {
            return true;
        }
        if conn.handshake.keys.long.initial().is_some()
            && (conn.handshake.crypto.has_sendable(conn::Epoch::Initial)
                || conn.receive.packet_numbers.has_ack::<kind::Initial>())
        {
            return true;
        }
        if conn.handshake.keys.long.early().is_some()
            && !conn.handshake.keys.has_write()
            && conn.streams.transmit.map().view().has_pending()
        {
            return true;
        }
        if conn.handshake.keys.long.handshake().is_some()
            && (conn.handshake.crypto.has_sendable(conn::Epoch::Handshake)
                || conn.receive.packet_numbers.has_ack::<kind::Handshake>())
        {
            return true;
        }
        conn.handshake.keys.has_write()
            && (conn.receive.packet_numbers.has_ack::<kind::OneRtt>()
                || !conn.egress.datagrams.pending_datagrams.is_empty()
                || conn.egress.derived.is_pending()
                || conn.control.probe().has_work()
                || receive::Status::new(&conn.streams.state).has_ctrl()
                || !conn.control.ready().is_empty()
                || conn.handshake.crypto.has_sendable(conn::Epoch::Application)
                || conn.streams.transmit.deliveries().has_retry()
                || conn.streams.transmit.map().view().has_pending()
                || conn.egress.cc.metrics().next_probe().is_some())
    }

    pub(crate) fn deadline(&self, now: time::Instant) -> Option<time::Instant> {
        let conn = self.connection;
        if !self.has_pending() {
            return None;
        }
        if let Some(close) = conn.egress.lifecycle.pending_close.as_ref() {
            return self
                .send_limit(conn.egress.cc.metrics().current_mtu() as usize)
                .and_then(|max| terminal::admit(conn, close, max))
                .map(|_| now);
        }
        let amplify = conn.egress.activity.amp_credit() != 0;
        if conn.egress.recovery.probe.allowance.is_armed()
            && conn
                .egress
                .recovery
                .probe
                .epoch
                .is_some_and(|epoch| fit::can_probe(self, epoch))
        {
            return Some(now);
        }
        if amplify {
            let initial = conn.handshake.keys.long.initial().is_some()
                && conn.receive.packet_numbers.has_ack::<kind::Initial>()
                && fit::can_crypto::<kind::Initial, DOMAIN, B, D>(self, now, CryptoIntent::AckOnly);
            let hs = conn.handshake.keys.long.handshake().is_some()
                && conn.receive.packet_numbers.has_ack::<kind::Handshake>()
                && fit::can_crypto::<kind::Handshake, DOMAIN, B, D>(
                    self,
                    now,
                    CryptoIntent::AckOnly,
                );
            let app = conn.handshake.keys.has_write()
                && conn
                    .receive
                    .packet_numbers
                    .is_ack_ready::<kind::OneRtt>(now)
                && fit::can_app::<true, DOMAIN, B, D>(self, now, AppIntent::AckOnly);
            if initial || hs || app {
                return Some(now);
            }
        }
        let recovery = fit::timer_deadline(self);
        let ack_at = if conn.handshake.keys.has_write() && amplify {
            conn.receive
                .packet_numbers
                .ack_deadline()
                .filter(|_| fit::can_app::<false, DOMAIN, B, D>(self, now, AppIntent::AckOnly))
        } else {
            None
        };
        if !self.has_output(now) {
            return earliest(recovery, ack_at);
        }
        let Some(flight) = conn.egress.recovery.in_flight() else {
            return earliest(recovery, ack_at);
        };
        if !amplify || !conn.egress.cc.has_window(flight) {
            return earliest(recovery, ack_at);
        }
        earliest(Some(conn.egress.cc.deadline(now)), ack_at)
    }

    pub(crate) fn send_limit(&self, request: usize) -> Option<usize> {
        let credit = self.connection.egress.activity.amp_credit();
        let ceiling = if credit < request as u64 {
            credit as usize
        } else {
            request
        };
        (ceiling != 0).then_some(ceiling)
    }

    fn has_close(&self) -> bool {
        let conn = self.connection;
        let keys = &conn.handshake.keys;
        conn.egress.lifecycle.pending_close.is_some()
            && (keys.has_write()
                || keys.long.handshake().is_some()
                || keys.long.initial().is_some())
    }

    fn has_stream(&self) -> bool {
        let conn = self.connection;
        if conn.streams.transmit.deliveries().has_retry() {
            return true;
        }
        let budget = conn.streams.transmit.peer.budget(0);
        conn.streams.transmit.map().iter_ready().any(|resolved| {
            if !conn
                .streams
                .local_initiated
                .allows(streams::Relative::new(resolved.id(), conn.streams.local()))
            {
                return false;
            }
            let entry = resolved.state();
            if entry.is_deferred() {
                return conn.control.available().raw() != 0;
            }
            let view = entry.view();
            if !view.has_pending()
                || !matches!(entry.phase(), queue::Phase::Open | queue::Phase::Marked)
            {
                return false;
            }
            if view.unsent_len() == 0 && matches!(view.boundary(0), send::Boundary::End) {
                return true;
            }
            let limit = entry.credit().limit();
            let credit = limit.get().saturating_sub(view.next_offset().get());
            (budget != 0 && credit != 0)
                || (budget == 0
                    && conn
                        .control
                        .ready()
                        .has_blocked(&conn.streams.transmit.peer.data_credit))
                || (credit == 0 && conn.control.ready().has_blocked(entry.credit()))
        })
    }

    fn has_output(&self, now: time::Instant) -> bool {
        let conn = self.connection;
        (conn.handshake.keys.long.initial().is_some()
            && (conn.handshake.crypto.has_sendable(conn::Epoch::Initial)
                || conn.receive.packet_numbers.has_ack::<kind::Initial>())
            && fit::can_crypto::<kind::Initial, DOMAIN, B, D>(
                self,
                now,
                CryptoIntent::CongestionControlledPacket,
            ))
            || (conn.handshake.keys.long.early().is_some()
                && !conn.handshake.keys.has_write()
                && self.has_stream())
            || (conn.handshake.keys.long.handshake().is_some()
                && (conn.handshake.crypto.has_sendable(conn::Epoch::Handshake)
                    || conn.receive.packet_numbers.has_ack::<kind::Handshake>())
                && fit::can_crypto::<kind::Handshake, DOMAIN, B, D>(
                    self,
                    now,
                    CryptoIntent::CongestionControlledPacket,
                ))
            || (conn.handshake.keys.has_write()
                && (conn
                    .receive
                    .packet_numbers
                    .is_ack_ready::<kind::OneRtt>(now)
                    || !conn.egress.datagrams.pending_datagrams.is_empty()
                    || conn.egress.derived.is_sendable(&conn.path, &conn.control)
                    || conn.control.ready().can_probe()
                    || receive::Status::new(&conn.streams.state).can_ctrl(&conn.control)
                    || conn
                        .control
                        .ready()
                        .has_sendable(&conn.streams.local_initiated, conn.streams.local())
                    || conn.handshake.crypto.has_sendable(conn::Epoch::Application)
                    || self.has_stream()
                    || conn.egress.cc.metrics().next_probe().is_some())
                && fit::has_app(self, now))
    }
}
