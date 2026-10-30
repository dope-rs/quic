use o3::buffer;
use std::{num::NonZero, time};

use crate::conn::output::transmit::builder::{ack, crypto::Room};
use crate::conn::output::transmit::permit::{AppIntent, CryptoIntent, Permit};
use crate::{
    conn::{
        self,
        output::{
            control::{encode, journal::cursor},
            transmit::{builder, packet::seals},
        },
        stream::state::receive,
        wire::path,
    },
    proto::recovery::numbers,
    stream,
    wire::{
        packet::{self, header, header::widths::Width, kind},
        stream::Initiator,
    },
};

pub(in crate::conn) fn loss_deadline<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>(
    permit: &Permit<'_, DOMAIN, B, D>,
) -> Option<time::Instant> {
    let timer = &permit.connection.egress.recovery.timer;
    let loss = timer.loss?;
    if timer.pto_epoch.is_none_or(|epoch| can_probe(permit, epoch)) {
        Some(loss)
    } else {
        None
    }
}

pub(in crate::conn) fn timer_deadline<
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
>(
    permit: &Permit<'_, DOMAIN, B, D>,
) -> Option<time::Instant> {
    super::earliest(
        loss_deadline(permit),
        permit.connection.egress.recovery.timer.idle,
    )
}

/// Admits one long-header packet from this exact connection observation.
pub(in crate::conn::output::transmit) fn crypto<
    K: numbers::AckSpace + seals::LongKind<DOMAIN>,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
>(
    permit: &Permit<'_, DOMAIN, B, D>,
    max: usize,
) -> Option<(numbers::Packet, NonZero<usize>, bool)> {
    let conn = permit.connection;
    let elicits = K::TYPE != packet::LONG_INITIAL || max >= conn::MIN_INITIAL_LEN;
    if !elicits && matches!(conn.peer.local, Initiator::Client) {
        return None;
    }
    K::write_key(conn.handshake.keys())?;
    let number = K::EPOCH.bind(&conn.egress.recovery.spaces).next()?;
    let limit =
        builder::Builder::<'_, DOMAIN, B, D>::limit_for::<K>(&conn.path, max, number.encoded_len());
    let limit = NonZero::new(limit)?;
    if limit.get() < header::Payload::new(1, Width::from_pn(number.encoding())).get() {
        return None;
    }
    Some((number, limit, elicits))
}

pub(in crate::conn) fn can_probe<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>(
    permit: &Permit<'_, DOMAIN, B, D>,
    epoch: conn::Epoch,
) -> bool {
    let conn = permit.connection;
    if conn.egress.lifecycle.pending_close.is_some() {
        return false;
    }
    let pn = epoch.bind(&conn.egress.recovery.spaces).next_pn;
    let journals = &conn.egress.recovery.packet_journals;
    if !journals.space(epoch).has_room_for(pn, 1)
        || (epoch == conn::Epoch::Application
            && !journals.has_carriers(conn::PACKET_CONTROL_CAPACITY, conn::PACKET_STREAM_CAPACITY))
    {
        return false;
    }
    if conn.egress.activity.peer_address_validated && epoch != conn::Epoch::Initial {
        return true;
    }
    let Some(max) = permit.send_limit(conn.egress.cc.metrics().current_mtu() as usize) else {
        return false;
    };
    match epoch {
        conn::Epoch::Initial => crypto::<kind::Initial, DOMAIN, B, D>(permit, max)
            .is_some_and(|(_, _, elicits)| elicits),
        conn::Epoch::Handshake => crypto::<kind::Handshake, DOMAIN, B, D>(permit, max).is_some(),
        conn::Epoch::Application => {
            conn.handshake.keys.has_write()
                && epoch
                    .bind(&conn.egress.recovery.spaces)
                    .next()
                    .is_some_and(|number| {
                        builder::Builder::<'_, DOMAIN, B, D>::short_for(
                            &conn.path,
                            max,
                            number.encoding(),
                            path::OutputRoute::ACTIVE,
                        ) != 0
                    })
        }
    }
}

pub(super) fn can_crypto<
    K: numbers::AckSpace + seals::LongKind<DOMAIN>,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
>(
    permit: &Permit<'_, DOMAIN, B, D>,
    now: time::Instant,
    intent: CryptoIntent,
) -> bool {
    let conn = permit.connection;
    if K::TYPE != packet::LONG_INITIAL && conn.egress.activity.peer_address_validated {
        return true;
    }
    let Some(max) = permit.send_limit(conn.egress.cc.metrics().current_mtu() as usize) else {
        return false;
    };
    let Some((number, limit, elicits)) = crypto::<K, DOMAIN, B, D>(permit, max) else {
        return false;
    };
    let limit = limit.get();
    let client = K::TYPE == packet::LONG_INITIAL && matches!(conn.peer.local, Initiator::Client);
    let ack = if client && limit <= conn::MAX_GENERATED_ACK_FRAME_BYTES {
        ack::encoded_len::<K, true>(&conn.receive.packet_numbers, now, limit)
    } else {
        ack::minimum::<K, true>(&conn.receive.packet_numbers, now)
    };
    if let Some(needed) = ack
        && needed <= limit
    {
        return !client
            || needed == limit
            || ((intent != CryptoIntent::AckOnly || permit.can_send(now))
                && conn
                    .egress
                    .recovery
                    .packet_journals
                    .space(K::EPOCH)
                    .has_room_for(number.full(), 2));
    }
    intent == CryptoIntent::CongestionControlledPacket
        && elicits
        && conn
            .egress
            .recovery
            .packet_journals
            .space(K::EPOCH)
            .has_room_for(number.full(), 2)
        && conn
            .handshake
            .crypto
            .select(K::EPOCH, |record| Room::new(limit).limit(record.offset()))
            .is_some()
}

fn control<const MASK: u16, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>(
    permit: &Permit<'_, DOMAIN, B, D>,
    records: Option<cursor::Cursor<'_, MASK>>,
    route: path::OutputRoute,
    limit: usize,
) -> Option<bool> {
    let mut records = records?;
    let selected =
        builder::Builder::<'_, DOMAIN, B, D>::select(permit.connection, &mut records, route)?;
    Some(
        encode::Encoder::new(&permit.connection.path)
            .minimum(selected)
            .is_some_and(|needed| needed.get() <= limit),
    )
}

pub(super) fn can_app<
    const DUE: bool,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
>(
    permit: &Permit<'_, DOMAIN, B, D>,
    now: time::Instant,
    intent: AppIntent,
) -> bool {
    let conn = permit.connection;
    if conn.egress.activity.peer_address_validated
        && (intent != AppIntent::CongestionControlledPacket
            || !conn.path.output().has_output(&conn.control))
    {
        return true;
    }
    let Some(number) = conn::Epoch::Application
        .bind(&conn.egress.recovery.spaces)
        .next()
    else {
        return false;
    };
    let Some(max) = permit.send_limit(conn.egress.cc.metrics().current_mtu() as usize) else {
        return false;
    };
    let (route, max) = if intent == AppIntent::CongestionControlledPacket {
        let permit = conn.path.output().permit(&conn.control, max, &number);
        (permit.route(), permit.ceiling())
    } else {
        (path::OutputRoute::ACTIVE, max)
    };
    let limit =
        builder::Builder::<'_, DOMAIN, B, D>::short_for(&conn.path, max, number.encoding(), route);
    if limit == 0 {
        return false;
    }
    if intent == AppIntent::AckOnly {
        return ack::minimum::<kind::OneRtt, DUE>(&conn.receive.packet_numbers, now)
            .is_some_and(|needed| needed <= limit);
    }
    if intent == AppIntent::CongestionControlledDatagram {
        return permit.can_track()
            && conn
                .egress
                .datagrams
                .pending_datagrams
                .front()
                .is_some_and(|data| data.len() < limit);
    }
    let ready = conn.control.ready();
    if route.path().is_some() {
        return control(permit, ready.responses(), route, limit)
            .or_else(|| control(permit, ready.challenges(), route, limit))
            .unwrap_or(false);
    }
    if ack::minimum::<kind::OneRtt, false>(&conn.receive.packet_numbers, now)
        .is_some_and(|needed| needed <= limit)
    {
        return true;
    }
    permit.can_track()
        && (control(permit, ready.prefix(), route, limit).unwrap_or(false)
            || conn
                .handshake
                .crypto
                .select(conn::Epoch::Application, |record| {
                    Room::new(limit).limit(record.offset())
                })
                .is_some()
            || control(permit, ready.response(), route, limit)
                .or_else(|| control(permit, ready.challenge(), route, limit))
                .or_else(|| control(permit, ready.suffix(), route, limit))
                .unwrap_or(false)
            || (conn.egress.activity.peer_address_validated && permit.has_stream()))
}

/// A batch materializes finite dirty work before encoding; runtime output
/// reconciliation then projects the admitted records even if nothing was sent.
pub(super) fn has_app<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>(
    permit: &Permit<'_, DOMAIN, B, D>,
    now: time::Instant,
) -> bool {
    let conn = permit.connection;
    let valid = conn.egress.activity.peer_address_validated;
    let routed = conn.path.output().has_output(&conn.control);
    if valid && !routed {
        return true;
    }
    if conn.egress.derived.is_sendable(&conn.path, &conn.control)
        || conn.control.ready().can_probe()
        || receive::Status::new(&conn.streams.state).can_ctrl(&conn.control)
        || (!valid && permit.has_stream())
    {
        return true;
    }
    (conn
        .receive
        .packet_numbers
        .is_ack_ready::<kind::OneRtt>(now)
        && can_app::<true, DOMAIN, B, D>(permit, now, AppIntent::AckOnly))
        || ((conn
            .control
            .ready()
            .has_sendable(&conn.streams.local_initiated, conn.streams.local())
            || conn.handshake.crypto.has_sendable(conn::Epoch::Application)
            || (valid && permit.has_stream()))
            && can_app::<false, DOMAIN, B, D>(permit, now, AppIntent::CongestionControlledPacket))
        || (!conn.egress.datagrams.pending_datagrams.is_empty()
            && can_app::<false, DOMAIN, B, D>(permit, now, AppIntent::CongestionControlledDatagram))
        || (permit.can_track()
            && conn.egress.cc.metrics().next_probe().is_some_and(|probe| {
                permit
                    .send_limit(probe.get())
                    .is_some_and(|max| probe.get() <= max)
            }))
}
