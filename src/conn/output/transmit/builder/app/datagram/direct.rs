use crate::conn::output::transmit::builder::ack;
use crate::conn::stream::state::transmit::log::journal;
use crate::security::crypto::output;
use o3::buffer::{self, write};
use std::time;

use crate::conn::output::transmit::builder::pending;
use crate::conn::output::transmit::packet::plan::Plan;
use crate::conn::output::transmit::{self, builder};
use crate::conn::wire::path;
use crate::stream;
use crate::wire::packet::{header, header::widths, kind, short};
use crate::{conn, wire::frame};

pub(in crate::conn::output::transmit) fn build<
    'connection,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
>(
    build: builder::Builder<'connection, DOMAIN, B, D>,
    now: time::Instant,
    dst: &mut write::Append<'_>,
    max: usize,
) -> transmit::Built<'connection, DOMAIN, B, D> {
    let Some(write) = build.connection.handshake.keys.write() else {
        return Ok(None);
    };
    let phase = write.is_key_phase();
    let Some(number) = conn::Epoch::Application
        .bind_mut(&mut build.connection.egress.recovery.spaces)
        .next()
    else {
        return Ok(None);
    };
    if !build.can_track() {
        return Ok(None);
    }
    let dcid = *build.connection.path.peer.id();
    let limit = build.short_limit(max, number.encoding(), path::OutputRoute::ACTIVE);
    if limit == 0 {
        return Ok(None);
    }
    let mut draft = output::Draft::try_new(
        dst.append(),
        short::Ref::new(dcid.as_ref_id(), number.encoding(), phase),
    )
    .map_err(transmit::Admission::Protection)?;
    let Some(data) = build.connection.egress.datagrams.pending_datagrams.front() else {
        return Ok(None);
    };
    let bytes = data.len() + 1;
    let width = widths::Width::from_pn(number.encoding());
    let bytes = header::Payload::new(bytes, width).get();
    let (ack, datagram) = {
        let mut frames = draft.append();
        let ack = ack::append::<kind::OneRtt, false>(
            &build.connection.receive.packet_numbers,
            now,
            &mut frames,
            limit.saturating_sub(bytes),
        )
        .map_err(transmit::Admission::into_error)?;
        let datagram = bytes <= limit.saturating_sub(frames.len());
        if datagram {
            let plain = frames.len() + 1 + data.len();
            let padding = header::Payload::padding(plain, width);
            frames
                .try_fill(padding, frame::TYPE_PADDING)
                .map_err(|error| transmit::Admission::Payload {
                    error,
                    requested: padding,
                })?;
            frame::Borrowed::datagram(data)
                .encode(&mut frames)
                .map_err(|error| transmit::Admission::Payload {
                    error,
                    requested: 1 + data.len(),
                })?;
        }
        if frames.is_empty() {
            return Ok(None);
        }
        (ack, datagram)
    };
    let mut commit = Plan::new(conn::Epoch::Application, number);
    commit.flags.ack = ack;
    commit.flags.set_elicit(datagram);
    commit.flags.set_flight(datagram);
    commit.flags.set_datagram(datagram);
    commit.set_queued(datagram);
    let Some(target) = build.target(commit.path.route) else {
        return Ok(None);
    };
    let prepared = pending::Packet::try_new(journal::Schedule::new(build).finish(), commit, target)
        .map_err(|(_, error)| error.into_error())?;
    let ((), prepared) = match prepared.protect(draft) {
        Ok(output) => output,
        Err(failure) => {
            return failure.into_error().map_or(Ok(None), Err);
        }
    };
    Ok(Some(prepared))
}
