use crate::conn::output::transmit::builder::ack;
use crate::conn::stream::state::transmit::log::journal::{self, Entry};
use crate::security::crypto::output;
use o3::buffer::{self, write};

use std::{ops::ControlFlow, time};

use crate::{
    conn::{
        self,
        output::{
            control::encode,
            transmit::{self, builder, builder::pending, packet::plan::Plan},
        },
        stream::state::transmit::log,
        wire::path,
    },
    proto::recovery::pmtud,
    stream::{self, send},
    wire::{
        frame,
        packet::{kind, short},
    },
};
use builder::app::probe;

pub(in crate::conn::output::transmit) fn build<
    'connection,
    const PTO_PROBE: bool,
    const ACK_ONLY: bool,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
>(
    mut build: builder::Builder<'connection, DOMAIN, B, D>,
    now: time::Instant,
    dst: &mut write::Append<'_>,
    max: usize,
    permit: Option<path::OutputPermit>,
    pad: bool,
) -> transmit::Built<'connection, DOMAIN, B, D> {
    use builder::crypto;

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
    let route = permit
        .as_ref()
        .map_or(path::OutputRoute::ACTIVE, |permit| permit.route());
    let selected = build.connection.path.output().cid(route);
    let active = *build.connection.path.peer.id();
    let dcid = if selected == active.as_ref_id() {
        active
    } else {
        let Some(item) = build.connection.path.peer.spare().copied() else {
            return Ok(None);
        };
        if selected != item.as_ref_id() {
            return Ok(None);
        }
        item
    };
    let limit = build.short_limit(max, number.encoding(), route);
    if limit == 0 {
        return Ok(None);
    }
    let mut draft = output::Draft::try_new(
        dst.append(),
        short::Ref::new(dcid.as_ref_id(), number.encoding(), phase),
    )
    .map_err(transmit::Admission::Protection)?;
    let policy = build.destination;
    let (commit, build) = {
        let mut frames = draft.append();
        let mut commit = Plan::new(conn::Epoch::Application, number);
        if let Some(permit) = permit {
            commit.path.route = permit.into_route();
        }
        let mut select = false;
        if ACK_ONLY {
            if PTO_PROBE {
                return Ok(None);
            }
            commit.flags.ack = ack::append::<kind::OneRtt, true>(
                &build.connection.receive.packet_numbers,
                now,
                &mut frames,
                limit,
            )
            .map_err(transmit::Admission::into_error)?;
        } else if PTO_PROBE {
            if matches!(
                probe::Probe::new(&mut build).one_rtt(now, &mut frames, limit, &mut commit)?,
                probe::Append::Full
            ) {
                return Ok(None);
            }
        } else {
            let track = build.can_track();
            let other = commit.path.route.path().is_some();
            if other {
                if let builder::Selection::Empty =
                    build.put(|ready| ready.responses(), &mut frames, limit, &mut commit)?
                {
                    build.put(|ready| ready.challenges(), &mut frames, limit, &mut commit)?;
                }
            } else {
                commit.flags.ack = ack::append::<kind::OneRtt, false>(
                    &build.connection.receive.packet_numbers,
                    now,
                    &mut frames,
                    limit,
                )
                .map_err(transmit::Admission::into_error)?;
                let control = track
                    && build.connection.control.ready().has_sendable(
                        &build.connection.streams.local_initiated,
                        build.connection.streams.local(),
                    );
                if control {
                    build.put(|ready| ready.prefix(), &mut frames, limit, &mut commit)?;
                }
                let room = limit.saturating_sub(frames.len());
                if track {
                    crypto::append::<false>(
                        &build.connection.handshake.crypto,
                        build.crypto,
                        conn::Epoch::Application,
                        room,
                        &mut frames,
                    )?;
                }
                if build.crypto.is_some() {
                    commit.flags.set_elicit(true);
                }
                if control
                    && let builder::Selection::Empty =
                        build.put(|ready| ready.response(), &mut frames, limit, &mut commit)?
                    && let builder::Selection::Empty =
                        build.put(|ready| ready.challenge(), &mut frames, limit, &mut commit)?
                {
                    build.put(|ready| ready.suffix(), &mut frames, limit, &mut commit)?;
                }
                let mut left = conn::PACKET_STREAM_CAPACITY;
                let mut work = log::RetryWork::new(&mut left);
                while track && let Some(vacant) = build.streams.vacancy() {
                    let room = limit
                        .saturating_sub(frames.len().saturating_add(conn::STREAM_FRAME_OVERHEAD));
                    let transmit = &mut build.connection.streams.state.transmit;
                    let (mut chosen, map) = transmit.selection();
                    let next = chosen
                        .retry(room, &mut work, |retry, sender, record| {
                            if vacant.as_slice().iter().any(
                                |delivery| matches!(*delivery, Entry::Retry(item) if item == retry),
                            ) {
                                return Ok(log::Append::Skip);
                            }
                            let Some((resolved, chunks)) = map.read(sender) else {
                                return Ok(log::Append::Retired);
                            };
                            if resolved.id() != record.id {
                                return Ok(log::Append::Retired);
                            }
                            if builder::Builder::<DOMAIN, B, D>::put_stream(
                                &mut frames,
                                limit,
                                record.id,
                                resolved.state(),
                                chunks,
                                record.range,
                            )?
                            .is_none()
                            {
                                return Ok(log::Append::Full);
                            }
                            Ok(log::Append::Done)
                        })
                        .map_err(|error| transmit::Admission::Payload {
                            error,
                            requested: limit,
                        })?;
                    let Some(retry) = next else { break };
                    vacant.insert(Entry::Retry(retry));
                    commit.flags.set_elicit(true);
                }
                select = track;
            }
        }

        let mut schedule = journal::Schedule::new(build);
        let mut fresh = Some(0u64);
        if select {
            loop {
                let step = schedule.next(
                    |mut selected, context| -> Result<ControlFlow<()>, transmit::Admission> {
                        let Some(total) = fresh else {
                            return Ok(ControlFlow::Break(()));
                        };
                        let (credit, boundary) = {
                            let entry = selected.state();
                            let view = entry.view();
                            (
                                entry
                                    .credit()
                                    .limit()
                                    .get()
                                    .saturating_sub(view.next_offset().get()),
                                view.boundary(0),
                            )
                        };
                        let budget = selected.budget(total);
                        let flow = credit.min(budget);
                        if flow == 0 && matches!(boundary, send::Boundary::More) {
                            let pending = selected.state().view().has_pending();
                            if budget == 0
                                && let Some(control) = context.controls.vacancy()
                                && !control
                                    .as_slice()
                                    .iter()
                                    .any(|item| item.kind() == frame::Kind::DataBlocked)
                            {
                                selected.try_data(
                                    context.control,
                                    |selected| -> Result<(), transmit::Admission> {
                                        if let Some(encode::Write::Done(written)) =
                                            encode::Encoder::new(context.path)
                                                .encode(&mut frames, limit, selected)
                                                .map_err(|error| transmit::Admission::Payload {
                                                    error,
                                                    requested: limit,
                                                })?
                                        {
                                            control.insert(written);
                                            commit.flags.set_elicit(true);
                                        }
                                        Ok(())
                                    },
                                )?;
                            }
                            if credit == 0
                                && pending
                                && let Some(control) = context.controls.vacancy()
                            {
                                selected.try_stream(
                                    context.control,
                                    |selected| -> Result<(), transmit::Admission> {
                                        if let Some(encode::Write::Done(written)) =
                                            encode::Encoder::new(context.path)
                                                .encode(&mut frames, limit, selected)
                                                .map_err(|error| transmit::Admission::Payload {
                                                    error,
                                                    requested: limit,
                                                })?
                                        {
                                            control.insert(written);
                                            commit.flags.set_elicit(true);
                                        }
                                        Ok(())
                                    },
                                )?;
                            }
                            return Ok(ControlFlow::Continue(()));
                        }
                        let room = limit.saturating_sub(
                            frames.len().saturating_add(conn::STREAM_FRAME_OVERHEAD),
                        );
                        let take = flow.min(room as u64) as usize;
                        if take == 0 && matches!(boundary, send::Boundary::More) {
                            return Ok(ControlFlow::Break(()));
                        }
                        let Some(prepared) = selected.prepare(take) else {
                            return Ok(ControlFlow::Continue(()));
                        };
                        let range = prepared.range();
                        if !prepared.write(&mut frames, limit).map_err(|error| {
                            transmit::Admission::Payload {
                                error,
                                requested: limit,
                            }
                        })? {
                            return Ok(ControlFlow::Break(()));
                        }
                        fresh = total.checked_add(range.len());
                        commit.flags.set_elicit(true);
                        Ok(ControlFlow::Continue(()))
                    },
                )?;
                if !matches!(step, Some(ControlFlow::Continue(()))) {
                    break;
                }
            }
        }
        let build = schedule.finish();

        if frames.is_empty() {
            return Ok(None);
        }

        if pad && commit.flags.is_eliciting() && frames.len() < limit {
            let needed = limit - frames.len();
            frames
                .try_fill(needed, frame::TYPE_PADDING)
                .map_err(|error| transmit::Admission::Payload {
                    error,
                    requested: needed,
                })?;
        }

        if build.owner().controls().iter().any(|delivery| {
            matches!(
                delivery.kind(),
                frame::Kind::PathChallenge | frame::Kind::PathResponse
            )
        }) {
            let padded = builder::Builder::<DOMAIN, B, D>::short_for(
                &build.owner().conn().path,
                pmtud::BASE_PMTU as usize,
                commit.packet_number.encoding(),
                route,
            )
            .min(limit);
            if frames.len() < padded {
                let needed = padded - frames.len();
                frames
                    .try_fill(needed, frame::TYPE_PADDING)
                    .map_err(|error| transmit::Admission::Payload {
                        error,
                        requested: needed,
                    })?;
            }
        }

        let elicit = commit.flags.is_eliciting();
        commit.flags.set_flight(elicit);
        (commit, build)
    };
    let Some(target) = build.owner().target(policy, commit.path.route) else {
        return Ok(None);
    };
    let prepared =
        pending::Packet::try_new(build, commit, target).map_err(|(_, error)| error.into_error())?;
    let ((), prepared) = match prepared.protect(draft) {
        Ok(output) => output,
        Err(failure) => {
            return failure.into_error().map_or(Ok(None), Err);
        }
    };
    Ok(Some(prepared))
}
