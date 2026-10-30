use crate::conn::stream::state::transmit::log::journal;
use o3::buffer::{self, write};

use std::{mem, ops::ControlFlow};

use crate::{
    conn::{
        self,
        output::transmit::{
            self, builder,
            builder::pending,
            packet::{plan::Plan, seals},
        },
    },
    stream::{self, send},
    wire::packet::{self, header, kind, long},
};
use app::probe;
use builder::app;

pub(in crate::conn::output::transmit) fn build<
    'connection,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
>(
    mut build: builder::Builder<'connection, DOMAIN, B, D>,
    dst: &mut write::Append<'_>,
    max: usize,
    is_probe: bool,
) -> transmit::Built<'connection, DOMAIN, B, D> {
    if build.connection.handshake.keys.long.early().is_none() {
        return Ok(None);
    }
    if !is_probe && !build.can_track() {
        return Ok(None);
    }
    let Some(number) = conn::Epoch::Application
        .bind_mut(&mut build.connection.egress.recovery.spaces)
        .next()
    else {
        return Ok(None);
    };
    let pn_len = number.encoded_len();
    let limit = build.limit::<kind::Handshake>(max, pn_len);
    let mut frames = mem::take(&mut build.connection.scratch.frames);
    frames.clear();
    let mut commit = Plan::new(conn::Epoch::Application, number);
    commit.flags.set_early(true);
    if is_probe
        && matches!(
            probe::Probe::new(&mut build)
                .early(&mut frames, limit, &mut commit)
                .inspect_err(|_| build.connection.scratch.frames = mem::take(&mut frames))?,
            probe::Append::Full
        )
    {
        build.connection.scratch.frames = frames;
        return Ok(None);
    }
    let policy = build.destination;
    let unbound = build.connection.peer.transport_params.is_none();
    let mut schedule = journal::Schedule::new(build);
    let mut fresh = 0u64;
    if !is_probe {
        loop {
            let step = schedule.next(
                |mut selected, context| -> Result<ControlFlow<()>, transmit::Admission> {
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
                    let budget = if unbound {
                        u64::MAX
                    } else {
                        selected.budget(fresh)
                    };
                    let room = limit
                        .saturating_sub(frames.len().saturating_add(conn::STREAM_FRAME_OVERHEAD));
                    let take = credit.min(budget).min(room as u64) as usize;
                    if take == 0 && matches!(boundary, send::Boundary::More) {
                        return Ok(ControlFlow::Continue(()));
                    }
                    let Some(prepared) = selected.prepare(take) else {
                        return Ok(ControlFlow::Continue(()));
                    };
                    let range = prepared.range();
                    let Some(next) = fresh.checked_add(range.len()) else {
                        return Ok(ControlFlow::Break(()));
                    };
                    let room = limit.saturating_sub(frames.len());
                    if !prepared
                        .write(&mut write::Append::new(&mut frames), room)
                        .map_err(|error| {
                            context.scratch.frames = mem::take(&mut frames);
                            transmit::Admission::Payload {
                                error,
                                requested: limit,
                            }
                        })?
                    {
                        return Ok(ControlFlow::Break(()));
                    }
                    fresh = next;
                    commit.flags.set_elicit(true);
                    Ok(
                        if limit.saturating_sub(frames.len()) <= conn::STREAM_FRAME_OVERHEAD {
                            ControlFlow::Break(())
                        } else {
                            ControlFlow::Continue(())
                        },
                    )
                },
            )?;
            if !matches!(step, Some(ControlFlow::Continue(()))) {
                break;
            }
        }
    }
    let mut build = schedule.finish();
    if frames.is_empty() {
        build.cancel().into_scratch().frames = frames;
        return Ok(None);
    }
    let mut header = mem::take(&mut build.scratch().header);
    header.clear();
    let encoded = match header::Body::<kind::ZeroRtt>::try_new(
        long::Fields {
            version: packet::QUIC_V1,
            dcid: build.owner().conn().path.peer.id().as_ref_id(),
            scid: build.owner().conn().path.local.cid(),
            token: None,
            packet_number: commit.packet_number.encoding(),
        },
        &mut header,
        &frames,
    ) {
        Ok(encoded) => encoded,
        Err(error) => {
            header.clear();
            let scratch = build.cancel().into_scratch();
            scratch.header = header;
            scratch.frames = frames;
            return Err(transmit::Admission::Header {
                epoch: conn::Epoch::Application,
                error,
            });
        }
    };
    commit.flags.set_flight(true);
    let Some(target) = build.owner().target(policy, commit.path.route) else {
        header.clear();
        let scratch = build.cancel().into_scratch();
        scratch.header = header;
        scratch.frames = frames;
        return Ok(None);
    };
    let prepared = match pending::Packet::try_new(build, commit, target) {
        Ok(prepared) => prepared,
        Err((scratch, error)) => {
            header.clear();
            scratch.header = header;
            scratch.frames = frames;
            return Err(error.into_error());
        }
    };
    let ((), mut prepared) = match prepared.protect(seals::Long::new(dst, encoded)) {
        Ok(output) => output,
        Err(failure) => {
            let mut failure = failure.release();
            let scratch = failure.scratch();
            header.clear();
            scratch.header = header;
            frames.clear();
            scratch.frames = frames;
            return failure.into_error().map_or(Ok(None), Err);
        }
    };
    header.clear();
    prepared.scratch().header = header;
    frames.clear();
    prepared.scratch().frames = frames;
    Ok(Some(prepared))
}
