use crate::conn::output::transmit::builder::ack;
use crate::conn::stream::state::transmit::log::journal;
use o3::buffer::{self, write};
use std::{mem, num::NonZero, time};

use crate::conn;
use crate::conn::output::{
    self,
    transmit::{
        self,
        builder::{self, pending},
        packet::{plan::Plan, seals},
        permit::{self, fit},
    },
};
use crate::conn::wire::path;
use crate::proto::recovery::{numbers, pmtud};
use crate::wire::frame::close;
use crate::{
    stream,
    wire::{
        frame,
        packet::{kind, short},
        stream::Initiator,
        varint,
    },
};

pub(in crate::conn::output::transmit) fn probe<
    'connection,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
>(
    build: builder::Builder<'connection, DOMAIN, B, D>,
    now: time::Instant,
    dst: &mut write::Append<'_>,
    probe: pmtud::Probe,
    max: usize,
) -> transmit::Built<'connection, DOMAIN, B, D> {
    let Some(write) = build.connection.handshake.keys.write() else {
        return Ok(None);
    };
    let phase = write.is_key_phase();
    if !build.can_track() {
        return Ok(None);
    }
    let target = probe.get();
    if target > max {
        return Ok(None);
    }
    let Some(number) = conn::Epoch::Application
        .bind_mut(&mut build.connection.egress.recovery.spaces)
        .next()
    else {
        return Ok(None);
    };

    let overhead = 1 + build.connection.path.peer.id().len() + usize::from(number.encoded_len());
    let Some(payload) = target.checked_sub(overhead + conn::TAG_LEN) else {
        return Ok(None);
    };
    let Some(space) = payload.checked_sub(1) else {
        return Ok(None);
    };

    let mut frames = mem::take(&mut build.connection.scratch.frames);
    frames.clear();
    let ack = match ack::append::<kind::OneRtt, false>(
        &build.connection.receive.packet_numbers,
        now,
        &mut frames,
        space,
    ) {
        Ok(ack) => ack,
        Err(error) => {
            build.connection.scratch.frames = frames;
            return Err(error.into_error());
        }
    };
    let padding = space - frames.len();
    if let Err(rejected) = write::Append::new(&mut frames).try_tail::<0, 1>(
        [&[frame::TYPE_PING]],
        padding,
        frame::TYPE_PADDING,
    ) {
        let (_, error) = rejected.into_parts();
        build.connection.scratch.frames = frames;
        return Err(transmit::Admission::Payload {
            error,
            requested: 1 + padding,
        });
    }

    let mut header = mem::take(&mut build.connection.scratch.header);
    header.clear();
    let dcid = *build.connection.path.peer.id();
    let encoded = match short::Ref::new(dcid.as_ref_id(), number.encoding(), phase)
        .encode_into(&mut header)
    {
        Ok(encoded) => encoded,
        Err(error) => {
            build.connection.scratch.header = header;
            build.connection.scratch.frames = frames;
            return Err(transmit::Admission::Payload {
                error,
                requested: overhead,
            });
        }
    };
    let mut commit = Plan::new(conn::Epoch::Application, number);
    commit.flags.ack = ack;
    commit.flags.set_elicit(true);
    commit.flags.set_flight(true);
    commit.path.pmtud_probe = Some(probe);
    let Some(target) = build.target(commit.path.route) else {
        header.clear();
        build.connection.scratch.header = header;
        build.connection.scratch.frames = frames;
        return Ok(None);
    };
    let prepared =
        match pending::Packet::try_new(journal::Schedule::new(build).finish(), commit, target) {
            Ok(prepared) => prepared,
            Err((scratch, error)) => {
                header.clear();
                scratch.header = header;
                scratch.frames = frames;
                return Err(error.into_error());
            }
        };
    let ((), mut prepared) = match prepared.protect(seals::Segments::new(dst, encoded, &frames)) {
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

enum Protection {
    Initial,
    Handshake,
    OneRtt(bool),
}

pub(in crate::conn::output::transmit) struct Close {
    seal: Protection,
    epoch: conn::Epoch,
    number: numbers::Packet,
    code: close::Code,
    limit: NonZero<usize>,
    fixed: usize,
}

pub(in crate::conn::output::transmit) fn admit<
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
>(
    conn: &conn::Machine<DOMAIN, B, D>,
    close: &output::PendingClose,
    max: usize,
) -> Option<Close> {
    let seal = if let Some(write) = conn.handshake.keys.write() {
        Protection::OneRtt(write.is_key_phase())
    } else if conn.handshake.keys.long.handshake().is_some() {
        Protection::Handshake
    } else {
        conn.handshake.keys.long.initial()?;
        Protection::Initial
    };
    let epoch = match &seal {
        Protection::Initial => conn::Epoch::Initial,
        Protection::Handshake => conn::Epoch::Handshake,
        Protection::OneRtt(_) => conn::Epoch::Application,
    };
    let permit = permit::Permit::new(conn);
    let (number, limit) = match epoch {
        conn::Epoch::Initial => {
            let (number, limit, _) = fit::crypto::<kind::Initial, DOMAIN, B, D>(&permit, max)?;
            (number, limit)
        }
        conn::Epoch::Handshake => {
            let (number, limit, _) = fit::crypto::<kind::Handshake, DOMAIN, B, D>(&permit, max)?;
            (number, limit)
        }
        conn::Epoch::Application => {
            let number = epoch.bind(&conn.egress.recovery.spaces).next()?;
            let limit = builder::Builder::<'_, DOMAIN, B, D>::short_for(
                &conn.path,
                max,
                number.encoding(),
                path::OutputRoute::ACTIVE,
            );
            (number, NonZero::new(limit)?)
        }
    };
    let code = match close {
        output::PendingClose::Application {
            error_code: value, ..
        } if epoch == conn::Epoch::Application => close::Code::Application(*value),
        output::PendingClose::Application { .. } => close::Code::Transport {
            error_code: conn::APPLICATION_ERROR,
            frame_type: varint::VarInt::ZERO,
        },
        output::PendingClose::Transport {
            error_code: value,
            frame_type: frame,
            ..
        } => close::Code::Transport {
            error_code: *value,
            frame_type: *frame,
        },
    };
    let fixed = 1 + usize::from(match code {
        close::Code::Application(value) => value.as_varint().encoded_len(),
        close::Code::Transport {
            error_code: value,
            frame_type: frame,
        } => value.encoded_len() + frame.encoded_len(),
    });
    (fixed < limit.get()).then_some(Close {
        seal,
        epoch,
        number,
        code,
        limit,
        fixed,
    })
}

pub(in crate::conn::output::transmit) fn close<
    'connection,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
>(
    build: builder::Builder<'connection, DOMAIN, B, D>,
    dst: &mut write::Append<'_>,
    max: usize,
) -> transmit::Built<'connection, DOMAIN, B, D> {
    let Some(close) = build.connection.egress.lifecycle.pending_close.as_ref() else {
        return Ok(None);
    };
    let Some(Close {
        seal,
        epoch,
        number,
        code,
        limit,
        fixed,
    }) = admit(build.connection, close, max)
    else {
        return Ok(None);
    };
    let limit = limit.get();
    let mut reason: &[u8] = match close {
        output::PendingClose::Application { .. }
            if matches!(code, close::Code::Transport { .. }) =>
        {
            &[]
        }
        output::PendingClose::Application { reason, .. }
        | output::PendingClose::Transport { reason, .. } => reason,
    };
    let encoding = number.encoding();
    let pn_len = number.encoded_len();
    while fixed + varint::VarInt::width(reason.len()) + reason.len() > limit {
        let len = reason.len();
        let encoded = fixed + varint::VarInt::width(len) + len;
        reason = &reason[..len.saturating_sub((encoded - limit).max(1))];
    }
    let len = reason.len();
    let close = frame::Borrowed::try_close(code, reason)
        .map_err(|error| transmit::Admission::Encoding { epoch, error })?;
    let frames = &mut build.connection.scratch.frames;
    frames.clear();
    close
        .encode(frames)
        .map_err(|error| transmit::Admission::Payload {
            error,
            requested: fixed + varint::VarInt::width(len) + len,
        })?;

    if epoch == conn::Epoch::Initial
        && matches!(build.connection.peer.local, Initiator::Client)
        && frames.len() < limit
    {
        let padding = limit - frames.len();
        write::Append::new(frames)
            .try_fill(padding, frame::TYPE_PADDING)
            .map_err(|error| transmit::Admission::Payload {
                error,
                requested: padding,
            })?;
    }
    let mut frames = mem::take(&mut build.connection.scratch.frames);
    let mut commit = Plan::new(epoch, number);
    commit.flags.set_close(true);
    let Some(target) = build.target(commit.path.route) else {
        build.connection.scratch.frames = frames;
        return Ok(None);
    };
    let mut prepared =
        match pending::Packet::try_new(journal::Schedule::new(build).finish(), commit, target) {
            Ok(prepared) => prepared,
            Err((scratch, error)) => {
                scratch.frames = frames;
                return Err(error.into_error());
            }
        };
    let mut prepared = match seal {
        Protection::Initial => {
            use kind::Initial;

            match seals::long::<DOMAIN, B, D, Initial>(dst, &frames, prepared) {
                Ok(((), prepared)) => prepared,
                Err(mut failure) => {
                    let scratch = failure.scratch();
                    frames.clear();
                    scratch.frames = frames;
                    return failure.into_error().map_or(Ok(None), Err);
                }
            }
        }
        Protection::Handshake => {
            use kind::Handshake;

            match seals::long::<DOMAIN, B, D, Handshake>(dst, &frames, prepared) {
                Ok(((), prepared)) => prepared,
                Err(mut failure) => {
                    let scratch = failure.scratch();
                    frames.clear();
                    scratch.frames = frames;
                    return failure.into_error().map_or(Ok(None), Err);
                }
            }
        }
        Protection::OneRtt(phase) => {
            let mut header = mem::take(&mut prepared.scratch().header);
            header.clear();
            let dcid = *prepared.conn().path.peer.id();
            let needed = 1 + dcid.len() + usize::from(pn_len);
            let encoded =
                match short::Ref::new(dcid.as_ref_id(), encoding, phase).encode_into(&mut header) {
                    Ok(encoded) => encoded,
                    Err(error) => {
                        let scratch = prepared.reject();
                        scratch.header = header;
                        scratch.frames = frames;
                        return Err(transmit::Admission::Payload {
                            error,
                            requested: needed,
                        });
                    }
                };
            let ((), mut prepared) =
                match prepared.protect(seals::Segments::new(dst, encoded, &frames)) {
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
            prepared
        }
    };
    frames.clear();
    prepared.scratch().frames = frames;
    Ok(Some(prepared))
}
