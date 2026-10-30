use crate::conn::output::transmit::builder::ack;
use crate::conn::stream::state::transmit::log::journal::Entry;
use o3::buffer::{self, write};
use write::Sink as _;

use std::time;

use crate::{
    conn::{
        self,
        output::transmit::{self, builder, packet::plan::Plan},
        stream::state::transmit::log,
    },
    stream,
    wire::{frame, packet::kind},
};

pub(in crate::conn::output::transmit) enum Append {
    Done,
    Full,
}

pub(in crate::conn::output::transmit) struct Probe<
    'a,
    'conn,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
> {
    builder: &'a mut builder::Builder<'conn, DOMAIN, B, D>,
}

impl<'a, 'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    Probe<'a, 'conn, DOMAIN, B, D>
{
    pub(in crate::conn::output::transmit) fn new(
        builder: &'a mut builder::Builder<'conn, DOMAIN, B, D>,
    ) -> Self {
        Self { builder }
    }

    pub(in crate::conn::output::transmit) fn one_rtt<N>(
        &mut self,
        now: time::Instant,
        frames: &mut write::Append<'_>,
        limit: usize,
        commit: &mut Plan<N>,
    ) -> Result<Append, transmit::Admission> {
        use builder::crypto;

        commit.flags.ack = ack::append::<kind::OneRtt, false>(
            &self.builder.connection.receive.packet_numbers,
            now,
            frames,
            limit.saturating_sub(1),
        )
        .map_err(transmit::Admission::into_error)?;
        let room = limit.saturating_sub(frames.len());
        crypto::append::<true>(
            &self.builder.connection.handshake.crypto,
            self.builder.crypto,
            conn::Epoch::Application,
            room,
            frames,
        )?;
        if self.builder.crypto.is_some() {
            commit.flags.set_elicit(true);
        }
        self.builder.probe(frames, limit, commit)?;
        self.streams(frames, limit, commit)?;
        Self::finish(frames, limit, commit)
    }

    pub(in crate::conn::output::transmit) fn early<N>(
        &mut self,
        frames: &mut Vec<u8>,
        limit: usize,
        commit: &mut Plan<N>,
    ) -> Result<Append, transmit::Admission> {
        let room = limit.saturating_sub(frames.len());
        let mut frames = write::Append::new(frames);
        self.streams(&mut frames, room, commit)?;
        Self::finish(&mut frames, room, commit)
    }

    fn streams<N>(
        &mut self,
        frames: &mut write::Append<'_>,
        limit: usize,
        commit: &mut Plan<N>,
    ) -> Result<(), transmit::Admission> {
        let mut work = self
            .builder
            .connection
            .streams
            .transmit
            .deliveries()
            .probe_work();
        while let Some(vacant) = self.builder.streams.vacancy() {
            let transmit = &mut self.builder.connection.streams.state.transmit;
            let (mut chosen, map) = transmit.selection();
            let next = chosen
                .probe(&mut work, |probe, sender, record| {
                    if vacant
                        .as_slice()
                        .iter()
                        .any(|item| matches!(*item, Entry::Probe(seen) if seen == probe))
                    {
                        return Ok(log::Append::Skip);
                    }
                    let room = limit
                        .saturating_sub(frames.len().saturating_add(conn::STREAM_FRAME_OVERHEAD));
                    if record.range.len_usize() > room {
                        return Ok(log::Append::Full);
                    }
                    let Some((resolved, chunks)) = map.read(sender) else {
                        return Ok(log::Append::Retired);
                    };
                    if resolved.id() != record.id {
                        return Ok(log::Append::Retired);
                    }
                    if builder::Builder::<DOMAIN, B, D>::put_stream(
                        frames,
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
            let Some(probe) = next else { break };
            vacant.insert(Entry::Probe(probe));
            commit.flags.set_elicit(true);
        }
        Ok(())
    }

    fn finish<N>(
        frames: &mut write::Append<'_>,
        limit: usize,
        commit: &mut Plan<N>,
    ) -> Result<Append, transmit::Admission> {
        if !commit.flags.is_eliciting() {
            if frames.len() >= limit {
                return Ok(Append::Full);
            }
            frames
                .write_byte(frame::TYPE_PING)
                .map_err(|error| transmit::Admission::Payload {
                    error,
                    requested: 1,
                })?;
        }
        commit.flags.set_elicit(true);
        commit.flags.set_probe(true);
        Ok(Append::Done)
    }
}
