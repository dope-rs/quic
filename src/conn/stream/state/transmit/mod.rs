mod commit;
pub(in crate::conn) mod log;
pub(in crate::conn) mod peer;
pub(in crate::conn) mod queue;
pub(in crate::conn) mod request;
mod state;
mod writer;

pub(in crate::conn) use commit::{Commit, Effects};
pub(in crate::conn) use state::State;
pub(in crate::conn) use writer::Writer;

use crate::stream::release;

use o3::buffer::{self, resident::Shared};

use crate::{conn, errors, proto, stream, wire};

use conn::output::control;
use conn::stream::state::receive::recv;
use conn::stream::{Access, Error, SendOutcome, Streams, resident, state::streams};
use proto::param;
use queue::plan;
use recv::map;
use send::admit;
use std::{convert, mem, ops};
use stream::send;
use wire::stream::{Direction, Id};

pub(in crate::conn) struct Sender<'streams, B: stream::Recv, D: buffer::raw::Segment> {
    streams: &'streams mut Streams<B, D>,
}

impl<'streams, B: stream::Recv, D: buffer::raw::Segment> Sender<'streams, B, D> {
    pub(in crate::conn) fn new(streams: &'streams mut Streams<B, D>) -> Self {
        Self { streams }
    }
}

impl<B: stream::Recv, D: buffer::raw::Segment> ops::Deref for Sender<'_, B, D> {
    type Target = Streams<B, D>;

    fn deref(&self) -> &Self::Target {
        self.streams
    }
}

impl<B: stream::Recv, D: buffer::raw::Segment> ops::DerefMut for Sender<'_, B, D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.streams
    }
}

impl<B: stream::Recv, D: buffer::raw::Segment> Sender<'_, B, D> {
    pub(in crate::conn) fn release_all<E: release::Sink>(
        &mut self,
        cause: release::Cause,
        proof: &mut E,
    ) {
        let Streams { state, events } = &mut *self.streams;
        let transmit = &mut state.transmit;
        let result = transmit
            .map
            .try_for_each::<convert::Infallible>(|mut occupied| {
                let released = occupied.stop::<E>(&mut transmit.deliveries, errors::Code::ZERO);
                released.commit(cause, events, proof);
                Ok(())
            });
        match result {
            Ok(()) => {}
            Err(never) => match never {},
        }
    }

    fn validate(&self, id: Id, access: Access, ready: bool) -> Result<(), Error> {
        if !ready {
            return Err(Error::NotEstablished);
        }
        if !self.can_access(id, access) {
            return Err(Error::InvalidStream);
        }
        Ok(())
    }

    pub(in crate::conn) fn send_bytes(
        &mut self,
        id: Id,
        data: &[u8],
        params: Option<&param::Set>,
        ready: bool,
    ) -> Result<(), Error> {
        self.validate(id, Access::Send, ready)?;
        if self.is_send_done(id) || data.is_empty() {
            return Ok(());
        }
        plan::check_copy(&mut self.transmit.map, data)?;
        let stream = streams::Relative::new(id, self.state.local());
        let credit = queue::Entry::limit(params, stream);
        let mode = queue::Preparation::new(stream);
        let state = &mut self.streams.state;
        let (registry, transmit) = (&mut state.resident, &mut state.transmit);
        let Some(mut occupied) = transmit.map.try_prepared(
            queue::Id::new(id),
            None,
            credit,
            mode,
            registry,
            |_, slot| slot,
        )?
        else {
            return Ok(());
        };
        occupied.copy(data)
    }

    pub(in crate::conn) fn send_batch<W: send::raw::Batch<D>>(
        &mut self,
        id: Id,
        parts: W,
        params: Option<&param::Set>,
        ready: bool,
    ) -> SendOutcome<W> {
        if let Err(error) = self.validate(id, Access::Send, ready) {
            return SendOutcome::Failed {
                owner: parts,
                error,
            };
        }
        if self.is_send_done(id) {
            plan::recycle(&mut self.transmit.map, parts.into_parts());
            return SendOutcome::Accepted;
        }
        let stream = streams::Relative::new(id, self.state.local());
        let credit = queue::Entry::limit(params, stream);
        let mode = queue::Preparation::new(stream);
        let state = &mut self.streams.state;
        let (registry, transmit) = (&mut state.resident, &mut state.transmit);
        let plan = match plan::Plan::try_new(parts, &mut transmit.map) {
            Ok(plan) => plan,
            Err(rejected) => return rejected.into_outcome(),
        };
        plan.apply(queue::Id::new(id), credit, mode, registry)
    }

    pub(in crate::conn) fn send_with<C, W>(
        &mut self,
        id: Id,
        owner: W,
        params: Option<&param::Set>,
        ready: bool,
        commit: C,
    ) -> admit::Outcome<D, C, Error, W>
    where
        C: admit::Commit<D, W>,
        W: send::raw::Batch<D>,
    {
        if let Err(error) = self.validate(id, Access::Send, ready) {
            return admit::Outcome::Failed {
                owner,
                commit,
                error,
            };
        }
        let source = admit::Source::new(id);
        if self.is_send_done(id) {
            plan::recycle(&mut self.transmit.map, owner.into_parts());
            return admit::Outcome::Discarded(
                commit.discarded(admit::Discard::new(source, admit::Cause::PeerRetired)),
            );
        }
        let stream = streams::Relative::new(id, self.state.local());
        let credit = queue::Entry::limit(params, stream);
        let mode = queue::Preparation::new(stream);
        let state = &mut self.streams.state;
        let (registry, transmit) = (&mut state.resident, &mut state.transmit);
        let plan = match plan::Observed::try_new(source, owner, commit, &mut transmit.map) {
            Ok(plan) => plan,
            Err(rejected) => return rejected.into_outcome(convert::identity),
        };
        plan.apply(queue::Id::new(id), credit, mode, registry)
    }

    pub(in crate::conn) fn try_send<C, W>(
        &mut self,
        local: resident::Local,
        owner: W,
        params: Option<&param::Set>,
        ready: bool,
        commit: C,
    ) -> admit::Outcome<D, C, resident::Error, W>
    where
        C: admit::Commit<D, W>,
        W: send::raw::Batch<D>,
    {
        let id = local.id();
        if let Err(error) = self.validate(id, Access::Send, ready) {
            return admit::Outcome::Failed {
                owner,
                commit,
                error: resident::Error::Stream(error),
            };
        }
        let source = admit::Source::new(id);
        if self.is_send_done(id) {
            plan::recycle(&mut self.transmit.map, owner.into_parts());
            return admit::Outcome::Discarded(
                commit.discarded(admit::Discard::new(source, admit::Cause::PeerRetired)),
            );
        }
        let stream = streams::Relative::new(id, self.state.local());
        let credit = queue::Entry::limit(params, stream);
        let state = &mut self.streams.state;
        let (registry, transmit) = (&mut state.resident, &mut state.transmit);
        let plan = match plan::Observed::try_new(source, owner, commit, &mut transmit.map) {
            Ok(plan) => plan,
            Err(rejected) => return rejected.into_outcome(resident::Error::Stream),
        };
        plan.try_apply(local, credit, queue::Preparation::new(stream), registry)
    }

    pub(in crate::conn) fn try_prepare(
        &mut self,
        local: resident::Local,
        params: Option<&param::Set>,
        ready: bool,
    ) -> Result<(), resident::Error> {
        let id = local.id();
        self.validate(id, Access::Send, ready)
            .map_err(resident::Error::Stream)?;
        if self.is_send_done(id) {
            return Ok(());
        }
        let stream = streams::Relative::new(id, self.state.local());
        let credit = queue::Entry::limit(params, stream);
        let state = &mut self.streams.state;
        let (registry, transmit) = (&mut state.resident, &mut state.transmit);
        let Some(mut occupied) =
            transmit
                .map
                .try_live(local, credit, queue::Preparation::new(stream), registry)?
        else {
            return Ok(());
        };
        if !matches!(occupied.state().phase(), queue::Phase::Open) {
            return Ok(());
        }
        occupied.refresh();
        Ok(())
    }

    pub(in crate::conn) fn send_fin(
        &mut self,
        id: Id,
        params: Option<&param::Set>,
        ready: bool,
    ) -> Result<(), Error> {
        self.validate(id, Access::Send, ready)?;
        if self.is_send_done(id) {
            return Ok(());
        }
        let stream = streams::Relative::new(id, self.state.local());
        let credit = queue::Entry::limit(params, stream);
        let mode = queue::Preparation::new(stream);
        let state = &mut self.streams.state;
        let (registry, transmit) = (&mut state.resident, &mut state.transmit);
        let _ = transmit.map.try_prepared(
            queue::Id::new(id),
            None,
            credit,
            mode,
            registry,
            |_, mut slot| {
                slot.mark_fin();
                slot.refresh();
            },
        )?;
        Ok(())
    }

    pub(in crate::conn) fn reset(
        &mut self,
        id: Id,
        error: errors::Code,
        params: Option<&param::Set>,
        ready: bool,
        control: &mut control::Pending,
    ) -> Result<(), Error> {
        request::Request::new(id, error, params, ready, control, &mut release::Ignore).apply(self)
    }

    pub(in crate::conn) fn stop_sending(
        &mut self,
        id: Id,
        error: errors::Code,
        ready: bool,
        control: &mut control::Pending,
    ) -> Result<(), Error> {
        self.validate(id, Access::Receive, ready)?;
        if !self.streams.state.is_recv_done(id) {
            let state = &mut self.streams.state;
            let relative = streams::Relative::new(id, state.local());
            let base = state.receive.initial_stream_data.credit(relative);
            let (registry, receive) = (&mut state.resident, &mut state.receive);
            let mut slots = receive.map.parts();
            let Some(mut occupied) = slots.entry(map::Id::new(id), registry).insert(registry)
            else {
                return Err(Error::Capacity);
            };
            occupied.stop(control, error, base);
        }
        Ok(())
    }

    /// The admitted peer count prevents reusing the final valid ID.
    pub(in crate::conn) fn open_local(
        &mut self,
        dir: Direction,
        params: Option<&param::Set>,
        ready: bool,
    ) -> Result<resident::Local, Error> {
        if !ready || params.is_none() {
            return Err(Error::NotEstablished);
        }
        let local = &self.state.local_initiated;
        let id = *dir.bind(&local.next);
        let raw = id.get();
        let opened = *dir.bind(&local.opened);
        if opened >= *dir.bind(&local.peer_max) {
            return Err(Error::PeerLimit);
        }
        if dir.bind(&local.active) >= dir.bind(&local.capacity) {
            return Err(Error::Capacity);
        }
        let active = dir
            .bind(&local.active)
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        let opened = opened + 1;
        let next = Id::new(raw + 4).unwrap_or(id);
        let stream = streams::Relative::new(id, self.state.local());
        let credit = queue::Entry::limit(params, stream);
        let state = &mut self.streams.state;
        let (registry, transmit) = (&mut state.resident, &mut state.transmit);
        let Some((key, mut occupied)) = transmit.map.try_prepared(
            queue::Id::new(id),
            None,
            credit,
            queue::Preparation::Create,
            registry,
            |key, slot| (key, slot),
        )?
        else {
            return Err(Error::Capacity);
        };
        occupied.refresh();
        let local = &mut self.state.local_initiated;
        *dir.bind_mut(&mut local.next) = next;
        *dir.bind_mut(&mut local.opened) = opened;
        *dir.bind_mut(&mut local.active) = active;
        Ok(resident::Local::new(id, key))
    }
}

const _: () = assert!(mem::size_of::<Sender<'_, Vec<u8>, Shared<'_>>>() == mem::size_of::<usize>());
