use crate::stream::release;
use release::batch;

use crate::conn::output::control;
use crate::conn::stream::event::{self, queue::Permit};
use crate::conn::stream::state::transmit::queue;
use crate::conn::stream::{Access, Error, State, resident, state::streams};
use crate::wire::stream::Id;
use crate::wire::varint;
use crate::{conn, errors, proto::param, stream};
use o3::buffer::{self, resident::Shared};
use send::admit;
use std::{mem, ops};
use stream::send;

pub(in crate::conn) struct Commit<'state, B: stream::Recv, D: buffer::raw::Segment> {
    state: &'state mut State<B, D>,
}

pub(in crate::conn) struct Effects<'a, 'events, E> {
    control: &'a mut control::Pending,
    events: &'a mut Permit<'events>,
    releases: &'a mut E,
}

impl<'a, 'events, E> Effects<'a, 'events, E> {
    pub(in crate::conn) fn new(
        control: &'a mut control::Pending,
        events: &'a mut Permit<'events>,
        releases: &'a mut E,
    ) -> Self {
        Self {
            control,
            events,
            releases,
        }
    }
}

impl<'state, B: stream::Recv, D: buffer::raw::Segment> Commit<'state, B, D> {
    pub(in crate::conn) fn new(state: &'state mut State<B, D>) -> Self {
        Self { state }
    }

    pub(in crate::conn) fn try_credit(
        &mut self,
        id: Id,
        limit: varint::VarInt,
        params: Option<&param::Set>,
        ctrl: &mut control::Pending,
    ) -> Result<(), Error> {
        if self.is_send_done(id) {
            return Ok(());
        }
        let stream = streams::Relative::new(id, self.local());
        let mode = queue::Preparation::new(stream);
        let credit = queue::Entry::limit(params, stream);
        let State {
            resident: registry,
            transmit,
            ..
        } = self.state;
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
        occupied.credit_mut().raise(limit, ctrl);
        occupied.refresh();
        Ok(())
    }

    pub(in crate::conn) fn plan_stop(&self, id: Id) -> Result<queue::StopImpact, conn::Error> {
        self.try_peer(id, Access::Send)?;
        if self.is_send_done(id) {
            return Ok(queue::StopImpact::NONE);
        }
        let create = !streams::Relative::new(id, self.local()).is_local();
        let key = self.resident.read().key(id);
        Ok(match key {
            Some(key) => {
                if self.transmit.map.find_key(key, &self.resident).is_some() {
                    queue::StopImpact {
                        key: Some(key),
                        active: true,
                        event_slots: usize::from(!self.resident.read().has_event::<true>(key)),
                        stream_slots: 0,
                    }
                } else if create {
                    queue::StopImpact {
                        key: Some(key),
                        active: true,
                        event_slots: 1,
                        stream_slots: 1,
                    }
                } else {
                    queue::StopImpact::NONE
                }
            }
            None if create => queue::StopImpact {
                key: None,
                active: true,
                event_slots: 1,
                stream_slots: 1,
            },
            None => queue::StopImpact::NONE,
        })
    }

    pub(in crate::conn) fn plan_credit(&self, id: Id) -> Result<usize, conn::Error> {
        self.try_peer(id, Access::Send)?;
        if self.is_send_done(id) {
            return Ok(0);
        }
        let create = !streams::Relative::new(id, self.local()).is_local();
        let active = self.transmit.map.find(id, &self.resident).is_some();
        Ok(usize::from(create && !active))
    }

    pub(in crate::conn) fn try_stop<E: release::Sink>(
        &mut self,
        key: Option<resident::Key>,
        id: Id,
        error: errors::Code,
        params: Option<&param::Set>,
        effects: Effects<'_, '_, E>,
    ) -> Result<(), Error> {
        let Effects {
            control: ctrl,
            events,
            releases: proof,
        } = effects;
        let stream = streams::Relative::new(id, self.local());
        let credit = queue::Entry::limit(params, stream);
        let State {
            resident: registry,
            transmit,
            ..
        } = self.state;
        let (log, map) = (&mut transmit.deliveries, &mut transmit.map);
        let mode = queue::Preparation::new(stream);
        let Some((token, mut occupied)) = map.try_prepared(
            queue::Id::new(id),
            key,
            credit,
            mode,
            registry,
            |key, slot| (key, slot),
        )?
        else {
            return Ok(());
        };
        {
            let (released, reset) = occupied.stop_reset::<E>(log, ctrl, error);
            released.commit(release::Cause::Stopped, events.events(), proof);
            if reset {
                batch::Batch::wire_bytes(0).commit(
                    admit::Source::new(id),
                    release::Cause::Reset,
                    |_| {},
                    proof,
                );
            }
            if let Some((hold, event)) = registry.event::<true>().hold(token, id)
                && matches!(
                    events.push_stopped(hold, token, id, error),
                    event::queue::Push::Rollback
                )
            {
                event.release();
            }
        }
        occupied.refresh();
        Ok(())
    }
}

impl<B: stream::Recv, D: buffer::raw::Segment> ops::Deref for Commit<'_, B, D> {
    type Target = State<B, D>;

    fn deref(&self) -> &Self::Target {
        self.state
    }
}

impl<B: stream::Recv, D: buffer::raw::Segment> ops::DerefMut for Commit<'_, B, D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.state
    }
}

const _: () = assert!(mem::size_of::<Commit<'_, Vec<u8>, Shared<'_>>>() == mem::size_of::<usize>());
