use std::ops;

use control::{kind, owner, revision};
use o3::base::num::bounded;

use crate::{
    conn,
    conn::output::{
        control,
        control::journal::{self, storage},
        delivery,
    },
    wire::{stream, varint},
};

/// Generation-checked ownership operations over one exact pending journal.
#[repr(transparent)]
pub(in crate::conn) struct Records<P>(P);

impl<P> Records<P> {
    pub(in crate::conn) const fn new(state: P) -> Self {
        Self(state)
    }
}

impl<P: ops::Deref<Target = control::Pending>> ops::Deref for Records<P> {
    type Target = control::Pending;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<P: ops::DerefMut<Target = control::Pending>> ops::DerefMut for Records<P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<P: ops::DerefMut<Target = control::Pending>> Records<P> {
    fn revise<Kind>(
        &mut self,
        owner: &mut Option<owner::Key<Kind>>,
        record: delivery::Control,
    ) -> Result<(), journal::Error> {
        let Some(key) = *owner else {
            return Err(journal::Error::Vacant);
        };
        let state = &mut *self.0;
        let Some(slot) = state.storage.owner(key) else {
            *owner = None;
            return Err(journal::Error::Vacant);
        };
        let entry = slot.entry();
        if *entry.record() == record {
            return Ok(());
        }
        let spent = match slot.revise() {
            Ok(mut rev) => {
                rev.replace(record);
                return Ok(());
            }
            Err(slot) => {
                let spent = slot.revision();
                slot.remove();
                spent
            }
        };
        *owner = None;
        Err(journal::Error::Revision(spent))
    }

    pub(in crate::conn) fn set_data(
        &mut self,
        owner: &mut Option<owner::Key<kind::MaxData>>,
        limit: varint::VarInt,
    ) -> Result<(), journal::Error> {
        self.revise(owner, delivery::Control::MaxData(limit))
    }

    pub(in crate::conn) fn set_stream(
        &mut self,
        owner: &mut Option<owner::Key<kind::StreamLimit>>,
        id: stream::Id,
        limit: varint::VarInt,
    ) -> Result<(), journal::Error> {
        self.revise(owner, delivery::Control::MaxStreamData(id, limit))
    }

    pub(in crate::conn) fn set_streams(
        &mut self,
        owner: &mut Option<owner::Key<kind::MaxStreams>>,
        dir: stream::Direction,
        limit: bounded::U64<0, { conn::MAX_STREAM_COUNT }>,
    ) -> Result<(), journal::Error> {
        self.revise(owner, delivery::Control::MaxStreams(dir, limit))
    }

    pub(in crate::conn) fn try_data(
        &mut self,
        owner: &mut Option<owner::Key<kind::MaxData>>,
        limit: varint::VarInt,
    ) -> Result<(), control::Admission> {
        let state = &mut *self.0;
        state
            .storage
            .try_queue(owner, delivery::Control::MaxData(limit))
    }

    pub(in crate::conn) fn try_stream(
        &mut self,
        owner: &mut Option<owner::Key<kind::StreamLimit>>,
        id: stream::Id,
        limit: varint::VarInt,
    ) -> Result<(), control::Admission> {
        let state = &mut *self.0;
        state
            .storage
            .try_queue(owner, delivery::Control::MaxStreamData(id, limit))
    }

    pub(in crate::conn) fn try_streams(
        &mut self,
        owner: &mut Option<owner::Key<kind::MaxStreams>>,
        dir: stream::Direction,
        limit: bounded::U64<0, { conn::MAX_STREAM_COUNT }>,
    ) -> Result<(), control::Admission> {
        let state = &mut *self.0;
        state
            .storage
            .try_queue(owner, delivery::Control::MaxStreams(dir, limit))
    }

    pub(in crate::conn::output::control) fn complete(
        &mut self,
        handle: revision::Key,
    ) -> Option<delivery::Control> {
        let state = &mut *self.0;
        let slot = state.storage.revision(handle)?;
        if !matches!(slot.entry().status, storage::Status::InFlight { .. }) {
            return None;
        }
        Some(slot.remove())
    }
}

impl<P: ops::Deref<Target = control::Pending>> Records<P> {
    pub(in crate::conn::output::control) fn entry<Kind>(
        &self,
        owner: Option<owner::Key<Kind>>,
    ) -> Option<&storage::Entry> {
        self.storage.view().owner(owner?.inner())
    }

    pub(in crate::conn) fn contains<Kind>(&self, owner: Option<owner::Key<Kind>>) -> bool {
        self.storage.contains(owner)
    }
}
