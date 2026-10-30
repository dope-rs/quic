use std::mem;

use crate::conn::output::control::{self, kind, owner};
use crate::conn::output::delivery;
use crate::errors::Code;
use crate::wire::{stream, varint};

/// One deferred signal retained through admission and publication.
#[must_use]
pub(in crate::conn) struct Deferred<'a, Kind> {
    pub(in crate::conn::output::control::owner) signal: &'a mut owner::Signal<Kind>,
    pub(in crate::conn::output::control::owner) code: Code,
}

impl<Kind> Deferred<'_, Kind> {
    fn try_insert(
        self,
        pending: &mut control::Pending,
        record: delivery::Control,
    ) -> Result<(), control::Admission> {
        let slot = pending.storage.try_insert(record)?;
        self.signal.set_owner(slot.owner());
        Ok(())
    }
}

impl Deferred<'_, kind::StopSending> {
    pub(in crate::conn) fn try_queue(
        self,
        pending: &mut control::Pending,
        id: stream::Id,
    ) -> Result<(), control::Admission> {
        let record = delivery::Control::StopSending(id, self.code);
        self.try_insert(pending, record)
    }
}

impl Deferred<'_, kind::ResetStream> {
    pub(in crate::conn) fn try_queue(
        self,
        pending: &mut control::Pending,
        id: stream::Id,
        size: varint::VarInt,
    ) -> Result<(), control::Admission> {
        let record = delivery::Control::ResetStream(id, self.code, size);
        self.try_insert(pending, record)
    }
}

const _: () = {
    assert!(mem::size_of::<Deferred<'static, kind::StopSending>>() == 16);
    assert!(mem::size_of::<Option<Deferred<'static, kind::StopSending>>>() == 16);
    assert!(mem::size_of::<Deferred<'static, kind::ResetStream>>() == 16);
    assert!(mem::size_of::<Option<Deferred<'static, kind::ResetStream>>>() == 16);
};
