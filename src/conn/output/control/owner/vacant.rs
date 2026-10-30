use std::mem;

use crate::conn::output::control::journal::storage;
use crate::conn::output::control::{self, kind, owner};
use crate::conn::output::delivery;
use crate::conn::wire::path;
use crate::wire::varint;

/// An unpublished owner retained through native control insertion.
#[must_use]
pub(in crate::conn) struct Vacant<'a, Kind>(&'a mut Option<owner::Key<Kind>>);

impl<'a, Kind> Vacant<'a, Kind> {
    pub(in crate::conn) fn new(owner: &'a mut Option<owner::Key<Kind>>) -> Option<Self> {
        if owner.is_some() {
            return None;
        }
        Some(Self(owner))
    }

    fn try_insert(
        self,
        pending: &mut storage::Set,
        record: delivery::Control,
    ) -> Result<(), control::Admission> {
        let slot = pending.try_insert(record)?;
        *self.0 = Some(slot.owner());
        Ok(())
    }
}

impl Vacant<'_, kind::PathResponse> {
    pub(in crate::conn) fn try_queue(
        self,
        pending: &mut storage::Set,
        key: path::ControlKey,
    ) -> Result<(), control::Admission> {
        self.try_insert(pending, delivery::Control::PathResponse(key))
    }
}

impl Vacant<'_, kind::RetireCid> {
    pub(in crate::conn) fn try_queue(
        self,
        pending: &mut storage::Set,
        serial: varint::VarInt,
    ) -> Result<(), control::Admission> {
        self.try_insert(pending, delivery::Control::RetireConnectionId(serial))
    }
}

impl Vacant<'_, kind::Challenge> {
    pub(in crate::conn) fn try_queue(
        self,
        pending: &mut storage::Set,
        key: path::ControlKey,
        path: Option<path::Key>,
    ) -> Result<(), control::Admission> {
        let record = match path {
            Some(_) => delivery::Control::PathValidation(key),
            None => delivery::Control::PathChallenge(key),
        };
        self.try_insert(pending, record)
    }
}

const _: () = {
    assert!(mem::size_of::<Vacant<'static, kind::PathResponse>>() == mem::size_of::<usize>());
    assert!(
        mem::size_of::<Option<Vacant<'static, kind::PathResponse>>>() == mem::size_of::<usize>()
    );
    assert!(mem::size_of::<Vacant<'static, kind::RetireCid>>() == mem::size_of::<usize>());
    assert!(mem::size_of::<Vacant<'static, kind::Challenge>>() == mem::size_of::<usize>());
};
