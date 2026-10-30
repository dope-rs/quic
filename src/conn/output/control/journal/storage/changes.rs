use crate::conn;
use crate::conn::output::control::journal::storage::{Insert, Set};
use crate::conn::output::control::{kind, owner, revision};
use crate::conn::output::{control, delivery};
use crate::conn::wire::path::local;
use o3::depot;
use o3::depot::arena::slab::key::Generation;
use o3::depot::index::Initialized;
use o3::depot::{capacity::Count, queue::links};
use std::mem;

/// Owns every classified CID operation and both original journal loans.
pub(in crate::conn) struct Batch<'a> {
    pending: &'a mut control::Pending,
    changes: [Option<Change<'a>>; conn::MAX_ACTIVE_CONNECTION_IDS],
    replace: Option<Change<'a>>,
}

struct Change<'a> {
    offer: local::Candidate<'a>,
    action: Action,
}

pub(super) enum Action {
    Insert,
    Revise {
        index: links::Index,
        next: Generation<{ revision::MAX }>,
    },
    Recycle(links::Index),
    Retire(links::Index),
}

pub(super) enum Relation {
    Current,
    Change(Action),
}

impl Action {
    pub(super) fn admission(&self) -> u32 {
        match self {
            Self::Insert | Self::Retire(_) => 1,
            Self::Revise { .. } | Self::Recycle(_) => 0,
        }
    }
}

impl Relation {
    pub(super) fn classify<Kind>(
        set: &Set,
        owner: Option<owner::Key<Kind>>,
        record: delivery::Control,
    ) -> Relation {
        let Some(owner) = owner else {
            return Relation::Change(Action::Insert);
        };
        let Some((key, slot)) = set.slots.entries().entry(owner.inner().index()) else {
            return Relation::Change(Action::Insert);
        };
        if key.parts() != owner.inner() {
            return Relation::Change(Action::Insert);
        }
        if slot.value.record == record {
            return Relation::Current;
        }
        // SAFETY: the successful occupied lookup excludes the compact sentinel.
        let index = unsafe { depot::raw::Word::from_offset(key.index() as usize) };
        let action = match slot.revision.checked_add(1) {
            Some(next) => Action::Revise { index, next },
            None if key.generation().get() == owner::MAX => Action::Retire(index),
            None => Action::Recycle(index),
        };
        Relation::Change(action)
    }
}

impl<'a> Batch<'a> {
    pub(in crate::conn) fn try_new(
        pending: &'a mut control::Pending,
        input: [Option<local::Candidate<'a>>; conn::MAX_ACTIVE_CONNECTION_IDS],
    ) -> Result<Self, control::Admission> {
        let mut changes = [const { None }; conn::MAX_ACTIVE_CONNECTION_IDS];
        let mut replace: Option<Change<'a>> = None;
        let mut carries = false;
        for (out, offer) in changes.iter_mut().zip(input) {
            let Some(offer) = offer else {
                continue;
            };
            let record = delivery::Control::NewConnectionId(offer.record());
            let relation = Relation::classify(&pending.storage, offer.owner(), record);
            match (offer.phase(), relation) {
                (local::Publication::Awaiting, Relation::Current)
                | (local::Publication::Available, Relation::Current) => carries = true,
                (local::Publication::Awaiting, Relation::Change(action)) => {
                    carries = true;
                    *out = Some(Change { offer, action });
                }
                (local::Publication::Available, Relation::Change(action)) => {
                    if replace.as_ref().is_none_or(|old| {
                        matches!(old.action, Action::Insert) && !matches!(action, Action::Insert)
                    }) {
                        replace = Some(Change { offer, action });
                    }
                }
            }
        }
        if carries {
            replace = None;
        }
        let records = Count::new(
            changes
                .iter()
                .flatten()
                .chain(replace.iter())
                .map(|change| change.action.admission())
                .sum(),
        );
        pending
            .storage
            .slots
            .try_grow(records)
            .map_err(|reason| control::Admission { records, reason })?
            .commit();
        Ok(Self {
            pending,
            changes,
            replace,
        })
    }

    pub(in crate::conn) fn commit(self) {
        let Self {
            pending,
            changes,
            replace,
        } = self;
        for change in changes.into_iter().flatten().chain(replace) {
            let Change { offer, action } = change;
            let record = delivery::Control::NewConnectionId(offer.record());
            match action {
                Action::Revise { index, next } => {
                    // SAFETY: this batch retains the original journal, live slot and exact
                    // next revision; distinct CID owner loans cannot target one another's slot.
                    let live = unsafe {
                        depot::raw::Proof::<(_, _), Initialized<local::Candidate<'a>>>::new((
                            (&mut pending.storage, ()),
                            index,
                        ))
                    };
                    let (mut slot, ()) = Set::project(live);
                    slot.slot.get_mut().revision = next;
                    slot.replace(record);
                }
                Action::Recycle(index) | Action::Retire(index) => {
                    // SAFETY: classification retained this exact occupied member in the batch.
                    let live = unsafe {
                        depot::raw::Proof::<(_, _), Initialized<local::Candidate<'a>>>::new((
                            (&mut pending.storage, ()),
                            index,
                        ))
                    };
                    let (slot, ()) = Set::project(live);
                    slot.remove();
                    let insert = Insert {
                        set: &mut pending.storage,
                        record,
                    };
                    offer.commit(insert.commit().owner());
                }
                Action::Insert => {
                    let insert = Insert {
                        set: &mut pending.storage,
                        record,
                    };
                    offer.commit(insert.commit().owner());
                }
            }
        }
    }
}

/// Admission cost of replacing one existing CID record.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::conn) enum Cid {
    Vacant,
    Mismatch,
    Retire,
    Current,
}

impl Cid {
    pub(in crate::conn) fn get(
        pending: &control::Pending,
        owner: Option<owner::Key<kind::NewCid>>,
        record: local::Announcement,
    ) -> Self {
        match Relation::classify(
            &pending.storage,
            owner,
            delivery::Control::NewConnectionId(record),
        ) {
            Relation::Current => Self::Current,
            Relation::Change(Action::Insert) => Self::Vacant,
            Relation::Change(Action::Retire(_)) => Self::Retire,
            Relation::Change(Action::Revise { .. } | Action::Recycle(_)) => Self::Mismatch,
        }
    }
}

const _: () = assert!(mem::size_of::<Cid>() == 1);
