use std::mem;

use o3::depot::capacity::Count;

use crate::conn::output::control;
use crate::conn::wire::path::local;

use crate::conn;
use control::{journal, kind, owner};
use journal::storage;
use local::routes;

#[derive(Clone, Copy)]
struct Summary {
    mutations: Count,
    admissions: Count,
}

enum Replacement {
    Vacant,
    Mismatch,
    Retire,
}

/// CID journal work retaining both owners until its final consumer.
#[derive(Clone, Copy)]
pub(in crate::conn) struct Work<L, C> {
    local: L,
    control: C,
}

impl<L, C> Work<L, C> {
    pub(super) const fn new(local: L, control: C) -> Self {
        Self { local, control }
    }
}

impl<'a> Work<&'a local::State, &'a control::Pending> {
    fn summary(self) -> Summary {
        Summary::new(self.local, self.control)
    }

    pub(in crate::conn) fn controls(self) -> Count {
        self.summary().mutations
    }

    pub(in crate::conn) fn fits(self, room: Count) -> bool {
        let summary = self.summary();
        summary.mutations.raw() != 0 && summary.admissions <= room
    }
}

pub(in crate::conn) struct Candidate<'a> {
    owner: &'a mut Option<owner::Key<kind::NewCid>>,
    record: local::Announcement,
    phase: local::Publication,
}

impl Candidate<'_> {
    pub(in crate::conn) fn record(&self) -> local::Announcement {
        self.record
    }
    pub(in crate::conn) fn phase(&self) -> local::Publication {
        self.phase
    }
    pub(in crate::conn) fn owner(&self) -> Option<owner::Key<kind::NewCid>> {
        *self.owner
    }
    pub(in crate::conn) fn commit(self, key: owner::Key<kind::NewCid>) {
        *self.owner = Some(key);
    }
}

impl<'a> Work<&'a mut local::State, &'a mut control::Pending> {
    pub(in crate::conn) fn queue(self) -> Result<(), control::Admission> {
        let prior = self.local.cids.watermark();
        let mut input = [const { None }; conn::MAX_ACTIVE_CONNECTION_IDS];
        for (out, (index, slot)) in input
            .iter_mut()
            .zip(routes::Index::iter().zip(&mut self.local.cids.slots))
        {
            let Some(cid) = slot.cid.get_mut() else {
                continue;
            };
            let Some((record, phase)) =
                cid.announce(prior, index.key(slot.generation), slot.node.get())
            else {
                continue;
            };
            *out = Some(Candidate {
                owner: &mut cid.control,
                record,
                phase,
            });
        }
        storage::Batch::try_new(self.control, input)?.commit();
        Ok(())
    }
}

impl Summary {
    fn new(local: &local::State, control: &control::Pending) -> Self {
        let prior = local.cids.watermark();
        let mut changes = 0;
        let mut admits = 0;
        let mut carries = false;
        let mut replace = None;
        for (index, slot) in routes::Index::iter().zip(&local.cids.slots) {
            let Some(cid) = slot.cid.get() else {
                continue;
            };
            let key = index.key(slot.generation);
            let Some((record, phase)) = cid.announce(prior, key, slot.node.get()) else {
                continue;
            };
            let state = storage::Cid::get(control, cid.control, record);
            if phase == local::Publication::Awaiting {
                carries = true;
                match state {
                    storage::Cid::Current => {}
                    storage::Cid::Mismatch => changes += 1,
                    storage::Cid::Vacant | storage::Cid::Retire => {
                        changes += 1;
                        admits += 1;
                    }
                }
                continue;
            }
            match state {
                storage::Cid::Current => carries = true,
                storage::Cid::Mismatch | storage::Cid::Retire => {
                    if !matches!(replace, Some(Replacement::Mismatch | Replacement::Retire)) {
                        replace = Some(if state == storage::Cid::Retire {
                            Replacement::Retire
                        } else {
                            Replacement::Mismatch
                        });
                    }
                }
                storage::Cid::Vacant => {
                    if replace.is_none() {
                        replace = Some(Replacement::Vacant);
                    }
                }
            }
        }
        if !carries {
            match replace {
                Some(Replacement::Mismatch) => {
                    changes += 1;
                }
                Some(Replacement::Vacant | Replacement::Retire) => {
                    changes += 1;
                    admits += 1;
                }
                None => {}
            }
        };
        Self {
            mutations: Count::new(changes),
            admissions: Count::new(admits),
        }
    }
}

const _: () = {
    assert!(
        mem::size_of::<Work<&'static local::State, &'static control::Pending>>()
            == mem::size_of::<usize>() * 2
    );
    assert!(!mem::needs_drop::<
        Work<&'static local::State, &'static control::Pending>,
    >());
};
