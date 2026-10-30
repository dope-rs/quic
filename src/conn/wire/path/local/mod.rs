mod key;
mod raw;
pub(crate) mod routes;
mod work;

pub(crate) use key::{LocalCidKey, RouteKey};
pub(in crate::conn) use work::{Candidate, Work};

use std::{array, mem, num};

use o3::{
    depot::{
        capacity::Count,
        queue::{links, tagged},
    },
    mem::slot,
};

use crate::conn::output::control;
use crate::conn::wire::path;
use crate::{conn, security::secrets, wire::packet, wire::varint};

use control::kind;
use control::owner;
use packet::cid;

/// An issued CID with an ordered retirement watermark.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::conn) struct Announcement {
    sequence: varint::VarInt,
    retire: varint::VarInt,
    key: path::LocalCidKey,
}

impl Announcement {
    pub(in crate::conn) const fn sequence(self) -> varint::VarInt {
        self.sequence
    }

    pub(in crate::conn) const fn retire(self) -> varint::VarInt {
        self.retire
    }

    pub(in crate::conn) const fn key(self) -> path::LocalCidKey {
        self.key
    }
}

/// The one CID value retained through detached, linked, and retiring phases.
pub(crate) struct Assigned {
    value: cid::Id,
    local: Option<LocalCidKey>,
    hook: tagged::Hook,
}

impl Assigned {
    pub(crate) fn new(value: cid::Id, local: Option<LocalCidKey>, index: links::Index) -> Self {
        Self {
            value,
            local,
            hook: tagged::Hook::new(index),
        }
    }

    pub(crate) const fn value(&self) -> cid::Id {
        self.value
    }

    pub(crate) const fn local(&self) -> Option<LocalCidKey> {
        self.local
    }

    pub(crate) const fn hook(&self) -> &tagged::Hook {
        &self.hook
    }
}

struct LocalCid {
    sequence: varint::VarInt,
    reset_token: [u8; 16],
    control: Option<owner::Key<kind::NewCid>>,
    phase: Phase,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Phase {
    /// The route exists locally, but no committed packet has advertised it.
    Awaiting,
    /// At least one committed packet made the CID usable by the peer.
    Available,
    /// Excluded from the next retirement watermark until the peer retires it.
    Retiring,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::conn) enum Publication {
    Awaiting,
    Available,
}

impl LocalCid {
    fn announce(
        &self,
        prior: varint::VarInt,
        key: path::LocalCidKey,
        assigned: Option<&Assigned>,
    ) -> Option<(Announcement, Publication)> {
        let phase = match self.phase {
            Phase::Awaiting => Publication::Awaiting,
            Phase::Available => Publication::Available,
            Phase::Retiring => return None,
        };
        if self.sequence == varint::VarInt::ZERO || self.sequence < prior || assigned.is_none() {
            return None;
        }
        Some((
            Announcement {
                sequence: self.sequence,
                retire: prior,
                key,
            },
            phase,
        ))
    }
}

struct Slot {
    generation: u32,
    cid: slot::Storage<LocalCid>,
    node: slot::Storage<Assigned>,
}

struct Set {
    slots: [Slot; conn::MAX_ACTIVE_CONNECTION_IDS],
    next_sequence: num::NonZero<u64>,
    largest_sent: varint::VarInt,
    target: u8,
    burned: u8,
}

impl Set {
    fn new(initial: cid::Id) -> Self {
        let slots = array::from_fn(|index| Slot {
            generation: 0,
            cid: if index == 0 {
                slot::Storage::filled(
                    LocalCid {
                        sequence: varint::VarInt::ZERO,
                        reset_token: [0; 16],
                        control: None,
                        phase: Phase::Available,
                    },
                    (),
                )
            } else {
                slot::Storage::new(())
            },
            node: if index == 0 {
                slot::Storage::filled(
                    Assigned::new(
                        initial,
                        Some(LocalCidKey::INITIAL),
                        links::Index::from(num::NonZero::<u32>::MIN),
                    ),
                    (),
                )
            } else {
                slot::Storage::new(())
            },
        });
        Self {
            slots,
            next_sequence: num::NonZero::<u64>::MIN,
            largest_sent: varint::VarInt::ZERO,
            target: 1,
            burned: 0,
        }
    }

    fn resolve(&self, key: path::LocalCidKey) -> Option<(&LocalCid, &Assigned)> {
        let slot = self.slots.get(key.slot())?;
        if slot.generation != key.generation() {
            return None;
        }
        Some((slot.cid.get()?, slot.node.get()?))
    }

    fn insert(&mut self, pending: &routes::Pending, cid: LocalCid) -> Option<routes::Issued> {
        let (index, vacant) =
            routes::Index::iter()
                .zip(&mut self.slots)
                .find_map(|(index, slot)| {
                    let vacant = slot.cid.vacant()?;
                    let bit = 1_u8 << index.get();
                    if pending.has_removal(index)
                        || self.burned & bit != 0
                        || (index.get() == 0 && slot.generation == 0)
                    {
                        return None;
                    }
                    Some((index, vacant))
                })?;
        vacant.insert(cid);
        Some(routes::Issued::new(index))
    }

    fn iter(&self) -> impl Iterator<Item = &LocalCid> {
        self.slots.iter().filter_map(|slot| slot.cid.get())
    }

    fn len(&self) -> usize {
        self.iter().count()
    }

    fn watermark(&self) -> varint::VarInt {
        self.iter()
            .filter(|cid| cid.phase != Phase::Retiring)
            .map(|cid| cid.sequence)
            .min()
            .unwrap_or(varint::VarInt::ZERO)
    }

    fn rotate(&mut self) -> Option<&mut LocalCid> {
        if self.iter().any(|cid| cid.phase == Phase::Retiring) {
            return None;
        }
        let (victim, seq) = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.cid.get().map(|cid| (index, cid.sequence)))
            .min_by_key(|item| item.1)?;
        let has_next = self.slots.iter().any(|slot| {
            slot.cid
                .get()
                .is_some_and(|cid| cid.sequence > seq && cid.sequence <= self.largest_sent)
        });
        if !has_next {
            return None;
        }
        let cid = self.slots.get_mut(victim)?.cid.get_mut()?;
        cid.phase = Phase::Retiring;
        Some(cid)
    }

    fn issue(&mut self, issuance: &mut Issuance, pending: &routes::Pending) -> Fill {
        let Some(sequence) = varint::VarInt::new(self.next_sequence.get()) else {
            return Fill::Sequence;
        };
        let next = num::NonZero::<u64>::MIN.saturating_add(sequence.get());
        let Some(index) = self.insert(
            pending,
            LocalCid {
                sequence,
                reset_token: [0; 16],
                control: None,
                phase: Phase::Awaiting,
            },
        ) else {
            return Fill::Slots;
        };
        issuance.issues.insert(index);
        self.next_sequence = next;
        Fill::Added
    }

    fn fill(&mut self, issuance: &mut Issuance, pending: &routes::Pending) -> Count {
        let mut count = 0;
        for _ in self.len()..usize::from(self.target) {
            match self.issue(issuance, pending) {
                Fill::Added => count += 1,
                Fill::Sequence | Fill::Slots => break,
            }
        }
        Count::new(count)
    }
}

enum Fill {
    Added,
    Sequence,
    Slots,
}

struct Issuance {
    secret: secrets::Reset,
    issues: routes::Issues,
    auto: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::conn) enum Rotation {
    Queued,
    Unavailable,
}

pub(in crate::conn) struct State {
    initial: cid::Id,
    cids: Set,
    pending: routes::Pending,
    issuance: slot::Storage<Issuance>,
    pub(super) active_connection_id_limit: u64,
}

impl State {
    pub(super) fn new(initial: cid::Id, secret: Option<secrets::Reset>, limit: u64) -> Self {
        let issuance = match secret {
            Some(secret) => (!initial.is_empty()).then_some(Issuance {
                secret,
                issues: routes::Issues::default(),
                auto: false,
            }),
            None => None,
        };
        Self {
            initial,
            cids: Set::new(initial),
            pending: routes::Pending::default(),
            issuance: match issuance {
                Some(value) => slot::Storage::filled(value, ()),
                None => slot::Storage::new(()),
            },
            active_connection_id_limit: limit,
        }
    }

    pub(in crate::conn) fn cid(&self) -> cid::Ref<'_> {
        self.initial.as_ref_id()
    }

    pub(in crate::conn) const fn id(&self) -> cid::Id {
        self.initial
    }

    pub(in crate::conn) fn is_dirty(&self) -> bool {
        !self.pending.is_empty()
            || self
                .issuance
                .get()
                .is_some_and(|issuance| !issuance.issues.is_empty())
    }

    pub(crate) fn drain(&self) -> Option<routes::Drain> {
        self.is_dirty().then(routes::Drain::new)
    }

    pub(in crate::conn) fn identity(
        &self,
        key: path::LocalCidKey,
    ) -> Option<(varint::VarInt, cid::Ref<'_>, [u8; 16])> {
        let (cid, node) = self.cids.resolve(key)?;
        Some((cid.sequence, node.value.as_ref_id(), cid.reset_token))
    }

    pub(in crate::conn) fn cids(&self) -> impl Iterator<Item = (varint::VarInt, &[u8])> {
        self.cids
            .slots
            .iter()
            .filter_map(|slot| Some((slot.cid.get()?.sequence, slot.node.get()?.value.as_slice())))
    }

    pub(in crate::conn) fn issue_cids(&mut self, limit: u64) -> Count {
        let Some(issuance) = self.issuance.get_mut() else {
            return Count::EMPTY;
        };
        if issuance.auto {
            return Count::EMPTY;
        }
        issuance.auto = true;
        self.cids.target = limit.min(conn::MAX_ACTIVE_CONNECTION_IDS as u64) as u8;
        self.cids.fill(issuance, &self.pending)
    }

    pub(in crate::conn) fn work<'a>(
        &'a self,
        control: &'a control::Pending,
    ) -> Work<&'a State, &'a control::Pending> {
        Work::new(self, control)
    }

    pub(in crate::conn) fn plan<'a>(
        &'a mut self,
        control: &'a mut control::Pending,
    ) -> Work<&'a mut State, &'a mut control::Pending> {
        Work::new(self, control)
    }

    pub(in crate::conn) fn rotate(&mut self, control: &mut control::Pending) -> Rotation {
        let Some(cid) = self.cids.rotate() else {
            return Rotation::Unavailable;
        };
        control.remove(&mut cid.control);
        Rotation::Queued
    }

    pub(in crate::conn) fn retire(
        &mut self,
        sequence: varint::VarInt,
        routed: Option<path::LocalCidKey>,
        dcid: &[u8],
        control: &mut control::Pending,
    ) -> Result<Count, conn::Error> {
        if self.initial.as_slice().is_empty() || sequence > self.cids.largest_sent {
            return Err(conn::Error::ProtocolViolation);
        }
        for (index, slot) in routes::Index::iter().zip(&mut self.cids.slots) {
            let Some(retired) = slot.cid.occupied() else {
                continue;
            };
            if retired.get().sequence != sequence {
                continue;
            }
            let key = index.key(slot.generation);
            if routed == Some(key)
                || slot
                    .node
                    .get()
                    .is_some_and(|node| node.value.as_slice() == dcid)
            {
                return Err(conn::Error::ProtocolViolation);
            }
            let (mut retired, _) = retired.take();
            self.pending.remove(index);
            control.remove(&mut retired.control);
            let count = usize::from(self.cids.target).saturating_sub(self.cids.len());
            return Ok(Count::new(count as u32));
        }
        Ok(Count::EMPTY)
    }
}

const _: () = {
    assert!(mem::size_of::<Announcement>() == 24);
    assert!(mem::size_of::<Option<Announcement>>() == 24);
    assert!(conn::MAX_ACTIVE_CONNECTION_IDS <= u32::MAX as usize);
    assert!(mem::size_of::<Phase>() == 1);
    assert!(!mem::needs_drop::<Phase>());
};
