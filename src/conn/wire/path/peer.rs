use crate::{
    conn::{self, output::control, wire::path},
    runtime::routing,
    wire::{frame::decode, packet, varint},
};
use o3::depot::{array::copy, capacity};
use packet::cid;
use path::reset;
use std::{iter, mem, num, ops};

pub(in crate::conn) enum Error {
    Connection(conn::Error),
    Capacity(capacity::Reason),
}

#[derive(Clone, Copy)]
struct Cid {
    sequence: varint::VarInt,
    id: cid::Id,
    reset_token: Option<reset::Token>,
}

impl Cid {
    fn matches(&self, id: cid::Id, token: reset::Token) -> bool {
        self.id == id && self.reset_token.is_some_and(|known| token.matches(known))
    }
}

pub(in crate::conn) struct Peer {
    active: Cid,
    spare: Spares,
    shard: Option<routing::Shard>,
    retire_prior_to: varint::VarInt,
    reset_tokens_dirty: bool,
}

impl Peer {
    pub(super) fn new(initial: cid::Id, shard: Option<routing::Shard>) -> Self {
        Self {
            active: Cid {
                sequence: varint::VarInt::ZERO,
                id: initial,
                reset_token: None,
            },
            spare: Spares::new(),
            shard,
            retire_prior_to: varint::VarInt::ZERO,
            reset_tokens_dirty: false,
        }
    }
}

impl Peer {
    pub(in crate::conn) fn validate_id(&self, id: cid::Ref<'_>) -> Result<(), conn::Error> {
        if !routing::matches_peer(self.shard, id) {
            return Err(conn::Error::ProtocolViolation);
        }
        Ok(())
    }

    pub(in crate::conn) fn set_id(&mut self, id: cid::Id) -> Result<(), conn::Error> {
        self.validate_id(id.as_ref_id())?;
        if self.active.sequence != varint::VarInt::ZERO {
            return Err(conn::Error::ProtocolViolation);
        }
        self.active.id = id;
        Ok(())
    }

    pub(in crate::conn) fn has_active(&self, token: reset::Token) -> bool {
        self.active
            .reset_token
            .is_some_and(|known| token.matches(known))
    }

    pub(in crate::conn) fn has_spare(&self, token: reset::Token) -> bool {
        match self.spare.selected() {
            Selection::Used(cid) => cid.reset_token.is_some_and(|known| token.matches(known)),
            Selection::Idle | Selection::Reserved(_) => false,
        }
    }

    pub(in crate::conn) fn reset_tokens(&self) -> impl Iterator<Item = reset::Token> + '_ {
        let spare = match self.spare.selected() {
            Selection::Used(cid) => cid.reset_token,
            Selection::Idle | Selection::Reserved(_) => None,
        };
        self.active.reset_token.into_iter().chain(spare)
    }

    pub(in crate::conn) const fn is_dirty(&self) -> bool {
        self.reset_tokens_dirty
    }

    pub(in crate::conn) fn sync_tokens(&mut self) {
        self.reset_tokens_dirty = false;
    }

    pub(in crate::conn) const fn id(&self) -> &cid::Id {
        &self.active.id
    }

    pub(in crate::conn) fn spare(&self) -> Option<&cid::Id> {
        match self.spare.selected() {
            Selection::Reserved(cid) | Selection::Used(cid) => Some(&cid.id),
            Selection::Idle => None,
        }
    }

    pub(in crate::conn) fn reserve(&mut self) {
        self.spare.reserve();
    }

    pub(in crate::conn) fn use_spare(&mut self) {
        self.spare.mark_used(&mut self.reset_tokens_dirty);
    }

    pub(super) fn try_abandon(
        &mut self,
        state: &mut control::Pending,
    ) -> Result<(), capacity::Reason> {
        if self
            .spare
            .try_take(|cid, spare| {
                state.queue().try_retire(
                    cid.sequence,
                    iter::once((self.active.sequence, true)).chain(
                        spare
                            .iter()
                            .map(|other| (other.sequence, other.sequence != cid.sequence)),
                    ),
                )
            })?
            .is_some()
        {
            self.reset_tokens_dirty = true;
        }
        Ok(())
    }

    pub(super) fn try_activate(
        &mut self,
        state: &mut control::Pending,
    ) -> Result<(), capacity::Reason> {
        if self
            .spare
            .try_take(|active, spare| {
                state.queue().try_retire(
                    self.active.sequence,
                    iter::once((self.active.sequence, false))
                        .chain(spare.iter().map(|cid| (cid.sequence, true))),
                )?;
                self.active = active;
                Ok(())
            })?
            .is_some()
        {
            self.reset_tokens_dirty = true;
        }
        Ok(())
    }

    pub(in crate::conn) fn set_token(&mut self, token: [u8; 16]) {
        if self.active.sequence != varint::VarInt::ZERO {
            return;
        }
        let token = reset::Token::new(token);
        if !self
            .active
            .reset_token
            .is_some_and(|known| token.matches(known))
        {
            self.active.reset_token = Some(token);
            self.reset_tokens_dirty = true;
        }
    }

    pub(super) fn accept_cid(
        &mut self,
        state: &mut control::Pending,
        limit: u64,
        update: decode::Notice<cid::Id>,
        retire: decode::Retire,
    ) -> Result<(), Error> {
        let (sequence, prior) = retire.into_parts();
        let (id, token) = update.into_parts();
        if self.active.id.is_empty() {
            return Err(Error::Connection(conn::Error::ProtocolViolation));
        }
        self.validate_id(id.as_ref_id())
            .map_err(Error::Connection)?;
        let token = reset::Token::new(token);
        let known = if self.active.sequence == sequence {
            Some(&self.active)
        } else {
            self.spare.iter().find(|cid| cid.sequence == sequence)
        };
        if let Some(existing) = known
            && !existing.matches(id, token)
        {
            return Err(Error::Connection(conn::Error::ProtocolViolation));
        }
        let known = known.is_some();
        let prior = self.retire_prior_to.max(prior);

        let retained = usize::from(self.active.sequence >= prior)
            + self
                .spare
                .iter()
                .filter(|cid| cid.sequence >= prior)
                .count();
        let admit = !known && sequence.get() > state.probe().retired() && sequence >= prior;
        let obsolete = (!known && !admit).then_some((sequence, false));
        let total = retained + usize::from(admit);
        if total == 0 || total as u64 > limit {
            return Err(Error::Connection(conn::Error::ConnectionIdLimit));
        }

        let incoming = admit.then_some(Cid {
            sequence,
            id,
            reset_token: Some(token),
        });
        let changed = self.active.sequence < prior;
        let next = if changed {
            Some(
                self.spare
                    .iter()
                    .filter(|cid| cid.sequence >= prior)
                    .copied()
                    .chain(incoming)
                    .min_by_key(|cid| cid.sequence)
                    .ok_or(Error::Connection(conn::Error::ConnectionIdLimit))?,
            )
        } else {
            None
        };
        let mut spare = Spares::new();
        self.spare
            .try_update(&mut spare, prior, next, incoming)
            .map_err(Error::Connection)?;
        if prior > self.retire_prior_to || obsolete.is_some() {
            state
                .queue()
                .try_retire(
                    varint::VarInt::saturate(u128::from(prior.get().saturating_sub(1))),
                    iter::once((self.active.sequence, self.active.sequence >= prior))
                        .chain(
                            self.spare
                                .iter()
                                .map(|cid| (cid.sequence, cid.sequence >= prior)),
                        )
                        .chain(obsolete),
                )
                .map_err(|reason| match reason {
                    capacity::Reason::Full => Error::Connection(conn::Error::ConnectionIdLimit),
                    capacity::Reason::Allocation(_) => Error::Capacity(reason),
                })?;
        }
        self.retire_prior_to = prior;
        self.reset_tokens_dirty |= matches!(
            (&self.spare.selection, &spare.selection),
            (Selection::Used(_), Selection::Idle)
        );
        self.spare.values.copy_from(&spare.values);
        self.spare.selection = spare.selection;
        if let Some(next) = next {
            self.active = next;
        }
        self.reset_tokens_dirty |= changed;
        Ok(())
    }
}

const _: () = assert!(mem::size_of::<cid::Id>() == 21);
const _: () = assert!(mem::size_of::<Cid>() == 48);
const _: () = assert!(mem::size_of::<Peer>() == 416);

pub(in crate::conn::wire::path::peer) enum Selection<T> {
    Idle,
    Reserved(T),
    Used(T),
}

#[derive(Clone, Copy)]
struct Slot(num::NonZero<u8>);

pub(in crate::conn::wire::path::peer) struct Spares {
    values: copy::Vec<Cid, { conn::MAX_ACTIVE_CONNECTION_IDS - 1 }>,
    selection: Selection<Slot>,
}

impl Spares {
    fn new() -> Self {
        Self {
            values: copy::Vec::new(),
            selection: Selection::Idle,
        }
    }

    fn selected(&self) -> Selection<&Cid> {
        // SAFETY: reserve/update issue slots from this prefix; every mutation
        // preserves the selected slot or clears it before changing the prefix.
        let get = |slot: Slot| unsafe { self.values.get_unchecked(usize::from(slot.0.get()) - 1) };
        match self.selection {
            Selection::Idle => Selection::Idle,
            Selection::Reserved(slot) => Selection::Reserved(get(slot)),
            Selection::Used(slot) => Selection::Used(get(slot)),
        }
    }

    fn reserve(&mut self) {
        if !matches!(self.selection, Selection::Idle) {
            return;
        }
        if let Some((index, _)) = self
            .values
            .iter()
            .enumerate()
            .min_by(|left, right| left.1.sequence.cmp(&right.1.sequence))
        {
            let slot = Slot(num::NonZero::<u8>::MIN.saturating_add(index as u8));
            self.selection = Selection::Reserved(slot);
        }
    }

    fn mark_used(&mut self, dirty: &mut bool) {
        if let Selection::Reserved(slot) = self.selection {
            self.selection = Selection::Used(slot);
            *dirty = true;
        }
    }

    fn try_take(
        &mut self,
        retire: impl FnOnce(Cid, &[Cid]) -> Result<(), capacity::Reason>,
    ) -> Result<Option<Cid>, capacity::Reason> {
        let cid = match self.selected() {
            Selection::Used(cid) => *cid,
            Selection::Idle | Selection::Reserved(_) => {
                self.selection = Selection::Idle;
                return Ok(None);
            }
        };
        retire(cid, &self.values)?;
        self.selection = Selection::Idle;
        self.values.retain(|other| other.sequence != cid.sequence);
        Ok(Some(cid))
    }

    fn try_update(
        &self,
        output: &mut Self,
        prior: varint::VarInt,
        next: Option<Cid>,
        incoming: Option<Cid>,
    ) -> Result<(), conn::Error> {
        let chosen = match &self.selection {
            Selection::Idle => None,
            Selection::Reserved(slot) | Selection::Used(slot) => Some(slot),
        };
        let mut source = num::NonZero::<u8>::MIN;
        let mut position = num::NonZero::<u8>::MIN;
        let mut selected = None;
        output.values.filter_from(&self.values, |cid| {
            let keep = cid.sequence >= prior
                && !next.is_some_and(|active| active.sequence == cid.sequence);
            if keep {
                if chosen.is_some_and(|slot| slot.0 == source) {
                    selected = Some(Slot(position));
                }
                position = position.saturating_add(1);
            }
            source = source.saturating_add(1);
            keep
        });
        output.selection = match self.selection {
            Selection::Idle => Selection::Idle,
            Selection::Reserved(_) => selected.map_or(Selection::Idle, Selection::Reserved),
            Selection::Used(_) => selected.map_or(Selection::Idle, Selection::Used),
        };
        if let Some(cid) = incoming
            && !next.is_some_and(|active| active.sequence == cid.sequence)
        {
            let Some(vacant) = output.values.vacancy() else {
                return Err(conn::Error::ConnectionIdLimit);
            };
            vacant.insert(cid);
        }
        Ok(())
    }
}

impl ops::Deref for Spares {
    type Target = copy::Vec<Cid, { conn::MAX_ACTIVE_CONNECTION_IDS - 1 }>;

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

const _: () = assert!(conn::MAX_ACTIVE_CONNECTION_IDS - 1 < u8::MAX as usize);
const _: () = assert!(mem::size_of::<Selection<Slot>>() == 2);
const _: () = assert!(mem::size_of::<Spares>() == 352);
