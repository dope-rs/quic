use o3::buffer;
use std::convert;

use crate::{conn, stream};

use crate::wire::varint::VarInt;
use conn::stream::state::transmit::queue;
use conn::stream::{Error, SendOutcome};
use conn::stream::{resident, state::resident::Table};
use queue::{budget, occupied::Append};
use send::admit;
use stream::{outbound, send};

pub(in crate::conn) fn check_copy<D: buffer::raw::Segment>(
    queue: &mut queue::Map<D>,
    data: &[u8],
) -> Result<(), Error> {
    queue
        .data
        .budget
        .admit(outbound::Charge::for_copy(data))
        .map_err(|error| match error {
            budget::Denied::Blocked => Error::Capacity,
            budget::Denied::TooLarge => Error::ValueOutOfRange,
        })
}

pub(in crate::conn) fn recycle<D: buffer::raw::Segment>(
    queue: &mut queue::Map<D>,
    parts: send::Parts<D>,
) {
    queue.data.budget.recycle(&mut queue.data.buffers, parts);
}

/// Retains the entire issuing queue unchanged until its admitted input is published.
pub(in crate::conn) struct Plan<'a, D: buffer::raw::Segment, W> {
    owner: outbound::Input<W>,
    queue: &'a mut queue::Map<D>,
    charge: outbound::Charge,
}

pub(in crate::conn) struct Observed<'a, D: buffer::raw::Segment, C, W> {
    source: admit::Source,
    plan: Plan<'a, D, W>,
    commit: C,
}

struct Ignore;

impl<D: buffer::raw::Segment, W> admit::Commit<D, W> for Ignore {
    type Retained = Self;
    type Discarded = Self;

    fn retained(self, _: admit::Admission<'_, D, W>) -> Self {
        self
    }

    fn discarded(self, _: admit::Discard<W>) -> Self {
        self
    }
}

pub(in crate::conn) enum Reject<W> {
    Blocked(W),
    Failed { owner: W, error: Error },
}

pub(in crate::conn) enum Rejected<C, W> {
    Blocked { owner: W, commit: C },
    Failed { owner: W, commit: C, error: Error },
}

impl<W> Reject<W> {
    pub(in crate::conn) fn into_outcome(self) -> SendOutcome<W> {
        match self {
            Self::Blocked(owner) => SendOutcome::Blocked(owner),
            Self::Failed { owner, error } => SendOutcome::Failed { owner, error },
        }
    }

    fn observe<C>(self, commit: C) -> Rejected<C, W> {
        match self {
            Self::Blocked(owner) => Rejected::Blocked { owner, commit },
            Self::Failed { owner, error } => Rejected::Failed {
                owner,
                commit,
                error,
            },
        }
    }
}

impl<C, W> Rejected<C, W> {
    pub(in crate::conn) fn into_outcome<D: buffer::raw::Segment, E>(
        self,
        map: impl FnOnce(Error) -> E,
    ) -> admit::Outcome<D, C, E, W>
    where
        C: admit::Commit<D, W>,
    {
        match self {
            Self::Blocked { owner, commit } => admit::Outcome::Blocked { owner, commit },
            Self::Failed {
                owner,
                commit,
                error,
            } => admit::Outcome::Failed {
                owner,
                commit,
                error: map(error),
            },
        }
    }
}

impl<'a, D: buffer::raw::Segment, W> Plan<'a, D, W> {
    pub(in crate::conn) fn try_new(
        owner: W,
        queue: &'a mut queue::Map<D>,
    ) -> Result<Self, Reject<W>>
    where
        W: send::raw::Batch<D>,
    {
        let (owner, charge) =
            outbound::Input::try_new(owner).map_err(|(owner, error)| Reject::Failed {
                owner,
                error: Error::Demand(error),
            })?;
        match queue.data.budget.admit(charge) {
            Ok(()) => {}
            Err(budget::Denied::Blocked) => {
                return Err(Reject::Blocked(owner.into_owner()));
            }
            Err(budget::Denied::TooLarge) => {
                return Err(Reject::Failed {
                    owner: owner.into_owner(),
                    error: Error::ValueOutOfRange,
                });
            }
        }
        Ok(Self {
            owner,
            queue,
            charge,
        })
    }

    pub(in crate::conn) fn apply(
        self,
        id: queue::Id,
        credit: VarInt,
        mode: queue::Preparation,
        table: &mut Table,
    ) -> SendOutcome<W>
    where
        W: send::raw::Batch<D>,
    {
        let observed = Observed {
            source: admit::Source::new(id.0.id()),
            plan: self,
            commit: Ignore,
        };
        match observed.apply(id, credit, mode, table) {
            admit::Outcome::Retained(Ignore) | admit::Outcome::Discarded(Ignore) => {
                SendOutcome::Accepted
            }
            admit::Outcome::Blocked { owner, .. } => SendOutcome::Blocked(owner),
            admit::Outcome::Failed { owner, error, .. } => SendOutcome::Failed { owner, error },
        }
    }
}

impl<'a, D: buffer::raw::Segment, C, W> Observed<'a, D, C, W> {
    pub(in crate::conn) fn try_new(
        source: admit::Source,
        owner: W,
        commit: C,
        queue: &'a mut queue::Map<D>,
    ) -> Result<Self, Rejected<C, W>>
    where
        C: admit::Commit<D, W>,
        W: send::raw::Batch<D>,
    {
        let plan = match Plan::try_new(owner, queue) {
            Ok(plan) => plan,
            Err(error) => return Err(error.observe(commit)),
        };
        Ok(Self {
            source,
            plan,
            commit,
        })
    }

    pub(in crate::conn) fn apply(
        self,
        id: queue::Id,
        credit: VarInt,
        mode: queue::Preparation,
        table: &mut Table,
    ) -> admit::Outcome<D, C, Error, W>
    where
        C: admit::Commit<D, W>,
        W: send::raw::Batch<D>,
    {
        self.select(
            |queue| queue.try_prepared(id, None, credit, mode, table, |_, slot| slot),
            convert::identity,
        )
    }

    pub(in crate::conn) fn try_apply(
        self,
        local: resident::Local,
        credit: VarInt,
        mode: queue::Preparation,
        table: &mut Table,
    ) -> admit::Outcome<D, C, resident::Error, W>
    where
        C: admit::Commit<D, W>,
        W: send::raw::Batch<D>,
    {
        self.select(
            |queue| queue.try_live(local, credit, mode, table),
            resident::Error::Stream,
        )
    }

    fn select<E>(
        self,
        select: impl for<'s> FnOnce(&'s mut queue::Map<D>) -> Result<Option<queue::Occupied<'s, D>>, E>,
        map: impl FnOnce(Error) -> E,
    ) -> admit::Outcome<D, C, E, W>
    where
        C: admit::Commit<D, W>,
        W: send::raw::Batch<D>,
    {
        let Self {
            source,
            plan:
                Plan {
                    owner,
                    queue,
                    charge,
                },
            commit,
        } = self;
        let bytes = charge.wire_bytes;
        let mut occupied = match select(queue) {
            Ok(Some(occupied)) => occupied,
            Ok(None) => {
                recycle(queue, owner.into_owner().into_parts());
                return admit::Outcome::Discarded(
                    commit.discarded(admit::Discard::new(source, admit::Cause::Retired)),
                );
            }
            Err(error) => {
                return admit::Outcome::Failed {
                    owner: owner.into_owner(),
                    commit,
                    error,
                };
            }
        };
        let (_, entry, mut chunks, pending, budget, buffers) = occupied.split();
        let open = match entry.open() {
            Ok(open) => open,
            Err(cause) => {
                budget.recycle(buffers, owner.into_owner().into_parts());
                return admit::Outcome::Discarded(
                    commit.discarded(admit::Discard::new(source, cause)),
                );
            }
        };
        let Some(append) = Append::new(open, pending, bytes) else {
            return admit::Outcome::Failed {
                owner: owner.into_owner(),
                commit,
                error: map(Error::ValueOutOfRange),
            };
        };
        let (boundary, retained) = match chunks.try_extend(owner.observe(source, commit)) {
            Ok(output) => output,
            Err(rejected) => {
                return admit::Outcome::Failed {
                    owner: rejected.owner,
                    commit: rejected.commit,
                    error: map(Error::Chunks(rejected.error)),
                };
            }
        };
        budget.commit(charge, buffers);
        append.commit(boundary);
        occupied.refresh();
        admit::Outcome::Retained(retained)
    }
}
