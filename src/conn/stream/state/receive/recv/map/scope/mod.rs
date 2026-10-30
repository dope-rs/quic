use crate::conn;
use crate::conn::stream::state::receive::recv::map::views;
use crate::errors::detail;
use crate::{
    conn::{
        stream::{
            event::queue::{self, readable},
            resident::{
                self,
                slot::{plane, store::scope},
            },
            state::{
                receive::recv::{
                    self,
                    map::{self, recycle},
                },
                resident::scopes,
            },
        },
        wire::ingress::frames,
    },
    stream::Recv,
    wire::stream::Id,
};
use bound::Bound;
use o3::depot;
use o3::depot::arena::linked::slots;
use o3::depot::array::init::{Guard, Prefix};
use o3::depot::capacity;
pub(in crate::conn) use storage::Storage;

mod bound;
mod storage;

pub(in crate::conn) struct Preparation<'a, 'id, 'table, B: Recv> {
    state: State<'a, 'id, 'table, B>,
    storage: &'a mut Storage,
}

pub(in crate::conn) struct Batch<'a, 'id, 'table, 'body, B: Recv> {
    state: State<'a, 'id, 'table, B>,
    values: Guard<'a, Bound<'id, 'table, 'body, B>, { conn::MAX_FRAMES_PER_PACKET }>,
}

struct State<'a, 'id, 'table, B: Recv> {
    core:
        scope::Pool<'a, 'id, map::Side, recv::Entry<B>, Option<readable::Handle>, plane::HeadOnly>,
    arena: &'a depot::raw::Arena<map::Node<B>, map::Tag>,
    table: scopes::Scope<'a, 'table>,
    slots: capacity::Count,
}

impl<'a, 'id, 'table, B: Recv> Preparation<'a, 'id, 'table, B> {
    pub(in crate::conn::stream::state::receive::recv::map) fn new(
        core: scope::Pool<
            'a,
            'id,
            map::Side,
            recv::Entry<B>,
            Option<readable::Handle>,
            plane::HeadOnly,
        >,
        arena: &'a depot::raw::Arena<map::Node<B>, map::Tag>,
        table: scopes::Scope<'a, 'table>,
        storage: &'a mut Storage,
    ) -> Self {
        Self {
            state: State {
                core,
                arena,
                table,
                slots: capacity::Count::EMPTY,
            },
            storage,
        }
    }

    pub(in crate::conn) fn prepare_all<'source, 'body, V, I, E>(
        self,
        source: &'source Prefix<'_, '_, V, { conn::MAX_FRAMES_PER_PACKET }>,
        mut make: impl FnMut(
            &'source V,
        )
            -> Result<Option<(Option<resident::Key>, Id, I)>, detail::Scope<E>>,
        mut fill: impl FnMut(I, views::Write<'a, '_, B>) -> Result<recv::Prepared<'body, B>, E>,
    ) -> Result<Batch<'a, 'id, 'table, 'body, B>, detail::Scope<E>> {
        let Self { mut state, storage } = self;
        match Guard::try_map(storage.entries(), source, |row| {
            let Some((key, id, input)) = make(row)? else {
                return Ok(None);
            };
            state
                .prepare(key, id, |target| fill(input, target))
                .map(Some)
        }) {
            Ok(values) => Ok(Batch { state, values }),
            Err((values, error)) => {
                Batch { state, values }.cancel();
                Err(error)
            }
        }
    }
}

impl<'a, 'id, 'table, B: Recv> State<'a, 'id, 'table, B> {
    fn prepare<'body, E>(
        &mut self,
        key: Option<resident::Key>,
        id: Id,
        prepare: impl FnOnce(views::Write<'a, '_, B>) -> Result<recv::Prepared<'body, B>, E>,
    ) -> Result<Bound<'id, 'table, 'body, B>, detail::Scope<E>> {
        let binding = self.table.claim(key, id).map_err(detail::Scope::Stale)?;
        let current = self.slots;
        let (bound, slots) = match binding {
            scopes::Entry::Occupied {
                lease: resident,
                slot,
            } => {
                let lease = self.core.bind(slot).ok_or(detail::Scope::Slot { id })?;
                let (actual, _, receiver, _) = self.core.get(&lease);
                if actual != id {
                    return Err(detail::Scope::Identity {
                        expected: id,
                        actual,
                    });
                }
                let data = prepare(views::Write {
                    entry: receiver,
                    arena: self.arena,
                })
                .map_err(|error| detail::Scope::Prepare { id, error })?;
                let slots = Self::count(current, data.slots())?;
                (
                    Bound::Existing {
                        lease,
                        resident,
                        data,
                    },
                    slots,
                )
            }
            scopes::Entry::Vacant(resident) => {
                let arena = self.arena;
                let prepared = self.core.try_insert(
                    map::Id::new(id).0,
                    (),
                    recycle::Fresh::new(arena),
                    |entry| {
                        let data = prepare(views::Write { entry, arena })
                            .map_err(|error| detail::Scope::Prepare { id, error })?;
                        let slots = Self::count(current, data.slots())?;
                        Ok((data, slots))
                    },
                );
                let (lease, (data, slots)) = match prepared {
                    Ok(prepared) => prepared,
                    Err(scope::Error::Full) => {
                        resident.release();
                        return Err(detail::Scope::Full { id });
                    }
                    Err(scope::Error::Preparation(error)) => {
                        resident.release();
                        return Err(error);
                    }
                };
                let (_, handle, _, _) = self.core.get(&lease);
                let resident = resident.bind(handle);
                (
                    Bound::Fresh {
                        lease,
                        resident,
                        data,
                    },
                    slots,
                )
            }
            scopes::Entry::Unavailable => return Err(detail::Scope::Slot { id }),
        };
        self.slots = slots;
        Ok(bound)
    }

    fn count<E>(
        current: capacity::Count,
        extra: capacity::Count,
    ) -> Result<capacity::Count, detail::Scope<E>> {
        current
            .raw()
            .checked_add(extra.raw())
            .map(capacity::Count::new)
            .ok_or(detail::Scope::Slots {
                current,
                additional: extra,
            })
    }
}

impl<B: Recv> Batch<'_, '_, '_, '_, B> {
    pub(in crate::conn) fn cancel(self) {
        let Self { mut state, values } = self;
        for bound in values.as_slice() {
            if let Bound::Fresh { resident, .. } = bound {
                state.table.clear(resident);
            }
        }
        let mut canceled = state.core.cancel();
        let mut table = state.table.cancel();
        for bound in values {
            if let Bound::Fresh {
                lease, resident, ..
            } = bound
            {
                table.remove(resident);
                canceled.retire(lease, recycle::Fresh::new(state.arena));
            }
        }
    }
}

pub(in crate::conn) struct Input<'a, 'id, 'table, 'body, 'b, 'events, 'commit, B: Recv> {
    scope: Batch<'a, 'id, 'table, 'body, B>,
    events: &'b mut queue::Permit<'events>,
    permit: &'b frames::CommitPermit<'commit>,
}

impl<'a, 'id, 'table, 'body, 'b, 'events, 'commit, B: Recv>
    Input<'a, 'id, 'table, 'body, 'b, 'events, 'commit, B>
{
    pub(in crate::conn) fn new(
        scope: Batch<'a, 'id, 'table, 'body, B>,
        permit: &'b frames::CommitPermit<'commit>,
        events: &'b mut queue::Permit<'events>,
    ) -> Self {
        Self {
            scope,
            events,
            permit,
        }
    }
}

// SAFETY: every prepared receiver retains this exclusive storage scope's
// invariant brand. Its owned projections consume the admitted peak quota;
// detached gaps supply their original vacancies when delivered or recycled.
unsafe impl<'a, B: Recv> depot::raw::LinkedBatch<'a, map::Node<B>, map::Tag>
    for Input<'a, '_, '_, '_, '_, '_, '_, B>
{
    type Output = ();
    type Error = capacity::Shortage;

    fn nodes(&self) -> &'a depot::raw::Arena<map::Node<B>, map::Tag> {
        self.scope.state.arena
    }

    fn count(&self) -> capacity::Count {
        self.scope.state.slots
    }

    fn reject(self, error: capacity::Shortage) -> Self::Error {
        self.scope.cancel();
        error
    }

    fn run(mut self, reserve: &mut slots::Reserve<'a, map::Node<B>, map::Tag>) {
        let mut table = self.scope.state.table.commit();
        for bound in self.scope.values {
            let (id, receiver, position, resident, data) = match bound {
                Bound::Existing {
                    lease,
                    resident,
                    data,
                } => {
                    let (id, _, receiver, position) = self.scope.state.core.get(&lease);
                    (id, receiver, position, resident, data)
                }
                Bound::Fresh {
                    lease,
                    resident,
                    data,
                } => {
                    let (id, _, receiver, position) = self.scope.state.core.get(&lease);
                    (id, receiver, position, resident.commit(), data)
                }
            };
            let readable = data.readable;
            views::Write {
                entry: receiver,
                arena: self.scope.state.arena,
            }
            .apply(self.permit, data, reserve);
            if readable {
                let key = resident.local().key();
                let hold = table.hold(&resident);
                if matches!(
                    self.events.push_read(hold, key, position, id),
                    queue::Push::Rollback
                ) {
                    table.refund(&resident);
                }
            }
        }
    }
}
