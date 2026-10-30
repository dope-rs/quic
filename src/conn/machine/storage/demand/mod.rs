//! Bounded generational storage whose exact backing follows its high-water.
use std::{marker, mem};

use o3::{
    alloc::array,
    base::num::bounded,
    depot,
    depot::{arena::slab::key, capacity, queue::links},
};

use crate::conn::{
    Selected,
    machine::storage::{self, compact, demand},
};

pub(in crate::conn) mod raw;

#[derive(Clone, Copy)]
#[repr(C)]
struct Key<const MAX: u32> {
    index: bounded::U32<0, { u32::MAX - 1 }>,
    epoch: key::Generation<MAX>,
}

impl<const MAX: u32> Key<MAX> {
    fn new(index: links::Index, epoch: key::Generation<MAX>) -> Self {
        Self {
            index: bounded::U32::from_one(index.position()),
            epoch,
        }
    }
}

impl<const MAX: u32> From<Key<MAX>> for links::Index {
    fn from(val: Key<MAX>) -> Self {
        val.index.into()
    }
}

/// Bounded storage whose exact backing follows its high-water mark.
pub(in crate::conn) struct Table<T, Tag = (), const MAX: u32 = { u32::MAX }> {
    core: compact::raw::Core<T, key::Generation<MAX>>,
    limit: capacity::Count,
    tag: marker::PhantomData<*mut Tag>,
}

/// The generation-checked state of one owner handle.
pub(in crate::conn) enum Entry<'a, T, Tag = (), const MAX: u32 = { u32::MAX }> {
    Occupied(Occupied<'a, T, Tag, MAX>),
    Stale(&'a mut Table<T, Tag, MAX>),
}

impl<T, Tag, const MAX: u32> Table<T, Tag, MAX> {
    pub(in crate::conn::machine::storage::demand) fn insert<O>(
        mut owner: O,
    ) -> Selected<O::Output, links::Index, O::Plane>
    where
        O: demand::raw::Owner<MAX, Value = T, Tag = Tag>,
    {
        let (table, context) = owner.parts();
        // SAFETY: O is a consuming native vacancy proof for this exact table.
        let lease = unsafe { table.core.reserve() };
        let value = O::build(lease.index(), context);
        let index = lease.insert(value).index();
        // SAFETY: initialization consumed O's vacancy, and finish retains its
        // original owner and lifetime in the resulting occupied capability.
        unsafe { depot::raw::Proof::new((owner.finish(), index)) }
    }

    #[must_use]
    pub(in crate::conn) fn with_limit(limit: capacity::Count) -> Self {
        Self {
            core: compact::raw::Core::empty(limit),
            limit,
            tag: marker::PhantomData,
        }
    }

    /// Plans backing for `additional` later insertions.
    pub(in crate::conn) fn try_grow(
        &mut self,
        added: capacity::Count,
    ) -> Result<demand::Growth<'_, T, Tag, MAX>, capacity::Reason> {
        let room = self.core.available();
        let resident = self.core.capacity();
        let used = self.limit.raw() - room.raw();
        let total = used
            .checked_add(added.raw())
            .map(capacity::Count::new)
            .ok_or(capacity::Reason::Full)?;
        let spare = if total > resident {
            let plan = storage::Plan::geometric(resident.get(), total.get(), self.limit.get())
                .ok_or(capacity::Reason::Full)?;
            Some(
                array::Block::try_new(capacity::Count::new(plan.capacity().get()), ())
                    .map_err(capacity::Reason::Allocation)?,
            )
        } else {
            None
        };
        Ok(Growth { table: self, spare })
    }

    pub(in crate::conn) fn entry(&mut self, key: key::Handle<Tag, MAX>) -> Entry<'_, T, Tag, MAX> {
        let epoch = self.core.generation(key.index());
        if epoch == Some(key.generation()) {
            return Entry::Occupied(Occupied {
                // SAFETY: this exact generation is occupied under the retained table borrow.
                live: unsafe {
                    depot::raw::Proof::new((
                        self,
                        Key::new(
                            depot::raw::Word::from_offset(key.index() as usize),
                            key.generation(),
                        ),
                    ))
                },
            });
        }
        Entry::Stale(self)
    }

    pub(in crate::conn) fn entry_at(&mut self, index: u32) -> Option<Occupied<'_, T, Tag, MAX>> {
        let epoch = self.core.generation(index)?;
        Some(Occupied {
            // SAFETY: generation returns only occupied slots in this retained table.
            live: unsafe {
                depot::raw::Proof::new((
                    self,
                    Key::new(depot::raw::Word::from_offset(index as usize), epoch),
                ))
            },
        })
    }

    #[must_use]
    pub(in crate::conn) fn initialized(&self) -> capacity::Count {
        self.core.initialized()
    }

    #[must_use]
    pub(in crate::conn) fn remaining(&self) -> capacity::Count {
        self.core.available()
    }

    #[must_use]
    pub(in crate::conn) fn bytes(&self) -> usize {
        self.core.capacity().get() * compact::raw::Core::<T, key::Generation<MAX>>::SLOT_SIZE
    }

    #[must_use]
    pub(in crate::conn) fn entries(&self) -> Entries<'_, T, Tag, MAX> {
        Entries {
            core: &self.core,
            tag: marker::PhantomData,
        }
    }
}

const _: () = {
    assert!(mem::size_of::<Table<(), ()>>() == 32);
    assert!(mem::size_of::<Growth<'static, ()>>() == 3 * mem::size_of::<usize>());
    assert!(mem::size_of::<Occupied<'static, ()>>() == 16);
    assert!(mem::size_of::<Option<Occupied<'static, ()>>>() == 16);
    assert!(mem::size_of::<Key<{ u32::MAX }>>() == 8);
    assert!(mem::size_of::<Option<Key<{ u32::MAX }>>>() == 8);
    assert!(mem::size_of::<Entries<'static, ()>>() == mem::size_of::<usize>());
};

/// Occupied values borrowed immutably from one demand table.
#[repr(transparent)]
pub(in crate::conn) struct Entries<'a, T, Tag = (), const MAX: u32 = { u32::MAX }> {
    core: &'a compact::raw::Core<T, key::Generation<MAX>>,
    tag: marker::PhantomData<*mut Tag>,
}

impl<T, Tag, const MAX: u32> Copy for Entries<'_, T, Tag, MAX> {}

impl<T, Tag, const MAX: u32> Clone for Entries<'_, T, Tag, MAX> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, T, Tag, const MAX: u32> Entries<'a, T, Tag, MAX> {
    /// Consumes an occupied-slot proof without repeating its lookup.
    pub(in crate::conn) fn project<P>(
        live: Selected<Self, links::Index, P>,
    ) -> (key::Handle<Tag, MAX>, &'a T) {
        let index = live.key().raw();
        // SAFETY: Entries retains this exact core and its owner lifetime;
        // projection preserves the occupied key and operation brand.
        let live = unsafe { live.map(|(entries, index)| (entries.core, index)) };
        let (epoch, value) = compact::raw::Core::project(live);
        (
            key::Handle::from_parts(key::Parts::new(index, epoch)),
            value,
        )
    }

    pub(in crate::conn) fn get(&self, key: key::Handle<Tag, MAX>) -> Option<&'a T> {
        self.core.get(key.index(), key.generation())
    }

    pub(in crate::conn) fn entry(&self, index: u32) -> Option<(key::Handle<Tag, MAX>, &'a T)> {
        self.core.entry_at(index).map(|(epoch, value)| {
            (
                key::Handle::from_parts(key::Parts::new(index, epoch)),
                value,
            )
        })
    }
}

/// Owner-bound backing growth awaiting an infallible commit.
#[must_use]
pub(in crate::conn) struct Growth<'a, T, Tag = (), const MAX: u32 = { u32::MAX }> {
    table: &'a mut Table<T, Tag, MAX>,
    spare: Option<
        array::Block<mem::MaybeUninit<compact::Slot<T, key::Generation<MAX>>>, capacity::Count>,
    >,
}

/// One generation-checked slot tied to its table's exclusive borrow.
#[must_use]
pub(in crate::conn) struct Occupied<'a, T, Tag = (), const MAX: u32 = { u32::MAX }, P = ()> {
    live: Selected<&'a mut Table<T, Tag, MAX>, Key<MAX>, P>,
}

impl<'a, T, Tag, const MAX: u32> Growth<'a, T, Tag, MAX> {
    pub(in crate::conn) fn commit(self) -> &'a mut Table<T, Tag, MAX> {
        let Self { table, spare } = self;
        if let Some(spare) = spare {
            // SAFETY: this growth owns the exact table borrow used to prove
            // that the replacement covers its unchanged initialized prefix.
            unsafe { table.core.replace(spare) };
        }
        table
    }
}

impl<'a, T, Tag, const MAX: u32> Occupied<'a, T, Tag, MAX> {
    pub(in crate::conn) fn into_table(self) -> &'a mut Table<T, Tag, MAX> {
        self.live.into_inner().0
    }
}

impl<'a, T, Tag, const MAX: u32, P> Occupied<'a, T, Tag, MAX, P> {
    /// Retains an initialized slot's owner, operation plane, and caller context.
    pub(in crate::conn) fn project<C>(
        live: Selected<(&'a mut Table<T, Tag, MAX>, C), links::Index, P>,
    ) -> (Self, C) {
        let ((table, context), index) = live.into_inner();
        let read: Selected<_, _, P> = unsafe { depot::raw::Proof::new((&table.core, index)) };
        let epoch = compact::raw::Core::project(read).0;
        (
            Self {
                // SAFETY: splitting context preserves this exact initialized slot and P.
                live: unsafe { depot::raw::Proof::new((table, Key::new(index, epoch))) },
            },
            context,
        )
    }

    #[must_use]
    pub(in crate::conn) fn key(&self) -> key::Handle<Tag, MAX> {
        let Key { index, epoch } = *self.live.key();
        key::Handle::from_parts(key::Parts::new(index.get(), epoch))
    }

    #[must_use]
    pub(in crate::conn) fn get(&self) -> &T {
        let live = unsafe { self.live.as_ref().map(|(table, key)| (&table.core, key)) };
        compact::raw::Core::project(live).1
    }

    pub(in crate::conn) fn get_mut(&mut self) -> &mut T {
        // SAFETY: the value borrow cannot remove or replace its occupied slot.
        let live = unsafe {
            self.live
                .as_mut()
                .map(|(table, key)| ((&mut table.core, ()), key))
        };
        compact::raw::Core::project_mut(live).0.into_mut()
    }

    pub(in crate::conn) fn remove(self) -> T {
        let live = unsafe { self.live.map(|(table, key)| ((&mut table.core, ()), key)) };
        compact::raw::Core::project_mut(live).0.remove()
    }

    /// Removes this slot and returns its original exclusive table loan.
    pub(in crate::conn) fn take(self) -> (&'a mut Table<T, Tag, MAX>, T) {
        let (table, key) = self.live.into_inner();
        // SAFETY: the consumed native guard owns this exact initialized slot.
        // The core reborrow finishes removal before the original table loan returns.
        let live: Selected<_, _, P> =
            unsafe { depot::raw::Proof::new(((&mut table.core, ()), key)) };
        let value = compact::raw::Core::project_mut(live).0.remove();
        (table, value)
    }

    #[must_use]
    pub(in crate::conn) fn as_table(&self) -> &Table<T, Tag, MAX> {
        self.live.source()
    }
}
