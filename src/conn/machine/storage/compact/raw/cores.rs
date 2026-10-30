use o3::alloc;
use o3::depot;
use o3::depot::index::Initialized;
use std::{marker, mem, num::NonZero, ops};

use crate::conn::machine::storage::compact;
use o3::alloc::array;
use o3::depot::arena::slab::external;
use o3::depot::{capacity, queue::links};

#[repr(transparent)]
pub(in crate::conn) struct Core<T, G: external::Generation> {
    pub(in crate::conn::machine::storage::compact) storage: compact::raw::Storage<T, G>,
}

pub(in crate::conn) struct Occupied<'a, T, G: external::Generation, P = ()> {
    core: &'a mut Core<T, G>,
    index: links::Index,
    plane: marker::PhantomData<fn(P) -> P>,
}

impl<T, G> Core<T, G>
where
    G: external::Generation,
{
    pub(in crate::conn) const SLOT_SIZE: usize = mem::size_of::<compact::Slot<T, G>>();

    pub(in crate::conn) fn empty(room: capacity::Count) -> Self {
        Self {
            storage: compact::raw::Storage::empty(room),
        }
    }

    pub(in crate::conn) fn try_new(cap: capacity::Count) -> Result<Self, alloc::Error> {
        Ok(Self {
            storage: compact::raw::Storage::try_new(cap)?,
        })
    }

    pub(in crate::conn) fn probe(&self) -> Option<compact::raw::Vacancy> {
        if let Some(free) = self.storage.state().free().peek() {
            return Some(compact::raw::Vacancy(compact::raw::Kind::Recycled(free)));
        }
        let index = self.storage.state().initialized();
        if index == self.storage.capacity() {
            return None;
        }
        Some(compact::raw::Vacancy(compact::raw::Kind::Virgin(
            NonZero::<u32>::MIN.saturating_add(index.raw()),
        )))
    }

    pub(in crate::conn::machine::storage::compact::raw) fn commit(
        &mut self,
        slot: compact::raw::Vacancy,
        value: T,
    ) -> Occupied<'_, T, G> {
        // SAFETY: Kind is held with the unchanged exclusive core by Lease or
        // Reserve; both variants prove one available slot in this exact owner.
        let room = unsafe { NonZero::new_unchecked(self.available().raw()) };
        let index =
            match slot.0 {
                compact::raw::Kind::Recycled(free) => {
                    let index = self.storage.take_free(free);
                    let slot = unsafe { self.storage.slot_mut(index) };
                    slot.value = mem::MaybeUninit::new(value);
                    index
                }
                compact::raw::Kind::Virgin(next) => {
                    let index = links::Index::from(next);
                    // SAFETY: the retained virgin reservation proves this next slot
                    // lies in the unchanged allocation and has never held a value.
                    unsafe {
                        self.storage.slots.as_mut_ptr().add(index.get()).write(
                            mem::MaybeUninit::new(compact::Slot {
                                generation: G::INITIAL,
                                next: compact::raw::NONE,
                                value: mem::MaybeUninit::new(value),
                            }),
                        );
                    }
                    self.storage
                        .state_mut()
                        .advance(capacity::Count::new(next.get()));
                    index
                }
            };
        self.storage.state_mut().available = capacity::Count::new(room.get() - 1);
        Occupied {
            core: self,
            index,
            plane: marker::PhantomData,
        }
    }

    pub(in crate::conn) fn project<K: Into<links::Index>, P>(
        live: depot::raw::Proof<(&Self, K), Initialized<P>>,
    ) -> (G, &T) {
        let (core, key) = live.into_inner();
        let slot = unsafe { core.storage.slot(key.into()) };
        (slot.generation, unsafe { slot.value.assume_init_ref() })
    }

    pub(in crate::conn) fn project_mut<'a, C, K: Into<links::Index>, P>(
        live: depot::raw::Proof<((&'a mut Self, C), K), Initialized<P>>,
    ) -> (Occupied<'a, T, G, P>, C) {
        let ((core, context), key) = live.into_inner();
        (
            Occupied {
                core,
                index: key.into(),
                plane: marker::PhantomData,
            },
            context,
        )
    }

    /// # Safety
    /// `spare` must cover this core's complete initialized prefix.
    pub(in crate::conn::machine::storage) unsafe fn replace(
        &mut self,
        spare: array::Block<mem::MaybeUninit<compact::Slot<T, G>>, capacity::Count>,
    ) {
        let len = self.initialized().get();
        // SAFETY: replace admits the spare for this exclusive core's initialized prefix.
        unsafe { alloc::raw::relocate(&mut self.storage.slots, spare, [(0, 0, len)]) };
    }

    pub(in crate::conn) fn initialized(&self) -> capacity::Count {
        self.storage.state().initialized()
    }

    pub(in crate::conn) fn available(&self) -> capacity::Count {
        self.storage.state().available()
    }
}

impl<'a, T, G> Occupied<'a, T, G>
where
    G: external::Generation,
{
    pub(in crate::conn) fn at(core: &'a mut Core<T, G>, index: u32) -> Option<Self> {
        if index >= core.storage.state().initialized().raw() {
            return None;
        }
        let index = unsafe { links::Index::from(NonZero::new_unchecked(index + 1)) };
        let slot = unsafe { core.storage.slot(index) };
        if slot.next != compact::raw::NONE {
            return None;
        }
        Some(Self {
            core,
            index,
            plane: marker::PhantomData,
        })
    }
}

impl<'a, T, G, P> Occupied<'a, T, G, P>
where
    G: external::Generation,
{
    pub(in crate::conn::machine::storage::compact) fn project<Q>(
        live: depot::raw::Proof<(&Self, links::Index), Initialized<Q>>,
    ) -> (G, &T) {
        let live = unsafe { live.map(|(entry, index)| (&*entry.core, index)) };
        Core::project(live)
    }

    pub(in crate::conn::machine::storage::compact) fn update<Q>(
        live: depot::raw::Proof<(&mut Self, links::Index), Initialized<Q>>,
    ) -> &mut T {
        let (entry, index) = live.into_inner();
        unsafe { entry.core.storage.slot_mut(index).value.assume_init_mut() }
    }

    pub(in crate::conn) fn index(&self) -> links::Index {
        self.index
    }

    pub(in crate::conn) fn generation(&self) -> G {
        unsafe { self.core.storage.slot(self.index) }.generation
    }

    pub(in crate::conn) fn value(&self) -> &T {
        unsafe { self.core.storage.slot(self.index).value.assume_init_ref() }
    }

    pub(in crate::conn) fn value_mut(&mut self) -> &mut T {
        unsafe {
            self.core
                .storage
                .slot_mut(self.index)
                .value
                .assume_init_mut()
        }
    }

    pub(in crate::conn) fn into_mut(self) -> &'a mut T {
        unsafe {
            self.core
                .storage
                .slot_mut(self.index)
                .value
                .assume_init_mut()
        }
    }

    fn retire(self, next: Option<G>) {
        let slot = unsafe { self.core.storage.slot_mut(self.index) };
        match next {
            Some(epoch) => {
                slot.generation = epoch;
                let state = self.core.storage.state_mut();
                state.available = capacity::Count::new(state.available.raw() + 1);
                let next = state.free.push(self.index);
                unsafe { self.core.storage.slot_mut(self.index) }.next = next.raw();
            }
            None => slot.next = self.index.raw(),
        }
    }

    pub(in crate::conn) fn remove(self) -> T {
        let slot = unsafe { self.core.storage.slot_mut(self.index) };
        let next = slot.generation.next();
        let value = unsafe { slot.value.assume_init_read() };
        self.retire(next);
        value
    }

    pub(in crate::conn) fn discard(self) {
        let slot = unsafe { self.core.storage.slot_mut(self.index) };
        let next = slot.generation.next();
        unsafe { slot.value.assume_init_drop() };
        self.retire(next);
    }
}

impl<T, G> Core<T, G>
where
    G: external::Generation,
{
    /// # Safety
    /// The consuming owner proves one resident vacancy in this exact core.
    pub(in crate::conn::machine::storage) unsafe fn reserve(
        &mut self,
    ) -> compact::raw::Lease<'_, T, G> {
        let kind = match self.storage.state().free().peek() {
            Some(free) => compact::raw::Kind::Recycled(free),
            None => compact::raw::Kind::Virgin(
                NonZero::<u32>::MIN.saturating_add(self.storage.state().initialized().raw()),
            ),
        };
        unsafe { compact::raw::Lease::new(self, compact::raw::Vacancy(kind)) }
    }
}

impl<T, G> ops::Deref for Core<T, G>
where
    G: external::Generation,
{
    type Target = compact::raw::Storage<T, G>;

    fn deref(&self) -> &Self::Target {
        &self.storage
    }
}

impl<T, G> ops::DerefMut for Core<T, G>
where
    G: external::Generation,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.storage
    }
}
