use crate::conn::Selected;
use o3::alloc;
use std::marker;

use crate::conn::machine::storage::compact;
use o3::depot::arena::slab::external;
use o3::depot::{arena::slab, capacity, queue::links};

/// Fixed-capacity generational storage in one exact allocation.
#[repr(transparent)]
pub(in crate::conn) struct Table<T, G: external::Generation, Tag = ()> {
    pub(in crate::conn) core: compact::raw::Core<T, G>,
    tag: marker::PhantomData<*mut Tag>,
}

/// Exclusive proof that one direct-address slot is occupied.
#[must_use]
#[repr(transparent)]
pub(in crate::conn) struct Occupied<'a, T, G: external::Generation, Tag = (), P = ()> {
    entry: compact::raw::Occupied<'a, T, G, P>,
    tag: marker::PhantomData<fn() -> Tag>,
}

impl<T, G: external::Generation, Tag> Table<T, G, Tag> {
    /// Consumes initialization into the original occupied table and caller context.
    pub(in crate::conn) fn project_mut<'a, C, P>(
        live: Selected<(&'a mut Self, C), links::Index, P>,
    ) -> (Occupied<'a, T, G, Tag, P>, C) {
        let live =
            unsafe { live.map(|((table, context), index)| ((&mut table.core, context), index)) };
        let (entry, context) = compact::raw::Core::project_mut(live);
        (
            Occupied {
                entry,
                tag: marker::PhantomData,
            },
            context,
        )
    }

    /// Projects an initialized slot while retaining the source owner's lifetime.
    pub(in crate::conn) fn project<P>(
        live: Selected<&Self, links::Index, P>,
    ) -> (external::Key<G, Tag>, &T) {
        let index = live.key().raw();
        let live = unsafe { live.map(|(table, index)| (&table.core, index)) };
        let (epoch, value) = compact::raw::Core::project(live);
        (external::Key::new(index, epoch), value)
    }

    /// Removes the proven slot and retains its disjoint operation context.
    pub(in crate::conn) fn take<C, P>(live: Selected<(&mut Self, C), links::Index, P>) -> (T, C) {
        let live =
            unsafe { live.map(|((table, context), index)| ((&mut table.core, context), index)) };
        let (entry, context) = compact::raw::Core::project_mut(live);
        (entry.remove(), context)
    }

    pub(in crate::conn) fn try_new(capacity: capacity::Count) -> Result<Self, alloc::Error> {
        Ok(Self {
            core: compact::raw::Core::try_new(capacity)?,
            tag: marker::PhantomData,
        })
    }

    pub(in crate::conn) fn entry_mut(&mut self, index: u32) -> Option<Occupied<'_, T, G, Tag>> {
        let entry = compact::raw::Occupied::at(&mut self.core, index)?;
        Some(Occupied {
            entry,
            tag: marker::PhantomData,
        })
    }

    #[must_use]
    pub(in crate::conn) fn initialized(&self) -> capacity::Count {
        self.core.initialized()
    }
}

impl<'a, T, G: external::Generation, Tag, P> Occupied<'a, T, G, Tag, P> {
    /// Projects a live neighbor through the original exclusive slot owner.
    pub(in crate::conn) fn project<Q>(
        live: Selected<&Self, links::Index, Q>,
    ) -> (external::Key<G, Tag>, &T) {
        let index = live.key().raw();
        let live = unsafe { live.map(|(occupied, index)| (&occupied.entry, index)) };
        let (epoch, value) = compact::raw::Occupied::project(live);
        (external::Key::new(index, epoch), value)
    }

    /// Updates a proven neighbor through the original exclusive owner.
    pub(in crate::conn) fn update<Q>(live: Selected<&mut Self, links::Index, Q>) -> &mut T {
        let live = unsafe { live.map(|(occupied, index)| (&mut occupied.entry, index)) };
        compact::raw::Occupied::update(live)
    }

    pub(in crate::conn) fn key(&self) -> external::Key<G, Tag> {
        external::Key::new(self.entry.index().raw(), self.entry.generation())
    }

    pub(in crate::conn) fn get(&self) -> &T {
        self.entry.value()
    }

    pub(in crate::conn) fn get_mut(&mut self) -> &mut T {
        self.entry.value_mut()
    }

    pub(in crate::conn) fn discard(self) {
        self.entry.discard();
    }
}

const _: () = {
    assert!(std::mem::size_of::<Table<(), slab::key::Generation>>() == 24);
    assert!(std::mem::size_of::<Occupied<'static, (), slab::key::Generation>>() == 16);
    assert!(std::mem::size_of::<Option<Occupied<'static, (), slab::key::Generation>>>() == 16);
};
