use std::{marker, mem, num::NonZero};

use o3::{
    alloc::{self, VecExt as _},
    base::num::Generation,
    depot::queue::{indexed::keyed, links},
};
use slot::{
    Capacity, Free, Handle, Index, MAX_GENERATION, Node, Occupied, Resolved, Reusable, Vacancy,
};

use crate::{conn::stream::resident::slot, wire::stream};

pub(in crate::conn) struct Table<Side, Value, Auxiliary> {
    pub(in crate::conn::stream::resident::slot) nodes: Vec<Node<Side, Value, Auxiliary>>,
    pub(in crate::conn::stream::resident::slot) free: Option<Free>,
    pub(in crate::conn::stream::resident::slot) capacity: usize,
    pub(in crate::conn::stream::resident::slot) len: usize,
    side: marker::PhantomData<fn() -> Side>,
}

impl<Side, Value: Reusable, Auxiliary: Default> Table<Side, Value, Auxiliary> {
    pub(in crate::conn) fn try_new(capacity: Capacity) -> Result<Self, alloc::Error> {
        Ok(Self {
            nodes: Vec::try_new(capacity.0 as usize)?,
            free: None,
            capacity: capacity.0 as usize,
            len: 0,
            side: marker::PhantomData,
        })
    }

    pub(in crate::conn) fn resolve(
        &self,
        handle: Handle<Side>,
    ) -> Option<Resolved<'_, Side, Value, Auxiliary>> {
        let node = self.nodes.get(handle.index() as usize)?;
        (node.generation.get() == handle.generation() && !node.vacancy.is_free()).then_some(
            Resolved {
                id: node.id,
                value: &node.value,
                auxiliary: &node.auxiliary,
                side: marker::PhantomData,
            },
        )
    }

    pub(in crate::conn) fn bind(
        &mut self,
        handle: Handle<Side>,
    ) -> Option<Occupied<'_, Side, Value, Auxiliary>> {
        let index = Index::new(handle.index(), self.nodes.len())?;
        let node = unsafe { self.nodes.get_unchecked(index.get()) };
        if node.generation.get() != handle.generation() || node.vacancy.is_free() {
            return None;
        }
        Some(Occupied::new(self, index))
    }

    pub(in crate::conn::stream::resident::slot) fn bind_at(
        &mut self,
        raw: u32,
    ) -> Option<Occupied<'_, Side, Value, Auxiliary>> {
        let index = Index::new(raw, self.nodes.len())?;
        let node = unsafe { self.nodes.get_unchecked(index.get()) };
        if node.vacancy.is_free() {
            return None;
        }
        Some(Occupied::new(self, index))
    }

    pub(in crate::conn::stream::resident::slot) fn insert(
        &mut self,
        id: stream::Id,
        init: Value::Init,
    ) -> Option<Occupied<'_, Side, Value, Auxiliary>> {
        if self.len == self.capacity {
            return None;
        }
        let index = if let Some(Free(index)) = self.free {
            let node = unsafe { self.nodes.get_unchecked_mut(index.get()) };
            self.free = node.vacancy.next();
            node.vacancy = Vacancy::OCCUPIED;
            node.id = id;
            node.value.reuse(init);
            index
        } else {
            let raw = self.nodes.len() as u32;
            let index = Index(NonZero::<u32>::MIN.saturating_add(raw));
            // SAFETY: initially C slots are reserved. With E exhausted slots,
            // nodes.len() = live + free + E and self.capacity = C - E.
            // This arm has no free slots and passed live < self.capacity, so
            // nodes.len() < C <= nodes.capacity(). The exclusive table never shrinks.
            unsafe { alloc::raw::VecExt::vacancy(&mut self.nodes) }.insert(Node {
                id,
                generation: Generation::<MAX_GENERATION>::INITIAL,
                value: Value::new(init),
                link: keyed::Link::from(links::Index::from(index.0)),
                vacancy: Vacancy::OCCUPIED,
                auxiliary: Auxiliary::default(),
            });
            index
        };
        self.len += 1;
        Some(Occupied::new(self, index))
    }
}

const _: () = {
    assert!(mem::size_of::<Table<(), (), ()>>() == 6 * mem::size_of::<usize>());
    assert!(mem::align_of::<Table<(), (), ()>>() == mem::align_of::<usize>());
};
