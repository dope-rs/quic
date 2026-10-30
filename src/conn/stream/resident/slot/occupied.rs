use crate::conn::Selected;
use o3::depot;
use o3::depot::queue::{indexed::keyed, links};

use crate::{
    conn::stream::resident::slot::{self, Index, Vacancy, plane},
    wire::stream,
};

#[must_use]
pub(in crate::conn) struct Occupied<'a, Side, Value, Auxiliary> {
    table: &'a mut slot::Table<Side, Value, Auxiliary>,
    pub(in crate::conn::stream::resident::slot) node: Index,
}

pub(in crate::conn) struct Activity<'b, 'a, S, V, A> {
    entry: &'b mut Occupied<'a, S, V, A>,
    fifo: &'b mut keyed::Fifo<slot::Handle<S>>,
}

#[repr(transparent)]
pub(in crate::conn::stream::resident::slot) struct Projected<'a, S, V, A>(
    pub(super) Selected<&'a slot::Table<S, V, A>, links::Index, ()>,
);

// SAFETY: the retained live table identifies this exact initialized slot and link.
unsafe impl<'a, S, V, A> depot::raw::KeyBorrow<'a> for Projected<'a, S, V, A> {
    type Key = slot::Handle<S>;

    fn parts(self) -> (Self::Key, &'a keyed::Link<Self::Key>) {
        let (table, index) = self.0.into_inner();
        let node = unsafe { table.nodes.get_unchecked(index.get()) };
        (
            slot::Handle::new(index.raw(), node.generation.get()),
            &node.link,
        )
    }
}

// SAFETY: the native occupied guard retains this exact slot and generation for the borrow.
unsafe impl<'a, S, V, A> depot::raw::KeyBorrow<'a> for &'a Occupied<'_, S, V, A> {
    type Key = slot::Handle<S>;

    fn parts(self) -> (Self::Key, &'a keyed::Link<Self::Key>) {
        let node = unsafe { self.table.nodes.get_unchecked(self.node.get()) };
        (
            slot::Handle::new(self.node.raw(), node.generation.get()),
            &node.link,
        )
    }
}

impl<'b, 'a, S, V, A> Activity<'b, 'a, S, V, A> {
    pub(in crate::conn::stream::resident::slot) fn new(
        entry: &'b mut Occupied<'a, S, V, A>,
        fifo: &'b mut keyed::Fifo<slot::Handle<S>>,
    ) -> Self {
        Self { entry, fifo }
    }

    pub(in crate::conn::stream::resident::slot) fn front(self) -> Option<slot::Handle<S>> {
        keyed::Fifo::first(&self).map(Self::handle)
    }

    pub(in crate::conn::stream::resident::slot) fn handle(
        live: Selected<&Self, links::Index, ()>,
    ) -> slot::Handle<S> {
        let index = live.key();
        let node = unsafe { live.source().entry.table.nodes.get_unchecked(index.get()) };
        slot::Handle::new(index.raw(), node.generation.get())
    }
}

// SAFETY: the original occupied guard and its root's sole active FIFO remain
// exclusively borrowed together; shared projections cannot change either.
unsafe impl<S, V, A> depot::raw::KeyOwner for Activity<'_, '_, S, V, A> {
    type Key = slot::Handle<S>;
    type Fifo = keyed::Fifo<Self::Key>;

    fn parts(&self) -> (Self::Key, &keyed::Link<Self::Key>) {
        depot::raw::KeyBorrow::parts(&*self.entry)
    }

    fn fifo(&self) -> &keyed::Fifo<Self::Key> {
        self.fifo
    }

    fn entry<'c>(live: Selected<&'c Self, links::Index, ()>) -> keyed::Entry<'c, Self::Key> {
        let live = unsafe { live.map(|(activity, index)| (&*activity.entry.table, index)) };
        keyed::Entry::from_source(Projected(live))
    }
}

// SAFETY: the original occupied guard retains this FIFO's storage and excludes mutation.
unsafe impl<S, V, A> depot::raw::KeySource for &Activity<'_, '_, S, V, A> {
    type Key = slot::Handle<S>;

    fn fifo(&self) -> &keyed::Fifo<Self::Key> {
        self.fifo
    }
}

// SAFETY: the same exclusive slot and FIFO loans remain owned by the output.
unsafe impl<S, V, A> depot::raw::KeyFinish<false> for Activity<'_, '_, S, V, A> {
    type Output = Self;

    unsafe fn finish(self) -> Self {
        self
    }
}

impl<'a, Side, Value, Auxiliary> Occupied<'a, Side, Value, Auxiliary> {
    pub(in crate::conn::stream::resident::slot) fn new(
        table: &'a mut slot::Table<Side, Value, Auxiliary>,
        node: Index,
    ) -> Self {
        Self { table, node }
    }

    pub(in crate::conn) fn id(&self) -> stream::Id {
        unsafe { self.table.nodes.get_unchecked(self.node.get()) }.id
    }

    pub(in crate::conn) fn get_mut(&mut self) -> &mut Value {
        &mut unsafe { self.table.nodes.get_unchecked_mut(self.node.get()) }.value
    }

    pub(in crate::conn) fn get(&self) -> &Value {
        &unsafe { self.table.nodes.get_unchecked(self.node.get()) }.value
    }

    pub(in crate::conn::stream::resident::slot) fn handle(&self) -> slot::Handle<Side> {
        let node = unsafe { self.table.nodes.get_unchecked(self.node.get()) };
        slot::Handle::new(self.node.raw(), node.generation.get())
    }

    pub(in crate::conn::stream::resident::slot) fn aux_mut(&mut self) -> &mut Auxiliary {
        &mut unsafe { self.table.nodes.get_unchecked_mut(self.node.get()) }.auxiliary
    }

    pub(in crate::conn::stream::resident::slot) fn retire<R, P>(
        mut self,
        plane: &mut plane::Plane<Side, P>,
        recycle: R,
    ) where
        Value: slot::Reusable,
        Auxiliary: Default,
        R: slot::Recycle<Value = Value>,
        P: plane::Policy<Side>,
    {
        plane.set_active(&mut self, false);
        let entry = unsafe { self.table.nodes.get_unchecked_mut(self.node.get()) };
        recycle.recycle(&mut entry.value);
        entry.auxiliary = Auxiliary::default();
        if let Some(next) = entry.generation.next() {
            entry.generation = next;
            entry.vacancy = Vacancy::free(self.table.free);
            self.table.free = Some(slot::Free(self.node));
        } else {
            entry.vacancy = Vacancy::free(None);
            self.table.capacity -= 1;
        }
        self.table.len -= 1;
    }
}
