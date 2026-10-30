use crate::{conn::stream::resident::slot, wire::stream};
use o3::depot::index::Initialized;
use o3::depot::queue::{indexed::keyed, links};
use o3::{alloc, depot};
use slot::plane;
use std::{marker, mem, num::NonZero};

pub(in crate::conn) mod scope;

pub(in crate::conn) struct Active<'a, S, V: slot::Reusable, A: Default, P: plane::Policy<S>> {
    entry: slot::Occupied<'a, S, V, A>,
    plane: &'a mut plane::Plane<S, P>,
}

struct Iter<'a, S, V: slot::Reusable, A: Default, P: plane::Policy<S>>(
    keyed::Iter<&'a Pool<S, V, A, P>>,
);

impl<S, V: slot::Reusable, A: Default, P: plane::Policy<S>> Active<'_, S, V, A, P> {
    pub(in crate::conn) fn id(&self) -> stream::Id {
        self.entry.id()
    }

    pub(in crate::conn) fn handle(&self) -> slot::Handle<S> {
        self.entry.handle()
    }

    pub(in crate::conn) fn get_mut(&mut self) -> &mut V {
        self.entry.get_mut()
    }

    pub(in crate::conn) fn deactivate(mut self) {
        // SAFETY: Active owns this exact member with both original root loans.
        let member = unsafe {
            keyed::Slot::from_source(depot::raw::Proof::new(slot::Activity::new(
                &mut self.entry,
                &mut self.plane.core.queue,
            )))
        };
        self.plane
            .policy
            .remove(member, &mut self.plane.core.length);
    }
}

impl<S, V: slot::Reusable, A: Default> Active<'_, S, V, A, plane::RoundRobin<S>> {
    pub(in crate::conn) fn advance(&mut self) {
        let next = {
            // SAFETY: advancing borrows this still-owned exact member.
            let member = unsafe {
                keyed::Slot::from_source(depot::raw::Proof::new(slot::Activity::new(
                    &mut self.entry,
                    &mut self.plane.core.queue,
                )))
            };
            member.successor().map(slot::Activity::handle)
        };
        self.plane.policy.cursor = next
            .or_else(|| slot::Activity::new(&mut self.entry, &mut self.plane.core.queue).front());
    }
}

impl<S, V: slot::Reusable, A: Default> Active<'_, S, V, A, plane::HeadOnly> {
    pub(in crate::conn) fn move_to_back(mut self) {
        // SAFETY: this guard retains the exact active member and its original
        // queue; moving it preserves membership, initialization and length.
        let member = unsafe {
            keyed::Slot::from_source(depot::raw::Proof::new(slot::Activity::new(
                &mut self.entry,
                &mut self.plane.core.queue,
            )))
        };
        member.move_to_back();
    }
}

impl<S, V: slot::Reusable, A: Default> Pool<S, V, A, plane::RoundRobin<S>> {
    pub(in crate::conn) fn active(&mut self) -> Option<Active<'_, S, V, A, plane::RoundRobin<S>>> {
        let Some(key) = self.plane.policy.cursor else {
            return self.front();
        };
        // SAFETY: the root's private cursor is updated only from a retained
        // member or neighbor, and removal repairs it before releasing the slot.
        let index = slot::Index(unsafe { NonZero::new_unchecked(key.index().wrapping_add(1)) });
        Some(Active {
            entry: slot::Occupied::new(&mut self.storage, index),
            plane: &mut self.plane,
        })
    }
}

pub(in crate::conn) struct Pool<
    Side,
    Value: slot::Reusable,
    Auxiliary: Default,
    Policy: plane::Policy<Side>,
> {
    pub(in crate::conn::stream::resident::slot::store) storage: slot::Table<Side, Value, Auxiliary>,
    pub(in crate::conn::stream::resident::slot::store) plane: plane::Plane<Side, Policy>,
}

pub(in crate::conn) struct Occupied<
    'a,
    Side,
    Value: slot::Reusable,
    Auxiliary: Default,
    Policy: plane::Policy<Side>,
    O = (),
> {
    entry: slot::Occupied<'a, Side, Value, Auxiliary>,
    plane: &'a mut plane::Plane<Side, Policy>,
    operation: marker::PhantomData<fn(O) -> O>,
}

pub(in crate::conn) struct Vacant<
    'a,
    Side,
    Value: slot::Reusable,
    Auxiliary: Default,
    Policy: plane::Policy<Side>,
> {
    owner: &'a mut Pool<Side, Value, Auxiliary, Policy>,
    id: stream::Id,
}

impl<Side, Value, Auxiliary, Policy> Pool<Side, Value, Auxiliary, Policy>
where
    Value: slot::Reusable,
    Auxiliary: Default,
    Policy: plane::Policy<Side>,
{
    pub(in crate::conn) fn try_new(capacity: slot::Capacity) -> Result<Self, alloc::Error> {
        Ok(Self {
            storage: slot::Table::try_new(capacity)?,
            plane: plane::Plane::new(),
        })
    }

    pub(in crate::conn) fn scope<R>(
        &mut self,
        run: impl for<'id> FnOnce(scope::Pool<'_, 'id, Side, Value, Auxiliary, Policy>) -> R,
    ) -> R {
        run(scope::Pool::new(self))
    }

    pub(in crate::conn) fn resolve(
        &self,
        handle: slot::Handle<Side>,
    ) -> Option<slot::Resolved<'_, Side, Value, Auxiliary>> {
        self.storage.resolve(handle)
    }

    pub(in crate::conn) fn current(
        &self,
        index: u32,
    ) -> Option<slot::Resolved<'_, Side, Value, Auxiliary>> {
        let node = self.storage.nodes.get(index as usize)?;
        if node.vacancy.is_free() {
            return None;
        }
        Some(slot::Resolved {
            id: node.id,
            value: &node.value,
            auxiliary: &node.auxiliary,
            side: marker::PhantomData,
        })
    }

    pub(in crate::conn) fn vacant(
        &mut self,
        id: slot::Id<Side>,
    ) -> Vacant<'_, Side, Value, Auxiliary, Policy> {
        Vacant {
            owner: self,
            id: id.id(),
        }
    }

    pub(in crate::conn) fn occupied(
        &mut self,
        handle: slot::Handle<Side>,
    ) -> Option<Occupied<'_, Side, Value, Auxiliary, Policy>> {
        Some(Occupied {
            entry: self.storage.bind(handle)?,
            plane: &mut self.plane,
            operation: marker::PhantomData,
        })
    }

    pub(in crate::conn) fn bind_at(
        &mut self,
        raw: u32,
    ) -> Option<Occupied<'_, Side, Value, Auxiliary, Policy>> {
        Some(Occupied {
            entry: self.storage.bind_at(raw)?,
            plane: &mut self.plane,
            operation: marker::PhantomData,
        })
    }

    pub(in crate::conn) fn available(&self) -> usize {
        self.storage.capacity.saturating_sub(self.storage.len)
    }

    /// The table's initialized prefix stays within its admitted u32 capacity.
    pub(in crate::conn) fn slot_count(&self) -> u32 {
        self.storage.nodes.len() as u32
    }

    pub(in crate::conn) fn front(&mut self) -> Option<Active<'_, Side, Value, Auxiliary, Policy>> {
        Some(keyed::Fifo::first(self)?.into())
    }

    pub(in crate::conn) fn iter<'a>(
        &'a self,
    ) -> impl Iterator<Item = slot::Resolved<'a, Side, Value, Auxiliary>>
    + use<'a, Side, Value, Auxiliary, Policy> {
        const {
            assert!(
                mem::size_of::<Iter<'_, Side, Value, Auxiliary, Policy>>()
                    == 2 * mem::size_of::<usize>()
            );
        }
        Iter(keyed::Iter::new(self))
    }

    pub(in crate::conn) fn length(&self) -> usize {
        self.plane.length()
    }
}

impl<'a, Side, Value, Auxiliary, Policy, O> Occupied<'a, Side, Value, Auxiliary, Policy, O>
where
    Value: slot::Reusable,
    Auxiliary: Default,
    Policy: plane::Policy<Side>,
{
    pub(in crate::conn) fn id(&self) -> stream::Id {
        self.entry.id()
    }

    pub(in crate::conn) fn handle(&self) -> slot::Handle<Side> {
        self.entry.handle()
    }

    pub(in crate::conn) fn get_mut(&mut self) -> &mut Value {
        self.entry.get_mut()
    }

    pub(in crate::conn) fn get(&self) -> &Value {
        self.entry.get()
    }

    pub(in crate::conn) fn position_mut(&mut self) -> &mut Auxiliary {
        self.entry.aux_mut()
    }

    pub(in crate::conn) fn set_active(&mut self, active: bool) {
        self.plane.set_active(&mut self.entry, active);
    }

    pub(in crate::conn) fn retire<R>(self, recycle: R)
    where
        R: slot::Recycle<Value = Value>,
    {
        self.entry.retire(self.plane, recycle);
    }
}

impl<'a, Side, Value, Auxiliary, Policy> Vacant<'a, Side, Value, Auxiliary, Policy>
where
    Value: slot::Reusable,
    Auxiliary: Default,
    Policy: plane::Policy<Side>,
{
    pub(in crate::conn) const fn id(&self) -> stream::Id {
        self.id
    }

    pub(in crate::conn) fn insert(
        self,
        init: Value::Init,
    ) -> Option<Occupied<'a, Side, Value, Auxiliary, Policy>> {
        Some(Occupied {
            entry: self.owner.storage.insert(self.id, init)?,
            plane: &mut self.owner.plane,
            operation: marker::PhantomData,
        })
    }
}

// SAFETY: the root owns both storage and its sole active plane; its shared
// borrow prevents insertion, retirement, and changes to every traversed link.
unsafe impl<S, V: slot::Reusable, A: Default, P: plane::Policy<S>> depot::raw::KeySource
    for &Pool<S, V, A, P>
{
    type Key = slot::Handle<S>;

    fn fifo(&self) -> &keyed::Fifo<Self::Key> {
        &self.plane.core.queue
    }
}

// SAFETY: the same permanently paired root is retained exclusively.
unsafe impl<S, V: slot::Reusable, A: Default, P: plane::Policy<S>> depot::raw::KeySource
    for &mut Pool<S, V, A, P>
{
    type Key = slot::Handle<S>;

    fn fifo(&self) -> &keyed::Fifo<Self::Key> {
        &self.plane.core.queue
    }
}

// SAFETY: this source cannot mutate or recycle any of its live projected nodes.
unsafe impl<S, V: slot::Reusable, A: Default, P: plane::Policy<S>> depot::raw::KeyRead
    for &Pool<S, V, A, P>
{
    fn entry<'a>(
        live: depot::raw::Proof<(&'a Self, links::Index), Initialized<()>>,
    ) -> keyed::Entry<'a, Self::Key> {
        let live = unsafe { live.map(|(pool, index)| (&pool.storage, index)) };
        keyed::Entry::from_source(slot::Projected(live))
    }
}

// SAFETY: the output retains the original root lifetime through real field
// references, and preserves the slot's side and initialized payload.
unsafe impl<'a, S, V: slot::Reusable, A: Default, P: plane::Policy<S>>
    depot::raw::Project<links::Index> for &'a Pool<S, V, A, P>
{
    type Output = slot::Resolved<'a, S, V, A>;

    unsafe fn project(self, index: links::Index) -> Self::Output {
        let node = unsafe { self.storage.nodes.get_unchecked(index.get()) };
        slot::Resolved {
            id: node.id,
            value: &node.value,
            auxiliary: &node.auxiliary,
            side: marker::PhantomData,
        }
    }
}

// SAFETY: Active retains the same root's disjoint storage and plane loans;
// its selected member cannot be recycled or substituted while the guard lives.
unsafe impl<'a, S, V: slot::Reusable, A: Default, P: plane::Policy<S>>
    depot::raw::Project<links::Index> for &'a mut Pool<S, V, A, P>
{
    type Output = Active<'a, S, V, A, P>;

    unsafe fn project(self, index: links::Index) -> Self::Output {
        let index = slot::Index(unsafe { NonZero::new_unchecked(index.raw().wrapping_add(1)) });
        const {
            assert!(mem::size_of::<Active<'_, S, V, A, P>>() == 3 * mem::size_of::<usize>());
        }
        Active {
            entry: slot::Occupied::new(&mut self.storage, index),
            plane: &mut self.plane,
        }
    }
}

// SAFETY: the native source retains this exact live generation and operation.
// Occupied preserves both the original storage/plane loans and operation type.
unsafe impl<'a, S, V: slot::Reusable, A: Default, P: plane::Policy<S>, O>
    depot::raw::Project<slot::Handle<S>, O> for &'a mut Pool<S, V, A, P>
{
    type Output = Occupied<'a, S, V, A, P, O>;

    unsafe fn project(self, handle: slot::Handle<S>) -> Self::Output {
        let index = slot::Index(unsafe { NonZero::new_unchecked(handle.index().wrapping_add(1)) });
        const {
            assert!(mem::size_of::<Occupied<'_, S, V, A, P, O>>() == 3 * mem::size_of::<usize>());
        }
        Occupied {
            entry: slot::Occupied::new(&mut self.storage, index),
            plane: &mut self.plane,
            operation: marker::PhantomData,
        }
    }
}

impl<'a, S, V: slot::Reusable, A: Default, P: plane::Policy<S>> Iterator for Iter<'a, S, V, A, P> {
    type Item = slot::Resolved<'a, S, V, A>;

    fn next(&mut self) -> Option<Self::Item> {
        let live = self.0.next_entry()?;
        // SAFETY: this copies the same retained shared root reference; the
        // returned fields keep its original lifetime and cannot mutate it.
        Some(unsafe { live.map(|(source, index)| (*source, index)) }.into())
    }
}
