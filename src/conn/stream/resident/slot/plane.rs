use std::{mem, num::NonZero};

use o3::depot::queue::indexed::keyed;

use crate::conn::stream::resident::slot;

pub(in crate::conn) trait Policy<Side>: Default {
    fn set_active<Value, Auxiliary>(
        &mut self,
        core: &mut Core<Side>,
        entry: &mut slot::Occupied<'_, Side, Value, Auxiliary>,
        active: bool,
    );

    fn remove<V, A>(
        &mut self,
        member: keyed::Slot<slot::Activity<'_, '_, Side, V, A>>,
        length: &mut u32,
    );
}

#[derive(Default)]
pub(in crate::conn) struct HeadOnly;

pub(in crate::conn) struct RoundRobin<Side> {
    pub(super) cursor: Option<slot::Handle<Side>>,
}

impl<Side> Default for RoundRobin<Side> {
    fn default() -> Self {
        Self { cursor: None }
    }
}

pub(in crate::conn) struct Core<Side> {
    pub(super) queue: keyed::Fifo<slot::Handle<Side>>,
    pub(super) length: u32,
}

pub(in crate::conn) struct Plane<Side, P> {
    pub(super) core: Core<Side>,
    pub(super) policy: P,
}

impl<Side> Core<Side> {
    fn new() -> Self {
        Self {
            queue: keyed::Fifo::new(),
            length: 0,
        }
    }

    fn link<Value, Auxiliary>(&mut self, entry: &mut slot::Occupied<'_, Side, Value, Auxiliary>) {
        if let Ok(vacant) = keyed::Slot::try_vacant(slot::Activity::new(entry, &mut self.queue)) {
            vacant.push::<false>();
            self.length += 1;
        }
    }
}

impl<Side> Policy<Side> for HeadOnly {
    fn set_active<Value, Auxiliary>(
        &mut self,
        core: &mut Core<Side>,
        entry: &mut slot::Occupied<'_, Side, Value, Auxiliary>,
        active: bool,
    ) {
        if active {
            core.link(entry);
            return;
        }
        if let Ok(member) = keyed::Slot::try_new(slot::Activity::new(entry, &mut core.queue)) {
            self.remove(member, &mut core.length);
        }
    }

    fn remove<V, A>(
        &mut self,
        member: keyed::Slot<slot::Activity<'_, '_, Side, V, A>>,
        length: &mut u32,
    ) {
        member.remove();
        *length -= 1;
    }
}

impl<Side> Policy<Side> for RoundRobin<Side> {
    fn set_active<Value, Auxiliary>(
        &mut self,
        core: &mut Core<Side>,
        entry: &mut slot::Occupied<'_, Side, Value, Auxiliary>,
        active: bool,
    ) {
        let key = entry.handle();
        if active {
            let first = core.length == 0;
            core.link(entry);
            if first {
                self.cursor = Some(key);
            }
            return;
        }
        if let Ok(member) = keyed::Slot::try_new(slot::Activity::new(entry, &mut core.queue)) {
            self.remove(member, &mut core.length);
        }
    }

    fn remove<V, A>(
        &mut self,
        member: keyed::Slot<slot::Activity<'_, '_, Side, V, A>>,
        length: &mut u32,
    ) {
        let key = member.key();
        let next = member.successor().map(slot::Activity::handle);
        let vacant = member.remove().release();
        *length -= 1;
        if self.cursor == Some(key) {
            self.cursor = next.or_else(|| vacant.front());
        }
        if *length == 0 {
            self.cursor = None;
        }
    }
}

impl<Side, P: Policy<Side>> Plane<Side, P> {
    pub(super) fn new() -> Self {
        Self {
            core: Core::new(),
            policy: P::default(),
        }
    }

    pub(in crate::conn) fn set_active<Value, Auxiliary>(
        &mut self,
        entry: &mut slot::Occupied<'_, Side, Value, Auxiliary>,
        active: bool,
    ) {
        self.policy.set_active(&mut self.core, entry, active);
    }
}

impl<Side, P> Plane<Side, P> {
    pub(in crate::conn) fn length(&self) -> usize {
        self.core.length as usize
    }
}

const _: () = {
    assert!(mem::size_of::<HeadOnly>() == 0);
    assert!(mem::size_of::<RoundRobin<()>>() == mem::size_of::<Option<NonZero<u64>>>());
    assert!(mem::size_of::<Plane<(), HeadOnly>>() == mem::size_of::<Core<()>>());
    assert!(mem::size_of::<Plane<(), RoundRobin<()>>>() == 6 * mem::size_of::<u32>());
};
