use crate::conn::{
    self,
    machine::storage::compact,
    output::delivery,
    wire::crypto::tx::{
        self, commit,
        stores::{self, table},
    },
};
use o3::depot;
use o3::depot::{
    index,
    queue::{indexed::keyed, links},
};
use std::num::NonZero;

#[must_use]
pub(in crate::conn) struct Prepared<O: tx::raw::Owner>(Allocation<O>);

enum Allocation<O: tx::raw::Owner> {
    Existing(Root<O, Existing>),
    Insert {
        root: Root<O, Insert>,
        kind: compact::raw::Vacancy,
    },
}

struct Root<O, P> {
    owner: O,
    operation: P,
}

enum Existing {
    Empty,
    Ready(Ready),
    Probe(Probe),
}

struct Ready {
    key: stores::Key,
    record: delivery::Crypto,
}

struct Probe {
    key: stores::Key,
    carriers: NonZero<u16>,
}

enum Insert {
    Fresh {
        epoch: conn::Epoch,
        record: delivery::Crypto,
    },
    Split {
        key: stores::Key,
        record: delivery::Crypto,
        rest: delivery::Crypto,
    },
}

struct Slot<'a, O, P> {
    owner: &'a mut O,
    operation: P,
}

impl<O: tx::raw::Owner> Prepared<O> {
    pub(in crate::conn) fn try_new(input: O::Input) -> Result<Self, O::Input> {
        let (owner, selected) = O::select(input);
        let insert = match selected.map(|commit| commit.0) {
            None => {
                return Ok(Self(Allocation::Existing(Root {
                    owner,
                    operation: Existing::Empty,
                })));
            }
            Some(commit::State::Ready {
                key,
                record,
                rest: None,
            }) => {
                return Ok(Self(Allocation::Existing(Root {
                    owner,
                    operation: Existing::Ready(Ready { key, record }),
                })));
            }
            Some(commit::State::Probe { key, carriers, .. }) => {
                return Ok(Self(Allocation::Existing(Root {
                    owner,
                    operation: Existing::Probe(Probe { key, carriers }),
                })));
            }
            Some(commit::State::Fresh { epoch, record }) => Insert::Fresh { epoch, record },
            Some(commit::State::Ready {
                key,
                record,
                rest: Some(rest),
            }) => Insert::Split { key, record, rest },
        };
        match owner.tx().deliveries.slots.entries.core.probe() {
            Some(kind) => Ok(Self(Allocation::Insert {
                root: Root {
                    owner,
                    operation: insert,
                },
                kind,
            })),
            None => {
                let state = match insert {
                    Insert::Fresh { epoch, record } => commit::State::Fresh { epoch, record },
                    Insert::Split { key, record, rest } => commit::State::Ready {
                        key,
                        record,
                        rest: Some(rest),
                    },
                };
                Err(owner.reject(tx::Commit(state)))
            }
        }
    }

    pub(in crate::conn) fn owner(&self) -> &O {
        match &self.0 {
            Allocation::Existing(root) => &root.owner,
            Allocation::Insert { root, .. } => &root.owner,
        }
    }

    pub(in crate::conn) fn is_empty(&self) -> bool {
        matches!(
            self.0,
            Allocation::Existing(Root {
                operation: Existing::Empty,
                ..
            })
        )
    }

    pub(in crate::conn) fn context(&mut self) -> O::Context<'_> {
        match &mut self.0 {
            Allocation::Existing(root) => root.owner.parts().1,
            Allocation::Insert { root, .. } => root.owner.parts().1,
        }
    }

    pub(in crate::conn) fn cancel(self) -> O {
        match self.0 {
            Allocation::Existing(root) => root.owner,
            Allocation::Insert { root, .. } => root.owner,
        }
    }

    pub(in crate::conn) fn commit(self) -> (O::Output, Option<delivery::Handle<delivery::Crypto>>) {
        match self.0 {
            Allocation::Existing(mut root) => {
                let handle = match root.operation {
                    Existing::Empty => None,
                    Existing::Ready(selected) => Some(
                        Slot {
                            owner: &mut root.owner,
                            operation: selected,
                        }
                        .send(),
                    ),
                    Existing::Probe(selected) => Some(
                        Slot {
                            owner: &mut root.owner,
                            operation: selected,
                        }
                        .probe(),
                    ),
                };
                (root.owner.finish(), handle)
            }
            Allocation::Insert { mut root, kind } => {
                let (epoch, record, status) = match root.operation {
                    Insert::Fresh { epoch, record } => {
                        (epoch, record, stores::Status::flight(NonZero::<u16>::MIN))
                    }
                    Insert::Split { key, rest, .. } => {
                        let source = Selected {
                            owner: &root.owner,
                            key,
                        };
                        let live = index::Access::into_live(source);
                        let live = unsafe {
                            live.map(|(source, index)| (&source.owner.tx().deliveries.slots, index))
                        };
                        (
                            table::Slots::project(live).1.epoch,
                            rest,
                            stores::Status::queued(),
                        )
                    }
                };
                let lease = unsafe {
                    compact::raw::Lease::new(
                        &mut root.owner.parts().0.deliveries.slots.entries.core,
                        kind,
                    )
                };
                let index = lease.index();
                let entry = lease.insert(stores::Entry {
                    epoch,
                    record,
                    status,
                    flight: keyed::Link::from(index),
                    order_next: None,
                });
                let index = entry.index();
                let live = unsafe { depot::raw::Proof::new((root, index)) };
                let (owner, handle) = live.into();
                (owner, Some(handle))
            }
        }
    }
}

struct Selected<'a, O> {
    owner: &'a O,
    key: stores::Key,
}

// SAFETY: only the original selected operation under the retained root creates this projection.
unsafe impl<O: tx::raw::Owner> depot::raw::Source<Insert> for Selected<'_, O> {
    type Key = links::Index;
    fn key(&self) -> Self::Key {
        unsafe {
            <links::Index as depot::raw::Word>::from_offset(
                <stores::Key as depot::raw::Key>::index(self.key),
            )
        }
    }
}

// SAFETY: the insertion leaf supplies this original root and its newly initialized slot.
unsafe impl<O: tx::raw::Owner> depot::raw::Project<links::Index> for Root<O, Insert> {
    type Output = (O::Output, delivery::Handle<delivery::Crypto>);

    unsafe fn project(mut self, index: links::Index) -> Self::Output {
        let slot = Slot {
            owner: &mut self.owner,
            operation: index,
        };
        let live = index::Access::into_live(slot);
        let live = unsafe {
            live.map(|(slot, index)| {
                let (tx, _) = slot.owner.parts();
                let stores::Set {
                    slots,
                    ready,
                    flights,
                } = &mut tx.deliveries;
                (
                    (
                        &mut slots.entries,
                        (&mut slots.order, ready, flights, &mut tx.bytes),
                    ),
                    index,
                )
            })
        };
        let (entry, (order, ready, flights, bytes)) = compact::Table::project_mut(live);
        let mut entry = table::Occupied(entry);
        let epoch = entry.get().epoch;
        let handle = match self.operation {
            Insert::Fresh { record, .. } => {
                let handle = table::Fresh {
                    entry,
                    order: epoch.bind_mut(order),
                }
                .append(flights);
                bytes.advance(epoch, record);
                handle
            }
            Insert::Split { key, record, .. } => {
                let added = entry.key();
                let source = Prior {
                    entry: &mut entry,
                    key,
                };
                let live = index::Access::into_live(source);
                let live = unsafe { live.map(|(source, index)| (&mut source.entry.0, index)) };
                let prior = compact::Occupied::update(live);
                let next = prior.order_next;
                prior.order_next = Some(added);
                entry.get_mut().order_next = next;
                if next.is_none() {
                    epoch.bind_mut(order).tail = Some(added);
                }
                // SAFETY: insertion produced this vacant suffix in the original ready queue.
                unsafe {
                    keyed::Slot::from_source(depot::raw::Proof::new(table::Slot {
                        entry,
                        source: epoch.bind_mut(&mut ready.0),
                    }))
                }
                .push::<false>();
                Slot {
                    owner: &mut self.owner,
                    operation: Ready { key, record },
                }
                .send()
            }
        };
        (self.owner.finish(), handle)
    }
}

struct Prior<'a, 'b> {
    entry: &'a mut table::Occupied<'b, Insert>,
    key: stores::Key,
}

// SAFETY: the selected prefix and inserted suffix remain in the same exclusively retained table.
unsafe impl depot::raw::Source<Insert> for Prior<'_, '_> {
    type Key = links::Index;
    fn key(&self) -> Self::Key {
        unsafe {
            <links::Index as depot::raw::Word>::from_offset(
                <stores::Key as depot::raw::Key>::index(self.key),
            )
        }
    }
}

// SAFETY: the insertion consumer retains this newly initialized index and owner.
unsafe impl<O: tx::raw::Owner> depot::raw::Source<Insert> for Slot<'_, O, links::Index> {
    type Key = links::Index;
    fn key(&self) -> Self::Key {
        self.operation
    }
}

// SAFETY: this ready operation retains its original root, key, and byte range.
unsafe impl<O: tx::raw::Owner> depot::raw::Source<Ready> for Slot<'_, O, Ready> {
    type Key = links::Index;
    fn key(&self) -> Self::Key {
        unsafe {
            <links::Index as depot::raw::Word>::from_offset(
                <stores::Key as depot::raw::Key>::index(self.operation.key),
            )
        }
    }
}

// SAFETY: this probe retains the native flight selection and checked carrier count.
unsafe impl<O: tx::raw::Owner> depot::raw::Source<Probe> for Slot<'_, O, Probe> {
    type Key = links::Index;
    fn key(&self) -> Self::Key {
        unsafe {
            <links::Index as depot::raw::Word>::from_offset(
                <stores::Key as depot::raw::Key>::index(self.operation.key),
            )
        }
    }
}

impl<O: tx::raw::Owner> Slot<'_, O, Ready> {
    fn send(self) -> delivery::Handle<delivery::Crypto> {
        let live = index::Access::into_live(self);
        let live = unsafe {
            live.map(|(slot, index)| {
                let (tx, _) = slot.owner.parts();
                let stores::Set {
                    slots,
                    ready,
                    flights,
                } = &mut tx.deliveries;
                (
                    (&mut slots.entries, (ready, flights, slot.operation)),
                    index,
                )
            })
        };
        let (entry, (ready, flights, selected)) = compact::Table::project_mut(live);
        let epoch = entry.get().epoch;
        let handle = selected.key.handle();
        table::Occupied(entry).send(
            epoch.bind_mut(&mut ready.0),
            epoch.bind_mut(&mut flights.chains),
            selected.record,
        );
        handle
    }
}

impl<O: tx::raw::Owner> Slot<'_, O, Probe> {
    fn probe(self) -> delivery::Handle<delivery::Crypto> {
        let live = index::Access::into_live(self);
        let live = unsafe {
            live.map(|(slot, index)| {
                let (tx, _) = slot.owner.parts();
                (
                    (
                        &mut tx.deliveries.slots.entries,
                        (&mut tx.deliveries.flights, slot.operation),
                    ),
                    index,
                )
            })
        };
        let (entry, (flights, selected)) = compact::Table::project_mut(live);
        let epoch = entry.get().epoch;
        let handle = selected.key.handle();
        // SAFETY: the native probe selection retained this exact flight membership.
        let member = unsafe {
            keyed::Slot::from_source(depot::raw::Proof::new(table::Slot {
                entry: table::Occupied(entry),
                source: epoch.bind_mut(&mut flights.chains),
            }))
        };
        *epoch.bind_mut(&mut flights.probes) = member.successor().map(|live| {
            let live = unsafe { live.map(|(owner, index)| (&owner.entry, index)) };
            table::Occupied::project(live).0
        });
        member.release().get_mut().status = stores::Status::flight(selected.carriers);
        handle
    }
}

const _: () = {
    assert!(std::mem::size_of::<table::Occupied<'static, Ready>>() == 16);
    assert!(std::mem::size_of::<table::Occupied<'static, Probe>>() == 16);
    assert!(std::mem::size_of::<table::Occupied<'static, Insert>>() == 16);
    assert!(std::mem::size_of::<Option<table::Occupied<'static, Probe>>>() == 16);
};
