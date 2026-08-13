use std::marker;
use std::num;

const NONE: u32 = u32::MAX;
const FREE_STREAM_ID: u64 = u64::MAX;
const MAX_GENERATION: u32 = i32::MAX as u32;

pub(in crate::conn) trait Reusable {
    type Init;

    fn new(init: Self::Init) -> Self;
    fn reuse(&mut self, init: Self::Init);
    fn retire(&mut self);
}

#[repr(transparent)]
pub(in crate::conn) struct Id<Side>(u64, marker::PhantomData<fn() -> Side>);

impl<Side> Id<Side> {
    pub(in crate::conn) const fn new(stream_id: u64) -> Self {
        Self(stream_id, marker::PhantomData)
    }

    pub(in crate::conn) const fn get(self) -> u64 {
        self.0
    }
}

impl<Side> Clone for Id<Side> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Side> Copy for Id<Side> {}

/// Side-typed node metadata. It stores the owning subsystem's position or
/// link while the node is live and the free-list link after retirement, so
/// ownership adds no per-stream storage.
#[repr(transparent)]
pub(in crate::conn) struct Position<Side>(u32, marker::PhantomData<fn() -> Side>);

impl<Side> Position<Side> {
    pub(in crate::conn) const fn none() -> Self {
        Self(NONE, marker::PhantomData)
    }

    pub(in crate::conn) const fn is_none(&self) -> bool {
        self.0 == NONE
    }

    pub(in crate::conn) const fn get(&self) -> u32 {
        self.0
    }

    pub(in crate::conn) fn set(&mut self, index: u32) {
        self.0 = index;
    }

    pub(in crate::conn) fn clear(&mut self) {
        self.0 = NONE;
    }
}

#[repr(transparent)]
pub(in crate::conn) struct Handle<Side>(num::NonZeroU64, marker::PhantomData<fn() -> Side>);

impl<Side> Handle<Side> {
    pub(in crate::conn) fn new(index: u32, generation: u32) -> Self {
        debug_assert!(generation <= MAX_GENERATION);
        let encoded_index = index
            .checked_add(1)
            .expect("validated stream-state index fits its handle");
        let raw = (u64::from(generation) << 32) | u64::from(encoded_index);
        Self(
            num::NonZeroU64::new(raw).expect("encoded stream-state index is nonzero"),
            marker::PhantomData,
        )
    }

    pub(in crate::conn) fn from_raw(raw: num::NonZeroU64) -> Self {
        debug_assert_ne!(raw.get() as u32, 0);
        debug_assert!(raw.get() >> 63 == 0);
        Self(raw, marker::PhantomData)
    }

    pub(in crate::conn) const fn raw(self) -> num::NonZeroU64 {
        self.0
    }

    pub(in crate::conn) const fn index(self) -> u32 {
        (self.0.get() as u32) - 1
    }

    pub(in crate::conn) const fn generation(self) -> u32 {
        (self.0.get() >> 32) as u32
    }
}

impl<Side> Clone for Handle<Side> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Side> Copy for Handle<Side> {}

impl<Side> PartialEq for Handle<Side> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<Side> Eq for Handle<Side> {}

impl<Side> std::fmt::Debug for Handle<Side> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("Handle")
            .field(&self.index())
            .field(&self.generation())
            .finish()
    }
}

struct Node<Side, Value> {
    stream_id: u64,
    generation: u32,
    value: Value,
    link_or_next_free: Position<Side>,
}

enum Probe {
    Occupied { bucket: usize, node: u32 },
    Vacant(usize),
}

/// Fixed-capacity stream-side storage.
///
/// A wire ID pays one bounded hash probe and yields an entry whose references
/// are tied to this map borrow. Work crossing that borrow uses a typed,
/// generation-checked handle and resolves by direct slot access.
pub(in crate::conn) struct Map<Side, Value> {
    nodes: Vec<Node<Side, Value>>,
    buckets: Box<[u32]>,
    free: u32,
    capacity: usize,
    len: usize,
    side: marker::PhantomData<fn() -> Side>,
}

pub(in crate::conn) enum Entry<'a, Side, Value: Reusable> {
    Occupied(Occupied<'a, Side, Value>),
    Vacant(Vacant<'a, Side, Value>),
}

pub(in crate::conn) struct Occupied<'a, Side, Value: Reusable> {
    map: &'a mut Map<Side, Value>,
    bucket: usize,
    node: u32,
}

pub(in crate::conn) struct Vacant<'a, Side, Value: Reusable> {
    map: &'a mut Map<Side, Value>,
    bucket: usize,
    stream_id: u64,
}

impl<Side, Value: Reusable> Map<Side, Value> {
    pub(in crate::conn) fn new(capacity: usize) -> Self {
        debug_assert!(u32::try_from(capacity).is_ok());
        let bucket_count = capacity
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .expect("validated stream-state capacity fits its fixed index");
        Self {
            nodes: Vec::with_capacity(capacity),
            buckets: vec![NONE; bucket_count].into_boxed_slice(),
            free: NONE,
            capacity,
            len: 0,
            side: marker::PhantomData,
        }
    }

    pub(in crate::conn) fn get(&self, stream_id: Id<Side>) -> Option<&Value> {
        let Probe::Occupied { node, .. } = self.probe(stream_id.get()) else {
            return None;
        };
        Some(&self.nodes[node as usize].value)
    }

    pub(in crate::conn) fn with_position(
        &self,
        stream_id: Id<Side>,
    ) -> Option<(&Value, &Position<Side>)> {
        let Probe::Occupied { node, .. } = self.probe(stream_id.get()) else {
            return None;
        };
        let node = &self.nodes[node as usize];
        Some((&node.value, &node.link_or_next_free))
    }

    pub(in crate::conn) fn remaining_capacity(&self) -> usize {
        self.capacity - self.len
    }

    pub(in crate::conn) fn entry(&mut self, stream_id: Id<Side>) -> Entry<'_, Side, Value> {
        match self.probe(stream_id.get()) {
            Probe::Occupied { bucket, node } => Entry::Occupied(Occupied {
                map: self,
                bucket,
                node,
            }),
            Probe::Vacant(bucket) => Entry::Vacant(Vacant {
                map: self,
                bucket,
                stream_id: stream_id.get(),
            }),
        }
    }

    pub(in crate::conn) fn resolve(&self, handle: Handle<Side>) -> Option<(u64, &Value)> {
        let node = self.nodes.get(handle.index() as usize)?;
        (node.generation == handle.generation() && node.stream_id != FREE_STREAM_ID)
            .then_some((node.stream_id, &node.value))
    }

    pub(in crate::conn) fn resolve_mut(
        &mut self,
        handle: Handle<Side>,
    ) -> Option<(u64, &mut Value)> {
        let node = self.nodes.get_mut(handle.index() as usize)?;
        (node.generation == handle.generation() && node.stream_id != FREE_STREAM_ID)
            .then_some((node.stream_id, &mut node.value))
    }

    pub(in crate::conn) fn position_mut(
        &mut self,
        handle: Handle<Side>,
    ) -> Option<&mut Position<Side>> {
        let node = self.nodes.get_mut(handle.index() as usize)?;
        (node.generation == handle.generation() && node.stream_id != FREE_STREAM_ID)
            .then_some(&mut node.link_or_next_free)
    }

    pub(in crate::conn) fn position(&self, handle: Handle<Side>) -> Option<&Position<Side>> {
        let node = self.nodes.get(handle.index() as usize)?;
        (node.generation == handle.generation() && node.stream_id != FREE_STREAM_ID)
            .then_some(&node.link_or_next_free)
    }

    pub(in crate::conn) fn resolve_with_position_mut(
        &mut self,
        handle: Handle<Side>,
    ) -> Option<(u64, &mut Value, &mut Position<Side>)> {
        let node = self.nodes.get_mut(handle.index() as usize)?;
        (node.generation == handle.generation() && node.stream_id != FREE_STREAM_ID).then_some((
            node.stream_id,
            &mut node.value,
            &mut node.link_or_next_free,
        ))
    }

    pub(in crate::conn) fn handle_at(&self, index: u32) -> Option<Handle<Side>> {
        let node = self.nodes.get(index as usize)?;
        (node.stream_id != FREE_STREAM_ID).then(|| Handle::new(index, node.generation))
    }

    pub(in crate::conn) fn remove(&mut self, stream_id: Id<Side>) -> bool {
        let Probe::Occupied { bucket, node } = self.probe(stream_id.get()) else {
            return false;
        };
        self.remove_at(bucket, node);
        true
    }

    fn insert_at(
        &mut self,
        bucket: usize,
        stream_id: u64,
        init: Value::Init,
    ) -> Option<(Handle<Side>, &mut Value, &mut Position<Side>)> {
        if self.len == self.capacity {
            return None;
        }
        let index = if self.free == NONE {
            if self.nodes.len() == self.capacity {
                return None;
            }
            let index = u32::try_from(self.nodes.len()).ok()?;
            self.nodes.push(Node {
                stream_id,
                generation: 0,
                value: Value::new(init),
                link_or_next_free: Position::none(),
            });
            index
        } else {
            let index = self.free;
            let node = &mut self.nodes[index as usize];
            self.free = node.link_or_next_free.get();
            node.stream_id = stream_id;
            node.value.reuse(init);
            node.link_or_next_free.clear();
            index
        };
        self.buckets[bucket] = index;
        self.len += 1;
        let handle = self.handle(index);
        let node = &mut self.nodes[index as usize];
        Some((handle, &mut node.value, &mut node.link_or_next_free))
    }

    fn remove_at(&mut self, bucket: usize, node: u32) {
        self.remove_bucket(bucket);
        let entry = &mut self.nodes[node as usize];
        entry.stream_id = FREE_STREAM_ID;
        entry.value.retire();
        if entry.generation < MAX_GENERATION {
            entry.generation += 1;
            entry.link_or_next_free.set(self.free);
            self.free = node;
        } else {
            entry.link_or_next_free.clear();
        }
        self.len -= 1;
    }

    fn handle(&self, index: u32) -> Handle<Side> {
        Handle::new(index, self.nodes[index as usize].generation)
    }

    fn probe(&self, stream_id: u64) -> Probe {
        let mask = self.buckets.len() - 1;
        let mut bucket = hash(stream_id) as usize & mask;
        for _ in 0..self.buckets.len() {
            let node = self.buckets[bucket];
            if node == NONE {
                return Probe::Vacant(bucket);
            }
            if self.nodes[node as usize].stream_id == stream_id {
                return Probe::Occupied { bucket, node };
            }
            bucket = (bucket + 1) & mask;
        }
        unreachable!("the half-full stream-state index always has a vacant bucket")
    }

    fn remove_bucket(&mut self, mut hole: usize) {
        let mask = self.buckets.len() - 1;
        self.buckets[hole] = NONE;
        let mut next = (hole + 1) & mask;
        while self.buckets[next] != NONE {
            let node = self.buckets[next];
            let home = hash(self.nodes[node as usize].stream_id) as usize & mask;
            if (next.wrapping_sub(home) & mask) > (hole.wrapping_sub(home) & mask) {
                self.buckets[hole] = node;
                self.buckets[next] = NONE;
                hole = next;
            }
            next = (next + 1) & mask;
        }
    }
}

impl<'a, Side, Value: Reusable> Entry<'a, Side, Value> {
    pub(in crate::conn) fn or_insert(
        self,
        init: Value::Init,
    ) -> Option<(Handle<Side>, &'a mut Value)> {
        match self {
            Self::Occupied(occupied) => Some((occupied.handle(), occupied.into_mut())),
            Self::Vacant(vacant) => vacant.insert(init),
        }
    }

    pub(in crate::conn) fn or_insert_with_position(
        self,
        init: Value::Init,
    ) -> Option<(Handle<Side>, &'a mut Value, &'a mut Position<Side>)> {
        match self {
            Self::Occupied(occupied) => Some(occupied.into_with_position()),
            Self::Vacant(vacant) => vacant.insert_with_position(init),
        }
    }
}

impl<'a, Side, Value: Reusable> Occupied<'a, Side, Value> {
    pub(in crate::conn) fn handle(&self) -> Handle<Side> {
        self.map.handle(self.node)
    }

    pub(in crate::conn) fn get_mut(&mut self) -> &mut Value {
        &mut self.map.nodes[self.node as usize].value
    }

    pub(in crate::conn) fn into_mut(self) -> &'a mut Value {
        &mut self.map.nodes[self.node as usize].value
    }

    pub(in crate::conn) fn with_position_mut(&mut self) -> (&mut Value, &mut Position<Side>) {
        let node = &mut self.map.nodes[self.node as usize];
        (&mut node.value, &mut node.link_or_next_free)
    }

    pub(in crate::conn) fn into_with_position(
        self,
    ) -> (Handle<Side>, &'a mut Value, &'a mut Position<Side>) {
        let handle = self.map.handle(self.node);
        let node = &mut self.map.nodes[self.node as usize];
        (handle, &mut node.value, &mut node.link_or_next_free)
    }

    pub(in crate::conn) fn remove_with(
        self,
        before_remove: impl FnOnce(&mut Map<Side, Value>, Handle<Side>),
    ) {
        let handle = self.map.handle(self.node);
        before_remove(self.map, handle);
        self.map.remove_at(self.bucket, self.node);
    }
}

impl<'a, Side, Value: Reusable> Vacant<'a, Side, Value> {
    pub(in crate::conn) fn insert(
        self,
        init: Value::Init,
    ) -> Option<(Handle<Side>, &'a mut Value)> {
        self.map
            .insert_at(self.bucket, self.stream_id, init)
            .map(|(handle, value, _)| (handle, value))
    }

    pub(in crate::conn) fn insert_with_position(
        self,
        init: Value::Init,
    ) -> Option<(Handle<Side>, &'a mut Value, &'a mut Position<Side>)> {
        self.map.insert_at(self.bucket, self.stream_id, init)
    }
}

fn hash(stream_id: u64) -> u64 {
    let mut value = stream_id;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

const _: () = assert!(std::mem::size_of::<Id<()>>() == std::mem::size_of::<u64>());
const _: () = assert!(std::mem::size_of::<Handle<()>>() == std::mem::size_of::<u64>());
const _: () = assert!(std::mem::size_of::<Option<Handle<()>>>() == std::mem::size_of::<u64>());
const _: () = assert!(std::mem::size_of::<Position<()>>() == std::mem::size_of::<u32>());
