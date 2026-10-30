use crate::conn::machine::storage::compact;
use o3::depot::arena::slab::external;
use o3::depot::queue::links;

pub(in crate::conn) struct Lease<'a, T, G: external::Generation> {
    core: &'a mut compact::raw::Core<T, G>,
    kind: compact::raw::Vacancy,
}

impl<'a, T, G: external::Generation> Lease<'a, T, G> {
    /// # Safety
    /// The kind was selected from this unchanged exclusively owned core.
    pub(in crate::conn) unsafe fn new(
        core: &'a mut compact::raw::Core<T, G>,
        kind: compact::raw::Vacancy,
    ) -> Self {
        Self { core, kind }
    }

    pub(in crate::conn) fn index(&self) -> links::Index {
        match &self.kind.0 {
            compact::raw::Kind::Recycled(free) => free.0,
            compact::raw::Kind::Virgin(position) => (*position).into(),
        }
    }

    pub(in crate::conn) fn insert(self, value: T) -> compact::raw::Occupied<'a, T, G> {
        self.core.commit(self.kind, value)
    }
}
