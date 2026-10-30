use std::mem;

pub(in crate::conn::machine::storage) struct Slot<T, G> {
    pub(in crate::conn::machine::storage::compact) generation: G,
    pub(in crate::conn::machine::storage::compact) next: u32,
    pub(in crate::conn::machine::storage::compact) value: mem::MaybeUninit<T>,
}
