use o3::depot::capacity::Count;

#[repr(C)]
pub(in crate::conn::output::journals) struct State {
    pub(in crate::conn::output::journals) head: Count,
    pub(in crate::conn::output::journals) len: Count,
    pub(super) limit: Count,
}

impl State {
    pub(in crate::conn::output::journals) const fn physical(
        &self,
        capacity: usize,
        offset: usize,
    ) -> usize {
        let physical = self.head.get() + offset;
        if physical >= capacity {
            physical - capacity
        } else {
            physical
        }
    }

    pub(super) const fn split(&self, capacity: usize) -> (usize, usize, usize) {
        let head = self.head.get();
        let first = if self.len.get() < capacity - head {
            self.len.get()
        } else {
            capacity - head
        };
        (head, first, self.len.get() - first)
    }
}

const _: () = assert!(size_of::<State>() == 12);
