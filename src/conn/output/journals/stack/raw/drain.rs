use crate::conn::output::journals::stack;

pub(in crate::conn::output) struct Drain<'a, T: Copy, Tag> {
    slab: &'a mut stack::raw::Slab<T, Tag>,
    head: stack::Head<Tag>,
}

impl<'a, T: Copy, Tag> Drain<'a, T, Tag> {
    pub(in crate::conn::output::journals::stack) const fn new(
        slab: &'a mut stack::raw::Slab<T, Tag>,
        head: stack::Head<Tag>,
    ) -> Self {
        Self { slab, head }
    }
}

impl<T: Copy, Tag> Iterator for Drain<'_, T, Tag> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        let index = self.head.index;
        if index == u16::MAX {
            return None;
        }
        let node =
            unsafe { (*self.slab.block.as_mut_ptr().add(usize::from(index))).assume_init_mut() };
        self.head.index = node.next;
        let value = node.value;
        let state = self.slab.block.state_mut();
        node.next = state.free;
        state.free = index;
        state.live -= 1;
        Some(value)
    }
}

impl<T: Copy, Tag> Drop for Drain<'_, T, Tag> {
    fn drop(&mut self) {
        while self.next().is_some() {}
    }
}

const _: () = assert!(size_of::<Drain<'static, (), ()>>() == 16);
