use std::alloc::{GlobalAlloc, Layout, System};

pub struct Allocator {
    record: fn(usize),
}

impl Allocator {
    pub const fn new(record: fn(usize)) -> Self {
        Self { record }
    }
}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        (self.record)(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        (self.record)(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        (self.record)(size);
        unsafe { System.realloc(pointer, layout, size) }
    }
}
