use crate::conn::stream::state::receive::recv::map;
use crate::{
    stream,
    wire::{frame, ranges::plan, varint},
};
use o3::depot::{arena::linked::head, capacity};

pub(in crate::conn::stream::state::receive::recv) struct Buffer<B: stream::Recv = Vec<u8>> {
    pub(in crate::conn::stream::state::receive::recv) assembled: B::Ready,
    pub(in crate::conn::stream::state::receive::recv) head: head::List<map::Tag>,
    pub(in crate::conn::stream::state::receive::recv) next: u64,
    pub(in crate::conn::stream::state::receive::recv) ranges: usize,
}

pub(in crate::conn) struct Pending<'body, B> {
    pub(in crate::conn::stream::state::receive::recv) offset: varint::VarInt,
    pub(in crate::conn::stream::state::receive::recv) record: plan::Record,
    pub(in crate::conn::stream::state::receive::recv) data: stream::Payload<'body, B>,
    pub(in crate::conn::stream::state::receive::recv) boundary: frame::Boundary,
}

pub(in crate::conn) struct Prepared<'body, B: stream::Recv> {
    pub(in crate::conn::stream::state::receive::recv) ranges: plan::Prepared<'body, B>,
    pub(in crate::conn::stream::state::receive::recv) end: u64,
    pub(in crate::conn::stream::state::receive::recv) final_size: Option<u64>,
    pub(in crate::conn::stream::state::receive::recv) slots: capacity::Count,
    pub(in crate::conn::stream::state::receive::recv) readable: bool,
}

impl<'body, B> Pending<'body, B> {
    pub(in crate::conn) const fn new(
        offset: varint::VarInt,
        record: plan::Record,
        data: stream::Payload<'body, B>,
        boundary: frame::Boundary,
    ) -> Self {
        Self {
            offset,
            record,
            data,
            boundary,
        }
    }
}

impl<B: stream::Recv> Default for Buffer<B> {
    fn default() -> Self {
        Self {
            assembled: B::Ready::default(),
            head: head::List::new(),
            next: 0,
            ranges: 0,
        }
    }
}

const _: () = assert!(usize::BITS <= u64::BITS);

impl<B: stream::Recv> Prepared<'_, B> {
    pub(in crate::conn) fn slots(&self) -> capacity::Count {
        self.slots
    }
}

const _: () = assert!(
    size_of::<Prepared<'_, Vec<u8>>>()
        == size_of::<plan::Prepared<'_, Vec<u8>>>() + 4 * size_of::<usize>()
);
