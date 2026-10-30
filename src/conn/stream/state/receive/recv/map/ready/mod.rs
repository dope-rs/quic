use crate::conn::stream::state::receive::recv::map;
use o3::depot::arena::linked::fifo;
use std::mem;

pub(crate) mod raw;

#[derive(Default)]
pub struct Segments {
    queue: fifo::Fifo<map::Tag>,
    bytes: u64,
}

const _: () = {
    assert!(usize::BITS == u64::BITS);
    assert!(mem::size_of::<Segments>() == 3 * mem::size_of::<usize>());
};
