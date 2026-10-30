use std::{mem, ops};

use crate::conn::stream::resident::slot;
use crate::conn::stream::state::receive::recv;
use crate::stream;

pub(in crate::conn) struct Entry<B: stream::Recv> {
    pub(in crate::conn::stream::state::receive::recv) buffer: recv::Buffer<B>,
    pub(in crate::conn::stream::state::receive::recv) state: recv::State,
}

impl<B: stream::Recv> slot::Reusable for Entry<B> {
    type Init = ();

    fn new((): Self::Init) -> Self {
        Self {
            buffer: recv::Buffer::default(),
            state: recv::State::new(),
        }
    }

    fn reuse(&mut self, (): Self::Init) {
        self.state.credit.reuse();
    }
}

impl<B: stream::Recv> ops::Deref for Entry<B> {
    type Target = recv::State;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<B: stream::Recv> ops::DerefMut for Entry<B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

const _: () = assert!(
    mem::size_of::<Entry<Vec<u8>>>()
        == mem::size_of::<recv::Buffer<Vec<u8>>>() + mem::size_of::<recv::State>()
);
