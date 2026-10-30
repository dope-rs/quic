use crate::conn::output::control;
use crate::conn::stream::resident::slot;
use crate::conn::stream::state::receive::recv::map::views;
use crate::conn::stream::state::receive::recv::{self, map};
use crate::stream;
use o3::depot;

/// Exclusive owners required to detach and recycle one receive entry.
pub(in crate::conn) struct Recycle<'a, B: stream::Recv> {
    control: &'a mut control::Pending,
    ranges: &'a depot::raw::Arena<map::Node<B>, map::Tag>,
}

pub(in crate::conn) struct Fresh<'a, B: stream::Recv> {
    ranges: &'a depot::raw::Arena<map::Node<B>, map::Tag>,
}

impl<'a, B: stream::Recv> Fresh<'a, B> {
    pub(in crate::conn::stream::state::receive::recv::map) fn new(
        ranges: &'a depot::raw::Arena<map::Node<B>, map::Tag>,
    ) -> Self {
        Self { ranges }
    }
}

impl<B: stream::Recv> slot::Recycle for Fresh<'_, B> {
    type Value = recv::Entry<B>;

    fn recycle(self, value: &mut Self::Value) {
        views::Write {
            entry: value,
            arena: self.ranges,
        }
        .clear();
        value.buffer.next = 0;
        value.state.progress.recycle();
        value.control_flags = 0;
    }
}

impl<'a, B: stream::Recv> Recycle<'a, B> {
    pub(in crate::conn::stream::state::receive::recv::map) fn new(
        control: &'a mut control::Pending,
        ranges: &'a depot::raw::Arena<map::Node<B>, map::Tag>,
    ) -> Self {
        Self { control, ranges }
    }
}

impl<B: stream::Recv> slot::Recycle for Recycle<'_, B> {
    type Value = recv::Entry<B>;

    fn recycle(self, value: &mut Self::Value) {
        value.retire(self.control);
        views::Write {
            entry: value,
            arena: self.ranges,
        }
        .clear();
        value.buffer.next = 0;
        value.state.progress.recycle();
    }
}
