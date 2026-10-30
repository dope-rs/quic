use o3::buffer;

use std::mem;

use crate::conn::output::control::{self, kind};
use crate::conn::stream;
use crate::conn::stream::state::receive::{self, credits, recv};
use crate::conn::stream::state::streams;
use control::owner;
use recv::map;

pub(in crate::conn) struct State<B: crate::stream::Recv> {
    pub(in crate::conn) map: map::Map<B>,
    pub(in crate::conn) connection_window: credits::Flow,
    pub(in crate::conn) initial_stream_data: receive::Limits,
    pub(in crate::conn) max_data: Option<owner::Key<kind::MaxData>>,
}

pub(in crate::conn) struct Status<'state, B: crate::stream::Recv, D: buffer::raw::Segment> {
    state: &'state stream::State<B, D>,
}

impl<'state, B: crate::stream::Recv, D: buffer::raw::Segment> Status<'state, B, D> {
    pub(in crate::conn) fn new(state: &'state stream::State<B, D>) -> Self {
        Self { state }
    }

    pub(in crate::conn) fn has_ctrl(&self) -> bool {
        if self.state.receive.map.meta().has_ctrl() {
            return true;
        }
        let local = &self.state.local_initiated;
        let map = &self.state.receive.map;
        if local.all_allowed() {
            map.len() != 0
        } else {
            let role = self.state.local();
            map.has_ready(|id| local.allows(streams::Relative::new(id, role)))
        }
    }

    pub(in crate::conn) fn can_ctrl(&self, ctrl: &control::Pending) -> bool {
        self.has_ctrl() && ctrl.available().raw() != 0
    }
}

const _: () = assert!(
    mem::size_of::<Status<'_, Vec<u8>, o3::buffer::resident::Shared<'_>>>()
        == mem::size_of::<usize>()
);
