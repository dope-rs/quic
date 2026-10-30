use std::{mem, ops};

use crate::conn::output::control::{self, kind};
use crate::conn::stream::state::receive::{credits, recv};
use control::owner;

const CREDIT_DIRTY: u8 = 1;

pub(in crate::conn) struct State {
    pub(in crate::conn::stream::state::receive::recv) progress: recv::Progress,
    pub(in crate::conn) credit: credits::Window,
    pub(in crate::conn::stream::state::receive::recv) control_flags: u8,
    pub(in crate::conn) max_stream_data: Option<owner::Key<kind::StreamLimit>>,
    pub(in crate::conn) stop_sending: owner::Signal<kind::StopSending>,
}

impl State {
    pub(in crate::conn::stream::state::receive::recv) fn new() -> Self {
        Self {
            progress: recv::Progress::default(),
            credit: credits::Window::new(),
            control_flags: 0,
            max_stream_data: None,
            stop_sending: owner::Signal::new(),
        }
    }
}

impl State {
    pub(in crate::conn) fn mark_credit(&mut self) {
        self.control_flags |= CREDIT_DIRTY;
    }

    pub(in crate::conn) fn clear_credit(&mut self) {
        self.control_flags &= !CREDIT_DIRTY;
    }

    pub(in crate::conn) fn has_credit(&self) -> bool {
        self.control_flags & CREDIT_DIRTY != 0
    }

    pub(in crate::conn) fn has_deferred(&self) -> bool {
        self.has_credit() || self.stop_sending.is_deferred()
    }

    pub(in crate::conn) fn retire(&mut self, ctrl: &mut control::Pending) {
        ctrl.remove(&mut self.max_stream_data);
        ctrl.clear(&mut self.stop_sending);
        self.control_flags = 0;
    }
}

impl ops::Deref for State {
    type Target = recv::Progress;

    fn deref(&self) -> &Self::Target {
        &self.progress
    }
}

impl ops::DerefMut for State {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.progress
    }
}

const _: () = assert!(
    mem::size_of::<State>() == mem::size_of::<recv::Progress>() + 5 * mem::size_of::<u64>()
);
