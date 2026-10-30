use crate::common::e2e::trace;

/// Exact causal identity of one decoded trace transition.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Step {
    ordinal: usize,
    action: trace::Action,
}

impl Step {
    pub const fn new(ordinal: usize, action: trace::Action) -> Self {
        Self { ordinal, action }
    }

    pub const fn ordinal(self) -> usize {
        self.ordinal
    }

    pub const fn action(self) -> trace::Action {
        self.action
    }
}
