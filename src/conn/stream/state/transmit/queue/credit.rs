use crate::conn::output::control;
use crate::wire::varint;
use control::owner;

/// Peer flow-control credit and its derived advisory state.
/// Raising the limit clears every blocked-key state through its owner.
pub(in crate::conn) struct Credit<Kind> {
    limit: varint::VarInt,
    pub(in crate::conn) blocked: Option<owner::Key<Kind>>,
}

impl<Kind> Credit<Kind> {
    pub(in crate::conn) fn new(limit: varint::VarInt) -> Self {
        Self {
            limit,
            blocked: None,
        }
    }

    pub(in crate::conn) fn limit(&self) -> varint::VarInt {
        self.limit
    }

    pub(in crate::conn) fn replace(&mut self, limit: varint::VarInt, ctrl: &mut control::Pending) {
        self.limit = limit;
        ctrl.remove(&mut self.blocked);
    }

    pub(in crate::conn) fn raise(&mut self, limit: varint::VarInt, ctrl: &mut control::Pending) {
        if limit <= self.limit {
            return;
        }
        self.replace(limit, ctrl);
    }
}

const _: () = assert!(
    std::mem::size_of::<Credit<control::kind::StreamBlock>>() == 2 * std::mem::size_of::<u64>()
);
