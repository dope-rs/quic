use o3::depot::queue::indexed::keyed;

use crate::conn::output::control::journal::storage::{Key, Status};
use crate::conn::output::delivery;

pub(in crate::conn::output::control) struct Entry {
    pub(in crate::conn::output::control::journal::storage) record: delivery::Control,
    pub(in crate::conn::output::control) status: Status,
    pub(in crate::conn::output::control::journal::storage) hook: keyed::Link<Key>,
}

impl Entry {
    pub(in crate::conn::output::control) const fn record(&self) -> &delivery::Control {
        &self.record
    }
}

const _: () = assert!(std::mem::size_of::<Entry>() == 48);
