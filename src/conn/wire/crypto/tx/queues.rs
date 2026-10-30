//! Exact-key CRYPTO ready, flight, and acknowledgement order queues.

use o3::depot::queue::indexed::keyed;

use crate::conn;
use crate::conn::wire::crypto::tx::stores;
use stores::table;

pub(super) struct Ready(pub(super) [keyed::Fifo<stores::Key, stores::Flight>; 3]);

impl Ready {
    pub(super) const fn new() -> Self {
        Self([const { keyed::Fifo::new() }; 3])
    }

    pub(super) fn clear(&mut self, epoch: conn::Epoch) {
        *epoch.bind_mut(&mut self.0) = keyed::Fifo::new();
    }

    pub(super) fn lose(&mut self, flights: &mut Flights, slot: table::Lost<'_>) {
        let epoch = slot.epoch();
        let source = epoch.bind_mut(&mut flights.chains);
        let target = epoch.bind_mut(&mut self.0);
        let (key, next) = slot.transfer(source, target);
        if *epoch.bind(&flights.probes) == Some(key) {
            *epoch.bind_mut(&mut flights.probes) = next;
        }
    }
}

pub(super) struct Flights {
    pub(super) chains: [keyed::Fifo<stores::Key, stores::Flight>; 3],
    pub(super) probes: [Option<stores::Key>; 3],
}

impl Flights {
    pub(super) fn new() -> Self {
        Self {
            chains: [const { keyed::Fifo::new() }; 3],
            probes: [None; 3],
        }
    }

    pub(super) fn clear(&mut self, epoch: conn::Epoch) {
        *epoch.bind_mut(&mut self.chains) = keyed::Fifo::new();
        *epoch.bind_mut(&mut self.probes) = None;
    }
}

const _: () = {
    assert!(std::mem::size_of::<Ready>() == 3 * std::mem::size_of::<usize>());
    assert!(std::mem::size_of::<Flights>() == 6 * std::mem::size_of::<usize>());
};
