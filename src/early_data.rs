use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use shin::server::EarlyDataGuard;

// Tickets (and thus binders) are only valid this long; matches shin's TICKET_LIFETIME.
const TICKET_LIFETIME_MS: u64 = 7_200_000;

#[derive(Debug, Default)]
pub struct ReplayStore {
    seen: HashMap<Vec<u8>, u64>,
}

impl ReplayStore {
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    // Returns true if `token` is new (accept), false if already seen (replay).
    fn register(&mut self, token: &[u8], now_ms: u64) -> bool {
        self.seen
            .retain(|_, &mut inserted| now_ms.saturating_sub(inserted) <= TICKET_LIFETIME_MS);
        if self.seen.contains_key(token) {
            return false;
        }
        self.seen.insert(token.to_vec(), now_ms);
        true
    }
}

pub type SharedReplayStore = Rc<RefCell<ReplayStore>>;

pub fn shared_replay_store() -> SharedReplayStore {
    Rc::new(RefCell::new(ReplayStore::new()))
}

pub struct ReplayGuard {
    store: SharedReplayStore,
}

impl ReplayGuard {
    pub fn new(store: SharedReplayStore) -> Self {
        Self { store }
    }
}

impl EarlyDataGuard for ReplayGuard {
    fn register(&mut self, token: &[u8]) -> bool {
        self.store
            .borrow_mut()
            .register(token, crate::time::now_ms())
    }
}
