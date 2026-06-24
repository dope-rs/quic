use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

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
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn register(&mut self, token: &[u8]) -> bool {
        let now = self.now_ms();
        self.store.borrow_mut().register(token, now)
    }
}
