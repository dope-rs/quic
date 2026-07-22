use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::rc::Rc;

use crate::clock::WallClock;
use shin::server::EarlyDataGuard;

const REPLAY_WINDOW_MS: u64 = 7_200_000;
const MAX_REPLAY_CAPACITY: usize = 65_536;
const DEFAULT_REPLAY_CAPACITY: usize = MAX_REPLAY_CAPACITY;
const MAX_TOKEN_LEN: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayCacheError;

impl fmt::Display for ReplayCacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("early data replay capacity exceeds the supported maximum")
    }
}

impl std::error::Error for ReplayCacheError {}

#[derive(Debug)]
pub struct EarlyDataReplayCache {
    seen: HashMap<Vec<u8>, u64>,
    expiry: VecDeque<(u64, Vec<u8>)>,
    capacity: usize,
}

impl EarlyDataReplayCache {
    pub fn new() -> Self {
        Self::from_capacity(DEFAULT_REPLAY_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Result<Self, ReplayCacheError> {
        if capacity > MAX_REPLAY_CAPACITY {
            return Err(ReplayCacheError);
        }
        Ok(Self::from_capacity(capacity))
    }

    fn from_capacity(capacity: usize) -> Self {
        Self {
            seen: HashMap::new(),
            expiry: VecDeque::new(),
            capacity,
        }
    }

    fn register(&mut self, token: &[u8], now_ms: u64) -> bool {
        while self
            .expiry
            .front()
            .is_some_and(|(expires, _)| *expires <= now_ms)
        {
            let Some((expires, token)) = self.expiry.pop_front() else {
                break;
            };
            if self.seen.get(token.as_slice()) == Some(&expires) {
                self.seen.remove(token.as_slice());
            }
        }
        if token.len() > MAX_TOKEN_LEN
            || self.capacity == 0
            || self.seen.contains_key(token)
            || self.seen.len() == self.capacity
        {
            return false;
        }
        let expires = now_ms.saturating_add(REPLAY_WINDOW_MS);
        let token = token.to_vec();
        self.seen.insert(token.clone(), expires);
        self.expiry.push_back((expires, token));
        true
    }
}

impl Default for EarlyDataReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct SharedEarlyDataReplayCache(Rc<RefCell<EarlyDataReplayCache>>);

impl SharedEarlyDataReplayCache {
    pub fn new() -> Self {
        Self(Rc::new(RefCell::new(EarlyDataReplayCache::new())))
    }

    pub fn with_capacity(capacity: usize) -> Result<Self, ReplayCacheError> {
        Ok(Self(Rc::new(RefCell::new(
            EarlyDataReplayCache::with_capacity(capacity)?,
        ))))
    }
}

impl Default for SharedEarlyDataReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) struct EarlyDataReplayGuard {
    store: SharedEarlyDataReplayCache,
}

impl EarlyDataReplayGuard {
    pub(crate) fn new(store: SharedEarlyDataReplayCache) -> Self {
        Self { store }
    }
}

impl EarlyDataGuard for EarlyDataReplayGuard {
    fn register(&mut self, token: &[u8]) -> bool {
        self.store
            .0
            .borrow_mut()
            .register(token, WallClock::now_millis())
    }
}
