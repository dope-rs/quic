use std::cell;
use std::collections;
use std::fmt;
use std::rc;

use shin::server::config;

const REPLAY_WINDOW_MS: u64 = 7_200_000;
const MAX_REPLAY_CAPACITY: usize = 65_536;
const DEFAULT_REPLAY_CAPACITY: usize = MAX_REPLAY_CAPACITY;
const MAX_TOKEN_LEN: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayCacheError {
    Capacity,
    Entropy,
}

impl fmt::Display for ReplayCacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Capacity => "early data replay capacity exceeds the supported maximum",
            Self::Entropy => "failed to create an early data replay domain",
        })
    }
}

impl std::error::Error for ReplayCacheError {}

#[derive(Debug)]
struct State {
    seen: collections::HashMap<Vec<u8>, u64>,
    expiry: collections::VecDeque<(u64, Vec<u8>)>,
    capacity: usize,
}

/// Lane-local replay protection that can be cloned across standalone QUIC
/// connections. Clones share both the replay store and its authenticated
/// ticket domain; the type remains `!Send` for thread-per-core runtimes.
#[derive(Clone, Debug)]
pub struct ReplayCache {
    state: rc::Rc<cell::RefCell<State>>,
    domain: shin::server::ReplayDomain,
}

impl ReplayCache {
    pub fn new() -> Result<Self, ReplayCacheError> {
        Self::from_capacity(DEFAULT_REPLAY_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Result<Self, ReplayCacheError> {
        if capacity > MAX_REPLAY_CAPACITY {
            return Err(ReplayCacheError::Capacity);
        }
        Self::from_capacity(capacity)
    }

    fn from_capacity(capacity: usize) -> Result<Self, ReplayCacheError> {
        let domain = shin::server::ReplayDomain::random().map_err(|_| ReplayCacheError::Entropy)?;
        Ok(Self {
            state: rc::Rc::new(cell::RefCell::new(State {
                seen: collections::HashMap::new(),
                expiry: collections::VecDeque::new(),
                capacity,
            })),
            domain,
        })
    }
}

impl State {
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

impl crate::conn::server::ReplayGuard for ReplayCache {
    fn replay_domain(&self) -> Option<shin::server::ReplayDomain> {
        Some(self.domain.clone())
    }
}

impl config::EarlyDataGuard for ReplayCache {
    fn register(&self, token: &[u8]) -> bool {
        self.state
            .borrow_mut()
            .register(token, crate::clock::WallClock::now_millis())
    }
}
