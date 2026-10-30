use std::mem;

use dope::runtime::random::HashSeed;
use o3::depot::{
    capacity,
    queue::{
        indexed::{lanes::runtime, planes::groups},
        links,
    },
};

use crate::{conn::wire::path::reset, runtime::mux};

const CAPACITY: usize = 2;

type Capacity = capacity::Limit<{ mux::MAX_CONNECTIONS }>;
type Rows = groups::Rows<Capacity, CAPACITY>;
type Buckets = groups::Buckets<Capacity, 4>;

pub(in crate::runtime) struct Reset {
    hasher: HashSeed,
}

impl Reset {
    pub(in crate::runtime) fn new(hasher: HashSeed) -> Self {
        Self { hasher }
    }

    pub(in crate::runtime) fn replace(
        &self,
        source: runtime::Group<'_, reset::Token, Rows, Buckets, links::List, CAPACITY>,
        tokens: [Option<reset::Token>; CAPACITY],
    ) {
        let vacant = source.clear();
        vacant.insert(tokens, |token| (self.hash(&token), token));
    }

    pub(in crate::runtime) fn hash(&self, token: &reset::Token) -> u64 {
        self.hasher.hash_bytes(token.as_slice())
    }
}

const _: () = {
    assert!(mem::size_of::<Reset>() == mem::size_of::<HashSeed>());
    assert!(!mem::needs_drop::<Reset>());
};
