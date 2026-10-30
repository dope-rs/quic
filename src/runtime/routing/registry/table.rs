use crate::runtime::mux;
use dope::runtime::random::HashSeed;
use o3::{
    alloc::{self, BoxSliceExt as _},
    depot::{capacity, queue::links},
};

pub(in crate::runtime) struct Table {
    heads: Box<[links::List]>,
    hasher: HashSeed,
}

impl Table {
    pub(in crate::runtime) fn try_new(
        max: capacity::Limit<{ mux::MAX_CONNECTIONS }>,
        hasher: HashSeed,
    ) -> Result<Self, alloc::Error> {
        Ok(Self {
            heads: Box::try_default(Self::bucket_count(max))?,
            hasher,
        })
    }

    pub(in crate::runtime) fn try_reserve(
        &mut self,
        max: capacity::Limit<{ mux::MAX_CONNECTIONS }>,
    ) -> Result<impl FnOnce() + '_, alloc::Error> {
        let heads = Box::try_default(Self::bucket_count(max))?;
        Ok(move || self.heads = heads)
    }

    fn bucket_count(max: capacity::Limit<{ mux::MAX_CONNECTIONS }>) -> usize {
        (max.get() * 2).next_power_of_two()
    }

    pub(in crate::runtime) fn hash(&self, value: &[u8]) -> u64 {
        self.hasher.hash(value)
    }

    pub(in crate::runtime) fn heads(&self) -> &[links::List] {
        &self.heads
    }
}
