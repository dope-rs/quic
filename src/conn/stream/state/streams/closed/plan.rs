use o3::depot::capacity;

use crate::conn::{
    self,
    stream::{Count, state::streams::closed},
};

/// A validated one-allocation plan for every closed stream-half lane.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(in crate::conn) struct Plan(u32);

impl Plan {
    pub(in crate::conn) const fn new(limits: [Count; closed::LANES]) -> Self {
        const {
            assert!(conn::MAX_STREAMS <= closed::MAX_INTERVALS as u64);
            assert!(closed::LANES as u64 * conn::MAX_STREAMS <= u32::MAX as u64);
            assert!(closed::LANES as u64 * conn::MAX_STREAMS <= usize::MAX as u64);
        }
        let mut nodes = 0_usize;
        let mut index = 0;
        while index < limits.len() {
            let limit = limits[index].get();
            nodes += (limit != 0) as usize + limit.saturating_sub(1) / closed::MIN_KEYS;
            index += 1;
        }
        Self(nodes as u32)
    }

    pub(super) const fn capacity(self) -> capacity::Count {
        capacity::Count::new(self.0)
    }
}

const _: () = assert!(std::mem::size_of::<Plan>() == std::mem::size_of::<u32>());
