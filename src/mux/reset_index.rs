use std::hash::{BuildHasher as _, RandomState};

use crate::conn::{Handle, path::StatelessResetToken};

const BUCKET_WIDTH: usize = 4;
const BUCKETS_PER_CONNECTION: usize = 4;

#[derive(Clone, Copy)]
struct Record {
    token: StatelessResetToken,
    handle: Handle,
}

#[derive(Default)]
struct Bucket {
    records: [Option<Record>; BUCKET_WIDTH],
}

/// Fixed-storage, fixed-probe reverse index for peer stateless-reset tokens.
///
/// A lookup examines two independently keyed buckets and therefore performs
/// at most `2 * BUCKET_WIDTH` token comparisons. Insertion reports saturation
/// instead of probing farther or growing storage on the packet path.
pub(super) struct ResetIndex {
    buckets: Box<[Bucket]>,
    first: RandomState,
    second: RandomState,
    len: usize,
}

impl ResetIndex {
    pub(super) fn with_connection_capacity(connections: usize) -> Self {
        let bucket_count = connections
            .max(1)
            .checked_mul(BUCKETS_PER_CONNECTION)
            .and_then(usize::checked_next_power_of_two)
            .expect("validated connection capacity fits the reset index");
        Self {
            buckets: std::iter::repeat_with(Bucket::default)
                .take(bucket_count)
                .collect(),
            first: RandomState::new(),
            second: RandomState::new(),
            len: 0,
        }
    }

    pub(super) fn insert(&mut self, token: StatelessResetToken, handle: Handle) -> bool {
        let [first, second] = self.bucket_indices(token);
        for bucket in [first, second] {
            if let Some(record) = self.buckets[bucket]
                .records
                .iter()
                .flatten()
                .find(|record| record.token == token)
            {
                return record.handle == handle;
            }
        }

        let target = [first, second]
            .into_iter()
            .min_by_key(|&bucket| self.occupied(bucket))
            .expect("two reset buckets");
        let Some(record) = self.buckets[target]
            .records
            .iter_mut()
            .find(|record| record.is_none())
        else {
            return false;
        };
        *record = Some(Record { token, handle });
        self.len += 1;
        true
    }

    pub(super) fn get(&self, token: StatelessResetToken) -> Option<Handle> {
        let [first, second] = self.bucket_indices(token);
        [first, second].into_iter().find_map(|bucket| {
            self.buckets[bucket]
                .records
                .iter()
                .flatten()
                .find(|record| record.token == token)
                .map(|record| record.handle)
        })
    }

    pub(super) fn remove(&mut self, token: StatelessResetToken, handle: Handle) -> bool {
        let [first, second] = self.bucket_indices(token);
        for bucket in [first, second] {
            let Some(record) = self.buckets[bucket].records.iter_mut().find(|record| {
                record.is_some_and(|record| record.token == token && record.handle == handle)
            }) else {
                continue;
            };
            *record = None;
            self.len -= 1;
            return true;
        }
        false
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    fn occupied(&self, bucket: usize) -> usize {
        self.buckets[bucket]
            .records
            .iter()
            .filter(|record| record.is_some())
            .count()
    }

    fn bucket_indices(&self, token: StatelessResetToken) -> [usize; 2] {
        let mask = self.buckets.len() - 1;
        let first = self.first.hash_one(token) as usize & mask;
        let mut second = self.second.hash_one(token) as usize & mask;
        if second == first {
            second = (second + 1) & mask;
        }
        [first, second]
    }
}
