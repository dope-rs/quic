use o3::depot::map::{self, resident};

pub(super) struct Hash;

impl map::Hasher<resident::Id> for Hash {
    fn hash(&self, id: &resident::Id) -> u64 {
        let value = (id.get() ^ (id.get() >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        let value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}
