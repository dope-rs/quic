use o3::buffer;
use o3::depot::queue::{indexed::planes, links};
use o3::mem::slot;

use crate::{runtime::routing::registry, stream};

pub(super) struct Seed;

impl<C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    planes::Seed<slot::Storage<registry::Slot<C, DOMAIN, B, D, T>, registry::Epoch>> for Seed
{
    fn seed(
        &self,
        _: links::Index,
    ) -> slot::Storage<registry::Slot<C, DOMAIN, B, D, T>, registry::Epoch> {
        slot::Storage::new(registry::Epoch::default())
    }
}
