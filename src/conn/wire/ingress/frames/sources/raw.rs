use std::{mem, num::NonZero};

use o3::alloc::{self, array::Block};

use crate::{errors::detail, stream};

/// # Safety
/// Every source prefix yields at most count items, and natural completion yields
/// exactly count. Preserve their order and any item borrows through cleanup.
pub(super) unsafe fn try_datagram<B: stream::Recv>(
    count: NonZero<usize>,
    entries: impl Iterator<Item = Result<B, detail::Backing>>,
) -> Result<Vec<B>, detail::Unavailable> {
    let count = count.get();
    let values = Block::<mem::MaybeUninit<B>, usize>::try_new(count, ()).map_err(|error| {
        detail::Unavailable::Allocation {
            error,
            requested: count,
        }
    })?;
    // SAFETY: the caller retains the exact source/count proof. Each successful
    // callback writes one final slot; o3 owns the initialized prefix and cleanup.
    let values = unsafe {
        alloc::raw::AssumeInit::try_map(values, entries, |slot, value| {
            Ok::<_, detail::Unavailable>(slot.insert(value.map_err(detail::Unavailable::Backing)?))
        })
    }?;
    Ok(values.into_vec())
}
