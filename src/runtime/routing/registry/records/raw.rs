use o3::buffer;
use o3::depot::{
    self,
    index::{Initialized, Vacant},
    queue::links,
};
use o3::mem::{self, slot};

use crate::conn::wire::path::local::{Assigned, routes};
use crate::runtime::routing::registry::records::Slot;
use crate::{conn, stream};

/// The packed index retains this same parent row and an ordinal in 0..=8.
unsafe impl<'loan, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    depot::raw::Project<links::Index, slot::Storage<Assigned>> for &'loan Slot<C, DOMAIN, B, D, T>
{
    type Output = &'loan slot::Storage<Assigned>;

    unsafe fn project(self, index: links::Index) -> Self::Output {
        let ordinal = index.get() & 15;
        if ordinal == conn::MAX_ACTIVE_CONNECTION_IDS {
            &self.alias
        } else {
            unsafe {
                depot::raw::Proof::<_, Initialized<routes::raw::Nodes>>::new((&self.conn, ordinal))
            }
            .into()
        }
    }
}

/// The exclusive parent loan retains the same fixed cell through its projection.
unsafe impl<'loan, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    depot::raw::Project<links::Index, slot::Storage<Assigned>>
    for &'loan mut Slot<C, DOMAIN, B, D, T>
{
    type Output = &'loan mut slot::Storage<Assigned>;

    unsafe fn project(self, index: links::Index) -> Self::Output {
        let ordinal = index.get() & 15;
        if ordinal == conn::MAX_ACTIVE_CONNECTION_IDS {
            &mut self.alias
        } else {
            unsafe {
                depot::raw::Proof::<_, Initialized<routes::raw::Nodes>>::new((
                    &mut self.conn,
                    ordinal,
                ))
            }
            .into()
        }
    }
}

/// The selected fixed cell contains the retained Assigned, independently of local metadata.
unsafe impl<'loan, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    depot::raw::Project<links::Index, Assigned> for &'loan Slot<C, DOMAIN, B, D, T>
{
    type Output = &'loan Assigned;

    unsafe fn project(self, index: links::Index) -> Self::Output {
        let cell: &'loan slot::Storage<Assigned> = unsafe {
            depot::raw::Proof::<_, Initialized<slot::Storage<Assigned>>>::new((self, index))
        }
        .into();
        unsafe { depot::raw::Proof::<_, Initialized<Assigned>>::new((cell, ())) }.into()
    }
}

/// The operation retains initialized cell custody after topology loans have ended.
unsafe impl<'loan, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    depot::raw::Project<links::Index, Assigned> for &'loan mut Slot<C, DOMAIN, B, D, T>
{
    type Output = mem::raw::Occupied<'loan, Assigned>;

    unsafe fn project(self, index: links::Index) -> Self::Output {
        let cell: &'loan mut slot::Storage<Assigned> = unsafe {
            depot::raw::Proof::<_, Initialized<slot::Storage<Assigned>>>::new((self, index))
        }
        .into();
        unsafe { depot::raw::Proof::<_, Initialized<Assigned>>::new((cell, ())) }.into()
    }
}

/// The actual cell was admitted vacant and its private owner excluded all intervening writes.
unsafe impl<'loan, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    depot::raw::Project<links::Index, Vacant<Assigned>> for &'loan mut Slot<C, DOMAIN, B, D, T>
{
    type Output = mem::raw::Vacant<'loan, Assigned>;

    unsafe fn project(self, index: links::Index) -> Self::Output {
        let cell: &'loan mut slot::Storage<Assigned> = unsafe {
            depot::raw::Proof::<_, Initialized<slot::Storage<Assigned>>>::new((self, index))
        }
        .into();
        unsafe { depot::raw::Proof::<_, Initialized<Vacant<Assigned>>>::new((cell, ())) }.into()
    }
}
