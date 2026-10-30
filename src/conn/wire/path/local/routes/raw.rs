use crate::conn::wire::path::local::routes::{Completion, Prepared};
use crate::{conn, conn::wire::path::local, stream};
use o3::{buffer, depot, mem::slot};

/// The same selected metadata and issuance remain live, and the same CID
/// cell has been initialized and linked under the retained routing owner.
pub(crate) enum Published {}

/// The same selected metadata and issuance remain live, and the exact
/// selected CID cell remains vacant under the retained routing owner.
pub(crate) enum Deferred {}

// SAFETY: the publication proof retains the exact original local State,
// metadata generation, issuance, and completed publication. Only short
// disjoint token/secret loans escape, after all root topology mutation.
unsafe impl<'a, 'id, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    depot::raw::Project<Prepared<'id>, Published> for &'a mut conn::Connection<DOMAIN, B, D>
{
    type Output = Completion<'a>;

    unsafe fn project(self, prepared: Prepared<'id>) -> Self::Output {
        let state = &mut self.machine_mut().path.local;
        let slot = prepared.key().slot_index().get_mut(&mut state.cids.slots);
        let cid = unsafe { depot::raw::Project::<(), local::LocalCid>::project(&mut slot.cid, ()) };
        let issue =
            unsafe { depot::raw::Project::<(), local::Issuance>::project(&state.issuance, ()) };
        Completion {
            cid,
            secret: &issue.secret,
        }
    }
}

// SAFETY: the original routing owner retains the selected metadata and its
// still-vacant cell. Restoring exactly its consumed Issued changes only the
// existing pending bit; no CID, hook, or reset token is initialized.
unsafe impl<'id, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    depot::raw::Project<Prepared<'id>, Deferred> for &mut conn::Connection<DOMAIN, B, D>
{
    type Output = ();

    unsafe fn project(self, prepared: Prepared<'id>) {
        let state = &mut self.machine_mut().path.local;
        let mut issue =
            unsafe { depot::raw::Project::<(), local::Issuance>::project(&mut state.issuance, ()) };
        issue.get_mut().issues.insert(prepared.index);
    }
}
/// The original connection's fixed local ordinal is in 0..MAX_ACTIVE_CONNECTION_IDS.
/// This does not assert current metadata, generation, or node occupancy.
pub(crate) enum Nodes {}

// SAFETY: the retained directory or selected local key proves this ordinal
// in the same original connection. The actual node survives metadata
// retirement and generation changes until its directory unlink completes.
unsafe impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    depot::raw::Project<usize, Nodes> for &'a conn::Connection<DOMAIN, B, D>
{
    type Output = &'a slot::Storage<local::Assigned>;

    unsafe fn project(self, index: usize) -> Self::Output {
        let slots = &self.machine().path.local.cids.slots;
        let selected = unsafe { depot::raw::Project::<usize>::project(slots, index) };
        &selected.node
    }
}

// SAFETY: the same fixed-slot proof carries the original connection's
// exclusive loan. No metadata or generation predicate is added here;
// initialization and vacancy are proved by the consuming node operation.
unsafe impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    depot::raw::Project<usize, Nodes> for &'a mut conn::Connection<DOMAIN, B, D>
{
    type Output = &'a mut slot::Storage<local::Assigned>;

    unsafe fn project(self, index: usize) -> Self::Output {
        let slots = &mut self.machine_mut().path.local.cids.slots;
        let selected = unsafe { depot::raw::Project::<usize>::project(slots, index) };
        &mut selected.node
    }
}
