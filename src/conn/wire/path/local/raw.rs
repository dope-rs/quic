use crate::conn;
use crate::conn::wire::path::local::{LocalCid, Phase, State};
use o3::{
    depot::{self, array},
    mem,
};

// SAFETY: successful encoding retained this original initialized metadata and
// generation under the packet's exclusive owner until publication.
unsafe impl depot::raw::Project<array::Index<{ conn::MAX_ACTIVE_CONNECTION_IDS }>> for &mut State {
    type Output = ();

    unsafe fn project(self, index: array::Index<{ conn::MAX_ACTIVE_CONNECTION_IDS }>) {
        let cell = &mut index.get_mut(&mut self.cids.slots).cid;
        let mut cid: mem::raw::Occupied<'_, LocalCid> =
            unsafe { depot::raw::Project::<_, LocalCid>::project(cell, ()) };
        let cid = cid.get_mut();
        if cid.phase == Phase::Awaiting {
            cid.phase = Phase::Available;
        }
        self.cids.largest_sent = self.cids.largest_sent.max(cid.sequence);
    }
}
