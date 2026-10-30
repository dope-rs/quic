use dope_quic::stream::send::{self, admit};
use dope_quic::wire::stream::Id;
use o3::buffer::storage;

pub struct Retain;

impl<W> admit::Commit<storage::Shared, W> for Retain {
    type Retained = (Id, send::Boundary, Vec<*const u8>);
    type Discarded = admit::Discard<W>;

    fn retained(self, admit: admit::Admission<'_, storage::Shared, W>) -> Self::Retained {
        (
            admit.source().id(),
            admit.boundary(),
            admit
                .retained()
                .map(|owner| owner.as_slice().as_ptr())
                .collect(),
        )
    }

    fn discarded(self, cause: admit::Discard<W>) -> Self::Discarded {
        cause
    }
}
