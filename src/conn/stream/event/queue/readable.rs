use o3::depot::queue::indexed::slab;

use crate::conn::stream::event::queue;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub(in crate::conn) struct Handle(pub(super) slab::Handle<queue::Domain>);
