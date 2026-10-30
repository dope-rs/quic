pub(in crate::conn) mod closed;

use crate::wire::stream;

/// A stream identifier normalized so bit zero means local/peer, independent of endpoint role.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::conn) struct Relative(stream::Id);

impl Relative {
    pub(in crate::conn) const fn new(id: stream::Id, local: stream::Initiator) -> Self {
        Self(id.relative(local))
    }

    pub(in crate::conn) const fn number(self) -> u64 {
        self.0.number()
    }

    pub(in crate::conn) const fn is_local(self) -> bool {
        self.0.get() & 0x01 == 0
    }

    pub(in crate::conn) const fn direction(self) -> stream::Direction {
        self.0.direction()
    }
}

const _: () = assert!(size_of::<Relative>() == size_of::<u64>());
