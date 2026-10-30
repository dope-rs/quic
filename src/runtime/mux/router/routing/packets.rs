use crate::runtime::routing::LocalRoute;
use crate::wire::packet::{self, long};

pub(in crate::runtime::mux) struct Header<'wire> {
    wire: &'wire [u8],
}

impl<'wire> Header<'wire> {
    pub(in crate::runtime::mux) fn new(wire: &'wire [u8]) -> Self {
        Self { wire }
    }

    pub(in crate::runtime::mux) fn is_initial(&self) -> bool {
        long::has_initial_form(self.wire)
            && self
                .wire
                .first()
                .is_some_and(|first| first & packet::FIXED_BIT != 0)
    }

    pub(in crate::runtime::mux) fn is_short(&self) -> bool {
        self.wire
            .first()
            .is_some_and(|first| first & 0x80 == 0 && first & packet::FIXED_BIT != 0)
    }

    pub(in crate::runtime::mux) fn len(&self) -> usize {
        self.wire.len()
    }

    pub(in crate::runtime::mux) fn dcid<L: LocalRoute>(&self) -> Option<&'wire [u8]> {
        let first = *self.wire.first()?;
        if first & 0x80 != 0 {
            let dcid_len = usize::from(*self.wire.get(5)?);
            self.wire.get(6..6usize.checked_add(dcid_len)?)
        } else {
            self.wire.get(1..1usize.checked_add(L::CONNECTION_ID_LEN)?)
        }
    }
}
