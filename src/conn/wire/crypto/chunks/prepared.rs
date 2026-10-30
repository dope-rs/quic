use std::{marker, mem};

use crate::conn::wire::crypto::chunks::Cursor;
use crate::wire::frame;

pub(in crate::conn) struct Prepared<'a, 'id> {
    state: Cursor<'a>,
    owner: marker::PhantomData<*mut &'id ()>,
}

const _: () = assert!(mem::size_of::<Prepared<'_, '_>>() == 2 * mem::size_of::<usize>());

impl<'a, 'id> Prepared<'a, 'id> {
    pub(super) const fn new(state: Cursor<'a>, _body: &frame::Body<'_, 'id>) -> Self {
        Self {
            state,
            owner: marker::PhantomData,
        }
    }

    pub(in crate::conn::wire) fn borrow(&mut self) -> Cursor<'_> {
        Cursor {
            next: &mut *self.state.next,
            parts: self.state.parts.as_deref_mut(),
        }
    }
}
