use o3::depot::queue::indexed::keyed;

use crate::conn::output::control;
use control::{
    encode::Selected,
    journal::{self, State},
};
/// A zero-allocation selection view tied to the pending-control owner.
#[repr(transparent)]
pub(in crate::conn) struct Cursor<'a, const MASK: u16> {
    current: keyed::Iter<journal::Lane<'a>, (), true>,
}

impl<'a, const MASK: u16> Cursor<'a, MASK> {
    pub(in crate::conn::output::control) fn new(pending: &'a control::Pending) -> Option<Self> {
        Some(Self {
            current: keyed::Iter::new(journal::Lane::new(pending, MASK)?),
        })
    }
}

impl<'a, const MASK: u16> Iterator for Cursor<'a, MASK> {
    type Item = Selected<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let probe = self.current.source().probe();
            if let Some(live) = self.current.next_entry() {
                let (_, handle, entry) = journal::Lane::project(live);
                return Some(Selected::new(handle, entry, State::Ready, probe));
            }
            self.current = keyed::Iter::new(self.current.source().next()?);
        }
    }
}

const _: () = {
    assert!(
        std::mem::size_of::<Cursor<'static, { control::PREFIX }>>()
            == 3 * std::mem::size_of::<usize>()
    );
    assert!(
        std::mem::size_of::<Option<Cursor<'static, { control::PREFIX }>>>()
            == 3 * std::mem::size_of::<usize>()
    );
};
