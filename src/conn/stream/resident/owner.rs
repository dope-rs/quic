use std::mem;

use crate::conn::stream::resident::{Handle, Local};
use crate::runtime::brand;

/// Zero-size resident auth for one lexical connection access.
#[derive(Clone, Copy)]
pub struct Owner<'conn> {
    _brand: brand::Token<'conn>,
}

impl<'conn> Owner<'conn> {
    pub(in crate::conn) const fn new(brand: brand::Token<'conn>) -> Self {
        Self { _brand: brand }
    }

    pub(in crate::conn) const fn handle(self, local: Local) -> Handle<'conn> {
        Handle::new(local)
    }
}

const _: () = {
    assert!(mem::size_of::<Owner<'static>>() == 0);
    assert!(mem::align_of::<Owner<'static>>() == 1);
    assert!(!mem::needs_drop::<Owner<'static>>());
};
