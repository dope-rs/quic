use std::{marker, mem};

use crate::conn::stream::resident::slot;

pub(in crate::conn) struct Lease<'id, S> {
    pub(in crate::conn::stream::resident::slot::store::scope) index: slot::Index,
    brand: marker::PhantomData<fn(&'id S) -> &'id S>,
}

impl<'id, S> Lease<'id, S> {
    pub(in crate::conn::stream::resident::slot::store::scope) fn new(index: slot::Index) -> Self {
        Self {
            index,
            brand: marker::PhantomData,
        }
    }
}

const _: () = assert!(mem::size_of::<Lease<'static, ()>>() == mem::size_of::<u32>());
