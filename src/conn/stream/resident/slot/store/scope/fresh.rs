use std::ops;

use crate::conn::stream::resident::slot::store::scope;

pub(in crate::conn) struct Fresh<'id, S> {
    pub(in crate::conn::stream::resident::slot::store::scope) lease: scope::Lease<'id, S>,
}

impl<'id, S> ops::Deref for Fresh<'id, S> {
    type Target = scope::Lease<'id, S>;

    fn deref(&self) -> &Self::Target {
        &self.lease
    }
}
