use crate::{
    conn::stream::resident::slot::{self, plane, store},
    wire::stream,
};
pub(in crate::conn) use canceled::Canceled;
pub(in crate::conn) use error::Error;
pub(in crate::conn) use fresh::Fresh;
pub(in crate::conn) use lease::Lease;
use std::marker;

mod canceled;
mod error;
mod fresh;
mod lease;

pub(in crate::conn) struct Pool<'a, 'id, S, V: slot::Reusable, A: Default, P: plane::Policy<S>> {
    pub(in crate::conn::stream::resident::slot::store::scope) pool: &'a mut store::Pool<S, V, A, P>,
    brand: marker::PhantomData<fn(&'id ()) -> &'id ()>,
}

impl<'a, 'id, S, V: slot::Reusable, A: Default, P: plane::Policy<S>> Pool<'a, 'id, S, V, A, P> {
    pub(in crate::conn::stream::resident::slot::store) fn new(
        pool: &'a mut store::Pool<S, V, A, P>,
    ) -> Self {
        Self {
            pool,
            brand: marker::PhantomData,
        }
    }

    pub(in crate::conn) fn bind(&mut self, raw: u32) -> Option<Lease<'id, S>> {
        let entry = self.pool.storage.bind_at(raw)?;
        Some(Lease::new(entry.node))
    }

    pub(in crate::conn) fn try_insert<R, E>(
        &mut self,
        id: slot::Id<S>,
        init: V::Init,
        recycle: impl slot::Recycle<Value = V>,
        prepare: impl FnOnce(&mut V) -> Result<R, E>,
    ) -> Result<(Fresh<'id, S>, R), Error<E>> {
        let mut entry = self.pool.storage.insert(id.id(), init).ok_or(Error::Full)?;
        match prepare(entry.get_mut()) {
            Ok(data) => Ok((
                Fresh {
                    lease: Lease::new(entry.node),
                },
                data,
            )),
            Err(error) => {
                entry.retire(&mut self.pool.plane, recycle);
                Err(Error::Preparation(error))
            }
        }
    }

    pub(in crate::conn) fn get(
        &mut self,
        lease: &Lease<'id, S>,
    ) -> (stream::Id, slot::Handle<S>, &mut V, &mut A) {
        // SAFETY: the invariant brand identifies this exclusive pool scope.
        // Only cancellation can retire an issued lease, consuming this scope.
        let node = unsafe { self.pool.storage.nodes.get_unchecked_mut(lease.index.get()) };
        (
            node.id,
            slot::Handle::new(lease.index.raw(), node.generation.get()),
            &mut node.value,
            &mut node.auxiliary,
        )
    }

    pub(in crate::conn) fn cancel(self) -> Canceled<'a, 'id, S, V, A, P> {
        Canceled { scope: self }
    }
}
