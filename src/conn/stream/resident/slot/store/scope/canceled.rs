use crate::conn::stream::resident::slot::{self, plane, store::scope};

pub(in crate::conn) struct Canceled<'a, 'id, S, V: slot::Reusable, A: Default, P: plane::Policy<S>>
{
    pub(in crate::conn::stream::resident::slot::store::scope) scope:
        scope::Pool<'a, 'id, S, V, A, P>,
}

impl<'id, S, V: slot::Reusable, A: Default, P: plane::Policy<S>> Canceled<'_, 'id, S, V, A, P> {
    pub(in crate::conn) fn retire<R: slot::Recycle<Value = V>>(
        &mut self,
        fresh: scope::Fresh<'id, S>,
        recycle: R,
    ) {
        let pool = &mut self.scope.pool;
        slot::Occupied::new(&mut pool.storage, fresh.lease.index).retire(&mut pool.plane, recycle);
    }
}
