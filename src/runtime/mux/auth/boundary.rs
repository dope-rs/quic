use crate::runtime::mux::auth::{Owned, Pooled};

pub trait Boundary {}

impl<R, E> Boundary for Owned<R, E> {}
impl<R, E> Boundary for Pooled<'_, R, E> {}
