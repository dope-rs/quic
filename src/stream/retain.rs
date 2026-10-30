use crate::errors::detail;
use std::ops;

use o3::buffer::{
    self, Complete as _,
    bytes::bounded,
    storage::{self, provided},
};

use crate::stream;

pub trait Retain<'d> {
    fn try_get<const ADAPTIVE: bool>(
        &self,
        range: ops::Range<usize>,
    ) -> Result<stream::RecvBuffer<'d, ADAPTIVE>, detail::Retention>;
}

impl<'d> Retain<'d> for storage::Shared<Option<provided::Account<'d>>> {
    fn try_get<const ADAPTIVE: bool>(
        &self,
        range: ops::Range<usize>,
    ) -> Result<stream::RecvBuffer<'d, ADAPTIVE>, detail::Retention> {
        let view = buffer::View::new(self)
            .try_get(range)
            .map_err(detail::Retention::Range)?;
        let bytes = view.try_retain().map_err(detail::Retention::Retain)?;
        Ok(stream::RecvBuffer::retained(bytes))
    }
}

impl<'d> Retain<'d> for bounded::Value<storage::Shared<Option<provided::Account<'d>>>> {
    fn try_get<const ADAPTIVE: bool>(
        &self,
        range: ops::Range<usize>,
    ) -> Result<stream::RecvBuffer<'d, ADAPTIVE>, detail::Retention> {
        let view = self
            .view()
            .try_get(range)
            .map_err(detail::Retention::Range)?;
        let bytes = view.try_retain().map_err(detail::Retention::Retain)?;
        Ok(stream::RecvBuffer::bounded(bytes))
    }
}
