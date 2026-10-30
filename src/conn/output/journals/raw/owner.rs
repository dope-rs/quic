use o3::depot::array;

use crate::conn;
use crate::conn::output::journals;
use journals::{controls, streams};

/// # Safety
/// Projections retain the original table, controls and admitted stream scope; context consumes only its frozen input and cannot change bounds.
/// Only consuming commit drains affine selections; cancellation retains them unchanged, and publication empties the original lists.
pub(in crate::conn::output) unsafe trait Owner: Sized {
    type Control;
    type Context<'a>
    where
        Self: 'a;

    fn demand(&self) -> journals::Demand;

    fn parts(
        &mut self,
    ) -> (
        &mut journals::Table,
        &mut array::Vec<Self::Control, { conn::PACKET_CONTROL_CAPACITY }>,
        Self::Context<'_>,
    );

    fn write<'a>(
        entry: journals::Entry<'a>,
        controls: journals::Slots<'a, Self::Control, controls::Tag>,
        streams: journals::Supply<streams::Tag>,
        context: Self::Context<'a>,
    ) where
        Self: 'a;
}
