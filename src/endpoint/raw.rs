use crate::mux;

/// Restricted coordinate view supplied by an endpoint handler.
///
/// # Safety
/// `Control` must not expose an operation that moves, replaces, or drops
/// driver-branded retained storage owned by the handler.
pub unsafe trait ControlHandler<'d, const ID: u8, B: crate::stream::ReceiveBuffer = Vec<u8>>:
    mux::Handler<ID, B>
{
    type Control<'step>
    where
        Self: 'step,
        'd: 'step;

    /// # Safety
    /// `handler` must be the handler installed beneath its live endpoint and
    /// no endpoint lifecycle phase may overlap the returned control.
    unsafe fn control<'step>(handler: &'step mut Self) -> Self::Control<'step>
    where
        'd: 'step;
}
