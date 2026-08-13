use super::{CapturingControl, CapturingHandler};

// SAFETY: the control moves only test-owned command/timer state and cannot
// replace the handler installed beneath the endpoint.
unsafe impl<'d, const ID: u8> dope_quic::endpoint::raw::ControlHandler<'d, ID>
    for CapturingHandler
{
    type Control<'step>
        = CapturingControl<'step>
    where
        Self: 'step,
        'd: 'step;

    unsafe fn control<'step>(handler: &'step mut Self) -> Self::Control<'step>
    where
        'd: 'step,
    {
        CapturingControl(handler)
    }
}
