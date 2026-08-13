use crate::{Capture, CaptureControl};

// SAFETY: the control exposes only test-owned command state and cannot move
// or replace retained endpoint storage.
unsafe impl<'d, const ID: u8>
    dope_quic::endpoint::raw::ControlHandler<'d, ID, dope_quic::RecvBuffer<'d>> for Capture
{
    type Control<'step>
        = CaptureControl<'step>
    where
        Self: 'step,
        'd: 'step;

    unsafe fn control<'step>(handler: &'step mut Self) -> Self::Control<'step>
    where
        'd: 'step,
    {
        CaptureControl(handler)
    }
}
