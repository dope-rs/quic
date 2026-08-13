use super::{Events, EventsControl};

// SAFETY: the control moves only test-owned timer state and cannot replace the
// protocol installed beneath the client.
unsafe impl dope_quic::client::raw::ControlProtocol for Events {
    type Control<'step>
        = EventsControl<'step>
    where
        Self: 'step;

    unsafe fn control<'step>(protocol: &'step mut Self) -> Self::Control<'step> {
        EventsControl(protocol)
    }
}
