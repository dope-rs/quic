use crate::client;

/// Restricted coordinate view supplied by a client protocol.
///
/// # Safety
/// `Control` must not expose an operation that moves, replaces, or drops
/// driver-branded retained storage owned by the protocol.
pub unsafe trait ControlProtocol: client::Protocol {
    type Control<'step>
    where
        Self: 'step;

    /// # Safety
    /// `protocol` must be the protocol installed beneath its live client and
    /// no client lifecycle phase may overlap the returned control.
    unsafe fn control<'step>(protocol: &'step mut Self) -> Self::Control<'step>;
}
