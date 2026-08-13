use crate::client;

/// # Safety
/// `Control` cannot move, replace, or drop driver-branded protocol storage.
pub unsafe trait ControlProtocol: client::Protocol {
    type Control<'step>
    where
        Self: 'step;

    /// # Safety
    /// `protocol` must be the protocol installed beneath its live client and
    /// no client lifecycle phase may overlap the returned control.
    unsafe fn control<'step>(protocol: &'step mut Self) -> Self::Control<'step>;
}
