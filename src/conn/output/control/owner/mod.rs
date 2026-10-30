mod deferred;
mod key;
mod signal;
mod vacant;

pub(in crate::conn::output::control) const MAX: u32 = i32::MAX as u32;

pub(in crate::conn) use deferred::Deferred;
pub(in crate::conn) use key::Key;
pub(in crate::conn) use signal::Signal;
pub(in crate::conn) use vacant::Vacant;
