use o3::buffer::resident;

use crate::stream;

mod input;
mod storage;

pub(in crate::runtime) use input::Input;
#[doc(hidden)]
pub use storage::Storage;

/// Statically selects packet ownership across runtime proto boundaries.
pub trait Policy {
    type Buffer<'d>: Storage<'d, resident::Shared<'d>>;
}

#[derive(Clone, Copy, Default)]
pub struct Copied;

impl Policy for Copied {
    type Buffer<'d> = Vec<u8>;
}

#[derive(Clone, Copy, Default)]
pub struct Adaptive;

impl Policy for Adaptive {
    type Buffer<'d> = stream::RecvBuffer<'d>;
}

#[derive(Clone, Copy, Default)]
pub struct Retained;

impl Policy for Retained {
    type Buffer<'d> = stream::RecvBuffer<'d, false>;
}

const _: () = {
    assert!(std::mem::size_of::<Copied>() == 0);
    assert!(std::mem::size_of::<Adaptive>() == 0);
    assert!(std::mem::size_of::<Retained>() == 0);
};
