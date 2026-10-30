pub mod frame;
mod packed;
pub mod packet;
#[doc(hidden)]
pub mod ranges;
pub mod stream;
pub mod varint;

#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mark {
    Clear,
    Set,
}

#[doc(hidden)]
pub use packed::Packed;

const _: () = {
    assert!(size_of::<Mark>() == size_of::<bool>());
    assert!(align_of::<Mark>() == align_of::<bool>());
};
