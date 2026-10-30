use o3::{alloc, buffer::write::Sink};

use crate::wire::packet::{header, kind};

/// An encoded header whose bytes can only be extended until admission.
pub(crate) struct Prefix<'a> {
    out: &'a mut Vec<u8>,
    layout: header::Layout<kind::OneRtt>,
}

impl<'a> Prefix<'a> {
    pub(in crate::wire::packet) fn new(
        out: &'a mut Vec<u8>,
        layout: header::Layout<kind::OneRtt>,
    ) -> Self {
        Self { out, layout }
    }

    pub(crate) fn layout(&self) -> &header::Layout<kind::OneRtt> {
        &self.layout
    }

    pub(crate) fn into_parts(self) -> (&'a [u8], header::Layout<kind::OneRtt>) {
        (self.out, self.layout)
    }
}

impl AsRef<[u8]> for Prefix<'_> {
    fn as_ref(&self) -> &[u8] {
        self.out
    }
}

impl Sink for Prefix<'_> {
    type Error = alloc::Error;

    fn write_slice(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.out.write_slice(bytes)
    }

    fn write_slices<const N: usize>(&mut self, slices: [&[u8]; N]) -> Result<(), Self::Error> {
        self.out.write_slices(slices)
    }
}

const _: () = {
    assert!(size_of::<Prefix<'static>>() == 3 * size_of::<usize>());
    assert!(size_of::<Option<Prefix<'static>>>() == size_of::<Prefix<'static>>());
};
