use crate::wire::{frame::ack::ranges, varint};
use o3::buffer::write::Sink;

/// ACK range traversal supported by frame encoding.
#[doc(hidden)]
pub trait Storage {
    #[doc(hidden)]
    fn encode_pairs<W: Sink>(&self, out: &mut W) -> Result<(), W::Error>;
}

impl Storage for Vec<(varint::VarInt, varint::VarInt)> {
    fn encode_pairs<W: Sink>(&self, out: &mut W) -> Result<(), W::Error> {
        self.as_slice().encode_pairs(out)
    }
}

impl Storage for &[(varint::VarInt, varint::VarInt)] {
    fn encode_pairs<W: Sink>(&self, out: &mut W) -> Result<(), W::Error> {
        for &(gap, range) in *self {
            out.write_slices([gap.pack().as_ref(), range.pack().as_ref()])?;
        }
        Ok(())
    }
}

impl Storage for ranges::Set<'_> {
    fn encode_pairs<W: Sink>(&self, out: &mut W) -> Result<(), W::Error> {
        for (gap, range) in self.clone() {
            out.write_slices([gap.pack().as_ref(), range.pack().as_ref()])?;
        }
        Ok(())
    }
}
