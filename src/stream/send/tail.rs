use o3::buffer::{self, segments};

use crate::stream::send;

/// One optional trailing storage owner in an atomic stream admission.
pub enum Tail<O: buffer::raw::Segment> {
    Buffer(send::Buffer<O>),
    Chain(segments::Many<O>),
}
