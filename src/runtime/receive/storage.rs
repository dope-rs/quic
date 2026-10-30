use o3::buffer::{self, resident};

use crate::runtime::receive::Input;
use crate::stream;

/// Selects copied or retained packet admission without runtime dispatch.
pub trait Storage<'d, D: buffer::raw::Segment = resident::Shared<'d>>: Input<'d, D> {
    const RETAINS: bool;
}

impl<'d, D: buffer::raw::Segment> Storage<'d, D> for Vec<u8> {
    const RETAINS: bool = false;
}

impl<'d, D: buffer::raw::Segment, const ADAPTIVE: bool> Storage<'d, D>
    for stream::RecvBuffer<'d, ADAPTIVE>
{
    const RETAINS: bool = true;
}
