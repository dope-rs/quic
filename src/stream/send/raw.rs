use crate::stream::send;
use o3::{buffer, depot::capacity};

/// # Safety
/// Demand matches unchanged `into_parts` owners' wire/resident bytes; discarded empty buffers count zero.
/// Nonempty buffers need one segment/node; chains need their exact segment count and one node.
pub unsafe trait Batch<O: buffer::raw::Segment>: Sized {
    fn demand(&self) -> Result<send::Demand, send::Overflow>;
    fn into_parts(self) -> send::Parts<O>;
}

unsafe impl<O: buffer::raw::Segment> Batch<O> for send::Buffer<O> {
    fn demand(&self) -> Result<send::Demand, send::Overflow> {
        Ok(send::Demand::buffer(self))
    }

    fn into_parts(self) -> send::Parts<O> {
        send::Parts::new(self, None, send::Boundary::More)
    }
}

unsafe impl<O: buffer::raw::Segment> Batch<O> for send::Parts<O> {
    fn demand(&self) -> Result<send::Demand, send::Overflow> {
        let first = send::Demand::buffer(&self.first);
        let tail = match &self.tail {
            None => send::Demand::default(),
            Some(send::Tail::Buffer(buffer)) => send::Demand::buffer(buffer),
            Some(send::Tail::Chain(chain)) => send::Demand::new(
                chain.as_chain().len(),
                chain.as_chain().resident(),
                chain.as_chain().count().into_raw() as usize,
                capacity::Count::new(1),
            ),
        };
        first.try_add(tail)
    }

    fn into_parts(self) -> send::Parts<O> {
        self
    }
}
