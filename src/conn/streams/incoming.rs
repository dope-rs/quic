use std::ops;

use o3::buffer::storage;

use crate::range_buffer;
use crate::stream;

pub(in crate::conn) trait Incoming<B: stream::ReceiveBuffer> {
    fn len(&self) -> usize;
    fn insert(
        self,
        stream: &mut stream::Receiver<B>,
        ranges: &mut range_buffer::Arena<B>,
        parts: &mut Vec<(u64, ops::Range<usize>)>,
        offset: u64,
        fin: bool,
    ) -> Result<(), stream::RecvError>;
}

pub(in crate::conn) struct Copied<'a>(pub(in crate::conn) &'a [u8]);

pub(in crate::conn) enum RetainedIncoming<'d> {
    Driver(stream::RecvBuffer<'d>),
    Compact {
        bytes: storage::Shared,
        original_len: usize,
    },
}

impl<B: stream::ReceiveBuffer> Incoming<B> for Copied<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn insert(
        self,
        stream: &mut stream::Receiver<B>,
        ranges: &mut range_buffer::Arena<B>,
        parts: &mut Vec<(u64, ops::Range<usize>)>,
        offset: u64,
        fin: bool,
    ) -> Result<(), stream::RecvError> {
        let len = u64::try_from(self.0.len()).map_err(|_| stream::RecvError::OffsetOverflow)?;
        offset
            .checked_add(len)
            .ok_or(stream::RecvError::OffsetOverflow)?;
        B::insert_copied(stream, ranges, parts, offset, self.0, fin)
    }
}

impl<'d> Incoming<stream::RecvBuffer<'d>> for RetainedIncoming<'d> {
    fn len(&self) -> usize {
        match self {
            Self::Driver(bytes) => bytes.len(),
            Self::Compact { original_len, .. } => *original_len,
        }
    }

    fn insert(
        self,
        stream: &mut stream::Receiver<stream::RecvBuffer<'d>>,
        ranges: &mut range_buffer::Arena<stream::RecvBuffer<'d>>,
        parts: &mut Vec<(u64, ops::Range<usize>)>,
        offset: u64,
        fin: bool,
    ) -> Result<(), stream::RecvError> {
        match self {
            Self::Driver(bytes) => stream.insert_retained(ranges, parts, offset, bytes, fin),
            Self::Compact {
                bytes,
                original_len,
            } => stream.insert_compact(ranges, parts, offset, original_len, bytes, fin),
        }
    }
}

impl<B: stream::ReceiveBuffer> Incoming<B> for B {
    fn len(&self) -> usize {
        self.as_ref().len()
    }

    fn insert(
        self,
        stream: &mut stream::Receiver<B>,
        ranges: &mut range_buffer::Arena<B>,
        parts: &mut Vec<(u64, ops::Range<usize>)>,
        offset: u64,
        fin: bool,
    ) -> Result<(), stream::RecvError> {
        stream.insert(ranges, parts, offset, self, fin)
    }
}
