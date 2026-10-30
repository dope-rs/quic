use o3::buffer::bytes::ChunksMut;
use std::{iter, num::NonZero};

/// Mutable UDP datagrams carried by one output allocation.
pub struct Segments<'a>(Inner<'a>);

enum Inner<'a> {
    One(Option<&'a mut [u8]>),
    Batch(ChunksMut<'a>),
}

impl<'a> Segments<'a> {
    pub(super) fn one(segment: &'a mut [u8]) -> Self {
        Self(Inner::One(Some(segment)))
    }

    pub(super) fn batch(segments: &'a mut [u8], size: NonZero<usize>) -> Self {
        Self(Inner::Batch(ChunksMut::new(segments, size)))
    }
}

impl<'a> Iterator for Segments<'a> {
    type Item = &'a mut [u8];

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            Inner::One(segment) => segment.take(),
            Inner::Batch(segments) => segments.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for Segments<'_> {
    fn len(&self) -> usize {
        match &self.0 {
            Inner::One(segment) => usize::from(segment.is_some()),
            Inner::Batch(segments) => segments.len(),
        }
    }
}

impl iter::FusedIterator for Segments<'_> {}
