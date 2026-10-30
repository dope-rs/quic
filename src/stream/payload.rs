use o3::buffer::storage::range;

use crate::stream;

/// The exact source owner or the original packet-body borrow.
pub enum Payload<'a, B> {
    Borrowed(&'a [u8]),
    Owned(B),
}

impl<'a, B: stream::Recv> Payload<'a, B> {
    pub(crate) fn layout(&self) -> stream::Layout {
        match self {
            Self::Borrowed(_) => stream::Layout::Full,
            Self::Owned(bytes) => bytes.layout(),
        }
    }

    pub(crate) fn try_slice(
        &self,
        extent: stream::Extent,
    ) -> Result<Payload<'a, stream::Projection<B>>, stream::Capacity> {
        Ok(match self {
            Self::Borrowed(bytes) => Payload::Borrowed(Self::slice(bytes, extent)?),
            Self::Owned(bytes) => Payload::Owned(bytes.try_slice(extent)?),
        })
    }

    pub(crate) fn try_project(
        self,
        extent: stream::Extent,
    ) -> Result<Payload<'a, stream::Projection<B>>, stream::Capacity> {
        Ok(match self {
            Self::Borrowed(bytes) => Payload::Borrowed(Self::slice(bytes, extent)?),
            Self::Owned(bytes) => Payload::Owned(bytes.try_project(extent)?),
        })
    }

    fn slice(bytes: &'a [u8], extent: stream::Extent) -> Result<&'a [u8], stream::Capacity> {
        let range = extent.range();
        bytes
            .get(range.clone())
            .ok_or_else(|| stream::Capacity::Range(range::Error::new(range, bytes.len())))
    }
}

impl<B: stream::Recv> Payload<'_, stream::Projection<B>> {
    pub(crate) fn try_owned(self) -> Result<stream::Projection<B>, stream::Capacity> {
        match self {
            Self::Borrowed(bytes) => Ok(stream::Projection::new(B::try_copy(bytes)?)),
            Self::Owned(bytes) => Ok(bytes),
        }
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Payload<'_, B> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes.as_ref(),
        }
    }
}
