use o3::buffer::{self, hold, segments, write};

use crate::stream::{outbound, release, send};

/// One send-queue node retaining contiguous storage or a segment chain.
pub(crate) enum Node<O: buffer::raw::Segment> {
    Buffer(send::Buffer<O>),
    One(segments::Single<O>),
    Segments(segments::Many<O>),
}

pub(in crate::stream::outbound) struct Copied;

impl<O: buffer::raw::Segment> Node<O> {
    pub(in crate::stream) fn charge(&self) -> hold::Charge {
        match self {
            Self::Buffer(send::Buffer::Inline(_)) => hold::Charge::default(),
            Self::Buffer(buffer) => hold::Charge::from_owner(buffer.len(), buffer.resident()),
            Self::One(owner) => {
                hold::Charge::from_owner(owner.len().get(), buffer::Residency::resident(owner))
            }
            Self::Segments(owners) => hold::Charge::from(owners.as_chain()),
        }
    }

    pub(in crate::stream::outbound) fn len(&self) -> usize {
        match self {
            Self::Buffer(buffer) => buffer.len(),
            Self::One(owner) => owner.len().get(),
            Self::Segments(segments) => segments.len().get(),
        }
    }

    pub(in crate::stream::outbound) fn resident(&self) -> usize {
        match self {
            Self::Buffer(buffer) => buffer.resident(),
            Self::One(owner) => buffer::Residency::resident(owner),
            Self::Segments(segments) => buffer::Residency::resident(segments.as_chain()),
        }
    }

    pub(in crate::stream::outbound) fn owners(&self) -> usize {
        match self {
            Self::Buffer(buffer) => usize::from(!buffer.is_empty()),
            Self::One(_) => 1,
            Self::Segments(segments) => segments.as_chain().count().into_raw() as usize,
        }
    }

    pub(in crate::stream::outbound) fn copy<W: write::Sink>(
        &self,
        offset: usize,
        len: usize,
        out: &mut W,
    ) -> Result<Option<Copied>, W::Error> {
        let Some(end) = offset.checked_add(len) else {
            return Ok(None);
        };
        let bytes = match self {
            Self::Buffer(buffer) => buffer.as_slice(),
            Self::One(owner) => owner.as_ref().as_ref(),
            Self::Segments(segments) => {
                if end > segments.as_chain().len() {
                    return Ok(None);
                }
                let mut skip = offset;
                let mut left = len;
                for owner in segments.as_chain().segments() {
                    let bytes = owner.as_ref();
                    if skip >= bytes.len() {
                        skip -= bytes.len();
                        continue;
                    }
                    let bytes = &bytes[skip..];
                    let take = left.min(bytes.len());
                    out.write_slice(&bytes[..take])?;
                    left -= take;
                    skip = 0;
                    if left == 0 {
                        break;
                    }
                }
                return Ok(Some(Copied));
            }
        };
        let Some(bytes) = bytes.get(offset..end) else {
            return Ok(None);
        };
        out.write_slice(bytes)?;
        Ok(Some(Copied))
    }

    pub(in crate::stream) fn release<M: release::Mode>(
        self,
        buffers: &mut outbound::BufferCache,
    ) -> (outbound::Charge, M::Projection) {
        let proof = M::project(|| self.charge());
        let charge = outbound::Charge {
            resident_bytes: self.resident(),
            segments: self.owners(),
            ..outbound::Charge::default()
        };
        self.recycle_into(buffers);
        (charge, proof)
    }

    fn recycle_into(self, buffers: &mut outbound::BufferCache) {
        if let Self::Buffer(buffer) = self {
            buffer.recycle_into(buffers);
        }
    }
}

const _: () = {
    use o3::buffer::{resident, storage};
    assert!(size_of::<Node<storage::Shared>>() == 4 * size_of::<usize>());
    assert!(size_of::<Option<Node<storage::Shared>>>() == size_of::<Node<storage::Shared>>());
    assert!(size_of::<Node<resident::Shared<'static>>>() == 4 * size_of::<usize>());
    assert!(
        size_of::<Option<Node<resident::Shared<'static>>>>()
            == size_of::<Node<resident::Shared<'static>>>()
    );
};
