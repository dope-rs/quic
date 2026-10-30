use std::{marker, num::NonZero};

use o3::buffer::write;

use crate::security::crypto::{self, output};
use crate::wire::{frame, packet};
use output::Extent;
use packet::{header, header::widths, kind, short};

/// An encoded header and append-only payload in their original allocation.
pub(crate) struct Draft<'packet> {
    bytes: write::Append<'packet>,
    layout: header::Layout<kind::OneRtt>,
}

impl<'packet> Draft<'packet> {
    pub(crate) fn try_new(
        out: write::Append<'packet>,
        header: short::Ref<'_>,
    ) -> Result<Self, crypto::Error> {
        let mut out = out.into_append();
        let layout = header
            .append(&mut out)
            .map_err(|error| crypto::Error::Allocation {
                error,
                base: out.start(),
                header: header.encoded_len(),
                body: 0,
                tag: 0,
            })?;
        Ok(Self { bytes: out, layout })
    }

    pub(crate) fn append(&mut self) -> write::Append<'_> {
        self.bytes.append()
    }

    pub(in crate::security::crypto) fn try_prepare(
        self,
    ) -> Result<
        output::Packet<'packet, kind::OneRtt, write::Append<'packet, { packet::TAG_LEN }>>,
        crypto::Error,
    > {
        let start = self.bytes.start();
        let width = widths::Width::from_pn(self.layout.encoding());
        let offset = self.layout.pn_offset();
        let head = offset + width.get();
        let plain = self.bytes.len() - head;
        let padding = header::Payload::padding(plain, width);
        let out = self.bytes;
        let out = out
            .try_tail::<{ packet::TAG_LEN }, 0>([], padding, frame::TYPE_PADDING)
            .map_err(|rejected| {
                let (out, error) = rejected.into_parts();
                out.rollback();
                crypto::Error::Allocation {
                    error,
                    base: start,
                    header: head,
                    body: plain + padding,
                    tag: packet::TAG_LEN,
                }
            })?;
        let end = out.len();
        Ok(output::Packet {
            bytes: out,
            number: self.layout.number(),
            width,
            offset,
            payload_end: end,
            borrow: marker::PhantomData,
            kind: marker::PhantomData,
        })
    }
}

impl Extent for Draft<'_> {
    /// The retained Vec prefix plus padding and tag is nonempty and below usize::MAX.
    fn wire_len(&self) -> NonZero<usize> {
        let width = widths::Width::from_pn(self.layout.encoding());
        let head = self.layout.pn_offset() + width.get();
        let body = header::Payload::new(self.bytes.len() - head, width).get();
        NonZero::<usize>::MIN.saturating_add(head + body + packet::TAG_LEN - 1)
    }
}

const _: () = {
    assert!(size_of::<Draft<'static>>() == 4 * size_of::<usize>());
    assert!(size_of::<Option<Draft<'static>>>() == size_of::<Draft<'static>>());
    assert!(!std::mem::needs_drop::<Draft<'static>>());
};
