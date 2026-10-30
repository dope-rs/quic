use crate::{security::crypto, wire};
use crypto::{key::cipher, op, output};
pub(crate) use draft::Draft;
use header::widths;
use o3::buffer::write;
use packet::{header, kind};
pub(crate) use prepared::Prepared;
use std::{marker, num::NonZero, slice};
use wire::{frame, packet};

mod draft;
mod prepared;

/// Exact nonempty wire extent retained by one immutable protection input.
pub(crate) trait Extent {
    fn wire_len(&self) -> NonZero<usize>;
}

/// An exclusive packet owner retaining its admitted protection geometry.
pub(crate) struct Packet<'packet, K = kind::OneRtt, B = &'packet mut [u8]> {
    bytes: B,
    number: header::Number,
    width: widths::Width,
    offset: usize,
    payload_end: usize,
    borrow: marker::PhantomData<&'packet mut ()>,
    kind: marker::PhantomData<fn() -> K>,
}

impl<'packet> Packet<'packet> {
    pub(crate) const fn number(&self) -> u64 {
        self.number.get()
    }
}

impl<'packet> Packet<'packet> {
    pub(in crate::security::crypto) fn encrypt(
        mut self,
        key: &cipher::Cipher<op::Seal>,
    ) -> Result<op::Wire<'packet>, crypto::Error> {
        let tag = self.seal(key)?;
        // SAFETY: admission retains the initialized tag extent of this exact slice.
        unsafe {
            self.bytes
                .as_mut_ptr()
                .add(self.payload_end)
                .cast::<[u8; packet::TAG_LEN]>()
                .write(tag);
        }
        self.mask(key)?;
        Ok(op::Wire::new(self.bytes))
    }
}

impl<K: kind::Kind, B: AsMut<[u8]>> Packet<'_, K, B> {
    fn seal(
        &mut self,
        key: &cipher::Cipher<op::Seal>,
    ) -> Result<[u8; packet::TAG_LEN], crypto::Error> {
        let head_end = self.offset + self.width.get();
        let pointer = self.bytes.as_mut().as_mut_ptr();
        // SAFETY: the constructors retain these disjoint regions of this exact packet.
        unsafe {
            let head = slice::from_raw_parts(pointer, head_end);
            let body =
                slice::from_raw_parts_mut(pointer.add(head_end), self.payload_end - head_end);
            key.seal(self.number, head, body)
        }
    }

    fn mask(&mut self, key: &cipher::Cipher<op::Seal>) -> Result<(), crypto::Error> {
        let pointer = self.bytes.as_mut().as_mut_ptr();
        // SAFETY: admission and sealing establish the initialized sample and number extents.
        unsafe {
            let sample = &*pointer
                .add(self.offset + header::SAMPLE_OFFSET)
                .cast::<[u8; header::SAMPLE_LEN]>();
            let number = slice::from_raw_parts_mut(pointer.add(self.offset), self.width.get());
            key.mask(sample, &mut *pointer, number)
        }
    }
}

impl<'packet, K: kind::Kind> Packet<'packet, K, write::Append<'packet, { packet::TAG_LEN }>> {
    pub(in crate::security::crypto) fn try_append(
        out: write::Append<'packet>,
        body: header::Body<'_, '_, K>,
    ) -> Result<
        output::Packet<'packet, K, write::Append<'packet, { packet::TAG_LEN }>>,
        crypto::Error,
    > {
        let out = out.into_append();
        let start = out.start();
        let (head, layout, body) = body.into_parts();
        let width = widths::Width::from_pn(layout.encoding());
        let padding = header::Payload::padding(body.len(), width);
        let fail = |error| crypto::Error::Allocation {
            error,
            base: start,
            header: head.len(),
            body: body.len() + padding,
            tag: packet::TAG_LEN,
        };
        let out = out
            .try_tail([head, body], padding, frame::TYPE_PADDING)
            .map_err(|rejected| fail(rejected.into_parts().1))?;
        let end = out.len();
        Ok(Self {
            bytes: out,
            number: layout.number(),
            width,
            offset: layout.pn_offset(),
            payload_end: end,
            borrow: marker::PhantomData,
            kind: marker::PhantomData,
        })
    }
}

impl<'packet, K: kind::Kind> Packet<'packet, K, write::Append<'packet, { packet::TAG_LEN }>> {
    pub(in crate::security::crypto) fn encrypt(
        mut self,
        key: &cipher::Cipher<op::Seal>,
    ) -> Result<op::Wire<'packet, K>, crypto::Error> {
        let tag = match self.seal(key) {
            Ok(tag) => tag,
            Err(error) => {
                self.bytes.rollback();
                return Err(error);
            }
        };
        let mut packet: Packet<'_, K, _> = Packet {
            bytes: self.bytes.commit(&tag),
            number: self.number,
            width: self.width,
            offset: self.offset,
            payload_end: self.payload_end,
            borrow: marker::PhantomData,
            kind: marker::PhantomData,
        };
        if let Err(error) = packet.mask(key) {
            packet.bytes.rollback();
            return Err(error);
        }
        Ok(op::Wire::new(packet.bytes.into_mut()))
    }
}

const _: () = {
    assert!(size_of::<write::Append<'static, { packet::TAG_LEN }>>() == 2 * size_of::<usize>());
    assert!(size_of::<Packet<'static>>() == 6 * size_of::<usize>());
    assert!(
        size_of::<Packet<'static, kind::Initial, write::Append<'static, { packet::TAG_LEN }>>>()
            == 6 * size_of::<usize>()
    );
};
