use crate::security::crypto::output;
use std::{marker, num::NonZero};

use o3::buffer::pool::borrowed;
use o3::buffer::write::Sink as _;

use crate::{conn, proto::datagram, security::crypto, wire};
use conn::output::transmit;
use header::widths;
use packet::{header, kind};
use wire::{frame, packet};

/// A pooled packet retaining its slot, original payload and admitted header.
pub(crate) struct Prepared<'pool> {
    lease: borrowed::Frame<'pool>,
    layout: header::Layout<kind::OneRtt>,
}

impl<'pool> Prepared<'pool> {
    pub(crate) fn try_new(
        packet: datagram::Packet<'pool>,
        maximum: usize,
        mut header: header::Prefix<'_>,
    ) -> Result<
        Self,
        (
            datagram::Packet<'pool>,
            transmit::Admission<crypto::Dimensions>,
        ),
    > {
        let layout = header.layout();
        let width = widths::Width::from_pn(layout.encoding());
        let head = layout.pn_offset() + width.get();
        let plain = header.as_ref().len() - head + 1 + packet.len();
        let pad_len = header::Payload::padding(plain, width);
        let padded = plain + pad_len;
        let bytes = head + padded + conn::TAG_LEN;
        if bytes > maximum {
            return Err((
                packet,
                transmit::Admission::Datagram(datagram::Error::Maximum { bytes, maximum }),
            ));
        }
        let padding = [frame::TYPE_PADDING; header::SAMPLE_END - packet::TAG_LEN - 1];
        if let Err(error) = header.write_slices([&padding[..pad_len], &[0x30]]) {
            return Err((
                packet,
                transmit::Admission::Payload {
                    error,
                    requested: header.as_ref().len() + pad_len + 1,
                },
            ));
        }
        let (prefix, layout) = header.into_parts();
        let lease = match packet.lease.try_frame(prefix, conn::TAG_LEN) {
            Ok(lease) => lease,
            Err((lease, error)) => {
                return Err((
                    datagram::Packet { lease },
                    transmit::Admission::Datagram(datagram::Error::Storage(error)),
                ));
            }
        };
        Ok(Self { lease, layout })
    }

    pub(crate) fn reject(self) -> datagram::Packet<'pool> {
        datagram::Packet {
            lease: self.lease.into_slice(),
        }
    }

    pub(crate) fn protect<R>(
        mut self,
        seal: impl FnOnce(output::Packet<'_>) -> Result<R, crypto::Error>,
    ) -> Result<(datagram::Sealed<'pool>, R), crypto::Error> {
        let end = self.lease.payload_end();
        let result = seal(output::Packet {
            bytes: self.lease.as_mut_slice(),
            number: self.layout.number(),
            width: widths::Width::from_pn(self.layout.encoding()),
            offset: self.layout.pn_offset(),
            payload_end: end,
            borrow: marker::PhantomData,
            kind: marker::PhantomData,
        })?;
        Ok((datagram::Sealed::new(self.lease.freeze()), result))
    }
}

impl output::Extent for Prepared<'_> {
    /// The pooled frame retains its header and tag within one u32-sized slot.
    fn wire_len(&self) -> NonZero<usize> {
        NonZero::<usize>::MIN.saturating_add(self.lease.len() - 1)
    }
}

const _: () = assert!(size_of::<Prepared<'static>>() == 6 * size_of::<usize>());
