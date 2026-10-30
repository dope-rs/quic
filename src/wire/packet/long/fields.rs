use o3::buffer::write::{self, Sink as _};

use crate::wire::packet::header::widths;

use crate::wire::packet;
use crate::wire::packet::{cid, encode, header, kind};
use crate::{conn, wire::varint};

pub(crate) struct Fields<'wire> {
    pub(crate) version: u32,
    pub(crate) dcid: cid::Ref<'wire>,
    pub(crate) scid: cid::Ref<'wire>,
    pub(crate) token: Option<&'wire [u8]>,
    pub(crate) packet_number: widths::Encoding,
}

impl Fields<'_> {
    pub(in crate::wire::packet) fn try_header<'out, K: kind::Long>(
        self,
        out: &'out mut Vec<u8>,
        plain: usize,
    ) -> Result<header::Ref<'out, K>, encode::Error> {
        let token = match self.token {
            Some(bytes) => {
                let Some(size) = varint::VarInt::from_usize(bytes.len()) else {
                    return Err(encode::Error::Length {
                        field: encode::Length::Token,
                        actual: bytes.len(),
                        maximum: varint::VarInt::MAX,
                    });
                };
                size.pack()
            }
            None => Default::default(),
        };
        let width = widths::Width::from_pn(self.packet_number);
        let sealed = header::Payload::new(plain, width).get();
        let Some(tagged) = sealed.checked_add(conn::TAG_LEN) else {
            return Err(encode::Error::Overflow {
                field: encode::Length::Tagged,
                base: sealed,
                added: conn::TAG_LEN,
            });
        };
        let Some(total) = width.get().checked_add(tagged) else {
            return Err(encode::Error::Overflow {
                field: encode::Length::Packet,
                base: width.get(),
                added: tagged,
            });
        };
        let Some(length) = varint::VarInt::from_usize(total) else {
            return Err(encode::Error::Length {
                field: encode::Length::Packet,
                actual: total,
                maximum: varint::VarInt::MAX,
            });
        };
        let mut out = write::Append::new(out);
        let first = packet::FORM_LONG | packet::FIXED_BIT | K::TYPE | (width.get() as u8 - 1);
        let number = self.packet_number.number().get().to_be_bytes();
        let length = varint::pack_minimum(length, K::MIN_LENGTH_WIDTH);
        let slices = [
            &[first][..],
            &self.version.to_be_bytes(),
            &[self.dcid.length().get()],
            self.dcid.into_slice(),
            &[self.scid.length().get()],
            self.scid.into_slice(),
            token.as_ref(),
            self.token.unwrap_or_default(),
            length.as_ref(),
            &number[8 - width.get()..],
        ];
        out.write_slices(slices)
            .map_err(|error| encode::Error::Allocation {
                error,
                requested: slices.iter().map(|slice| slice.len()).sum(),
            })?;
        let pn_at = out.len() - width.get();
        Ok(header::Ref::new(
            out.into_mut(),
            header::Layout::new(self.packet_number, pn_at),
        ))
    }
}

const _: () = assert!(usize::BITS >= 64);
