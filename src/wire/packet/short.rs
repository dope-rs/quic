use crate::wire::packet::header::widths;
use o3::{alloc, buffer::write};
use write::Sink as _;

use crate::wire::packet::{cid, header, kind, long};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reject {
    Underflow { actual: usize, required: usize },
    Type { first: u8 },
    Fixed { first: u8 },
}

pub(crate) struct Rejected<P> {
    packet: P,
    error: Reject,
}

impl<P> Rejected<P> {
    pub(crate) fn into_parts(self) -> (P, Reject) {
        (self.packet, self.error)
    }
}

pub(crate) struct Protected<P: long::Buffer> {
    packet: P,
    cid: cid::Len,
}

impl<P: long::Buffer> Protected<P> {
    pub(crate) fn parse(packet: P, cid_len: cid::Len) -> Result<Self, Rejected<P>> {
        let result = Self::validate(packet.as_ref(), cid_len);
        match result {
            Ok(()) => Ok(Self {
                packet,
                cid: cid_len,
            }),
            Err(error) => Err(Rejected { packet, error }),
        }
    }

    fn validate(bytes: &[u8], cid_len: cid::Len) -> Result<(), Reject> {
        let pn_at = cid_len.end();
        let Some(&first) = bytes.first() else {
            return Err(Reject::Underflow {
                actual: 0,
                required: 1,
            });
        };
        if first & super::FORM_LONG != 0 {
            return Err(Reject::Type { first });
        }
        if first & super::FIXED_BIT == 0 {
            return Err(Reject::Fixed { first });
        }
        if bytes.get(1..pn_at).is_none() {
            return Err(Reject::Underflow {
                actual: bytes.len(),
                required: pn_at,
            });
        }
        let end = pn_at + header::SAMPLE_END;
        if end > bytes.len() {
            return Err(Reject::Underflow {
                actual: bytes.len(),
                required: end,
            });
        }
        Ok(())
    }

    pub(crate) fn into_parts(self) -> (P, cid::Len) {
        (self.packet, self.cid)
    }
}

pub(crate) struct Ref<'wire> {
    dcid: cid::Ref<'wire>,
    encoding: widths::Encoding,
    key_phase: bool,
}

impl<'wire> Ref<'wire> {
    pub(crate) const fn new(
        dcid: cid::Ref<'wire>,
        encoding: widths::Encoding,
        phase: bool,
    ) -> Self {
        Self {
            dcid,
            encoding,
            key_phase: phase,
        }
    }

    pub(crate) fn encoded_len(&self) -> usize {
        1 + self.dcid.len() + usize::from(self.encoding.len())
    }

    pub(crate) fn append(
        &self,
        out: &mut write::Append<'_>,
    ) -> Result<header::Layout<kind::OneRtt>, alloc::Error> {
        let pn = self.encoding.number();
        let pn_len = self.encoding.len();
        out.write_slices([
            &[super::FIXED_BIT | (u8::from(self.key_phase) << 2) | (pn_len - 1)],
            self.dcid.into_slice(),
            &pn.get().to_be_bytes()[8 - usize::from(pn_len)..],
        ])?;
        Ok(header::Layout::new(self.encoding, 1 + self.dcid.len()))
    }

    pub(crate) fn encode_into<'out>(
        self,
        out: &'out mut Vec<u8>,
    ) -> Result<header::Ref<'out, kind::OneRtt>, alloc::Error> {
        let mut out = write::Append::new(out);
        let layout = self.append(&mut out)?;
        Ok(header::Ref::new(out.into_mut(), layout))
    }

    pub(crate) fn prefix<'out>(
        self,
        out: &'out mut Vec<u8>,
    ) -> Result<header::Prefix<'out>, alloc::Error> {
        out.clear();
        let layout = self.append(&mut write::Append::new(out))?;
        Ok(header::Prefix::new(out, layout))
    }
}
