use crate::wire::packet::header::widths;

use crate::wire::packet::{self, cid, decode, encode, header, kind, long};

#[derive(PartialEq, Eq)]
pub struct Header {
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub packet_number: u64,
    pub pn_len: u8,
}

impl Header {
    pub fn encode(&self, plain: usize) -> Result<header::Encoded<kind::Initial>, encode::Error> {
        let dcid = cid::Ref::new(&self.dcid).map_err(|cause| encode::Error::Cid {
            field: encode::Cid::Destination,
            cause,
        })?;
        let scid = cid::Ref::new(&self.scid).map_err(|cause| encode::Error::Cid {
            field: encode::Cid::Source,
            cause,
        })?;
        let Some(number) = header::Number::new(self.packet_number) else {
            return Err(encode::Error::Number {
                actual: self.packet_number,
                maximum: widths::MAX,
            });
        };
        let Some(number) = widths::Encoding::new(number, self.pn_len) else {
            return Err(encode::Error::Width {
                actual: self.pn_len,
                minimum: 1,
                maximum: widths::MAX_LEN,
            });
        };
        let mut out = Vec::new();
        let head = long::Fields {
            version: self.version,
            dcid,
            scid,
            token: Some(&self.token),
            packet_number: number,
        }
        .try_header::<kind::Initial>(&mut out, plain)?;
        let (_, layout) = head.into_parts();
        Ok(header::Encoded::new(out, layout))
    }
}

impl<'wire> Prefix<'wire> {
    pub fn decode(input: &'wire [u8]) -> Result<Self, decode::Error> {
        let layout = long::decode_initial(input)?;
        Ok(Self {
            version: packet::QUIC_V1,
            dcid: layout.ids.dcid(),
            scid: layout.ids.scid(),
            token: layout.token(),
            length: layout.length,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Prefix<'wire> {
    pub version: u32,
    pub dcid: cid::Ref<'wire>,
    pub scid: cid::Ref<'wire>,
    pub token: &'wire [u8],
    pub length: usize,
}
