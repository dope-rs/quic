use crate::wire::packet::{self, cid, decode, long};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Prefix<'wire> {
    pub version: u32,
    pub dcid: cid::Ref<'wire>,
    pub scid: cid::Ref<'wire>,
    pub length: usize,
}

impl<'wire> Prefix<'wire> {
    pub fn decode(input: &'wire [u8]) -> Result<Self, decode::Error> {
        let layout = long::decode_plain(input, long::Type::ZeroRtt)?;
        Ok(Self {
            version: packet::QUIC_V1,
            dcid: layout.ids.dcid(),
            scid: layout.ids.scid(),
            length: layout.length,
        })
    }
}
