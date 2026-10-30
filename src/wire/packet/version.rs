use crate::wire::packet::{cid, decode};
use o3::{
    alloc,
    buffer::{storage, write::Sink as _},
    mem::Rejected,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Packet(decode::Error),
    Version { actual: u32 },
    List { actual: usize, unit: usize },
    Zero { offset: usize },
}

/// Fields from a long header advertising an unsupported version.
pub(crate) struct Unsupported<'wire> {
    dcid: cid::Ref<'wire>,
    scid: cid::Ref<'wire>,
}

impl<'wire> Unsupported<'wire> {
    pub(crate) fn decode(wire: &'wire [u8]) -> Option<Self> {
        let first = *wire.first()?;
        if first & super::FORM_LONG == 0 || wire.len() < 7 {
            return None;
        }
        let version = u32::from_be_bytes(wire.get(1..5)?.try_into().ok()?);
        if version == 0 || version == super::QUIC_V1 {
            return None;
        }
        let ids = super::Ids::decode(wire).ok()?;
        Some(Self {
            dcid: ids.dcid(),
            scid: ids.scid(),
        })
    }

    pub(crate) fn encoded_len(&self) -> usize {
        11 + self.dcid.len() + self.scid.len()
    }

    /// Encodes a response with request CIDs swapped.
    pub(crate) fn encode(
        &self,
        storage: Vec<u8>,
        first: u8,
    ) -> Result<storage::NonEmpty<Vec<u8>>, (Vec<u8>, alloc::Error)> {
        let mut packet = storage::NonEmpty::try_push(storage, first | super::FORM_LONG)
            .map_err(Rejected::into_parts)?;
        if let Err(error) = packet.append().write_slices([
            &0_u32.to_be_bytes(),
            &[self.scid.length().get()],
            self.scid.as_ref(),
            &[self.dcid.length().get()],
            self.dcid.as_ref(),
            &super::QUIC_V1.to_be_bytes(),
        ]) {
            return Err((packet.into_storage(), error));
        }
        Ok(packet)
    }
}

/// A validated Version Negotiation borrowing its wire bytes.
pub struct Negotiation<'wire> {
    dcid: cid::Ref<'wire>,
    scid: cid::Ref<'wire>,
    versions: &'wire [u8],
}

impl<'wire> Negotiation<'wire> {
    pub fn decode(wire: &'wire [u8]) -> Result<Self, Error> {
        let Some(&first) = wire.first() else {
            return Err(Error::Packet(decode::Error::Underflow {
                actual: 0,
                required: 1,
            }));
        };
        if first & super::FORM_LONG == 0 {
            return Err(Error::Packet(decode::Error::Form { first }));
        }
        if wire.len() < 5 {
            return Err(Error::Packet(decode::Error::Underflow {
                actual: wire.len(),
                required: 5,
            }));
        }
        let actual = u32::from_be_bytes([wire[1], wire[2], wire[3], wire[4]]);
        if actual != 0 {
            return Err(Error::Version { actual });
        }
        let ids = super::Ids::decode(wire).map_err(Error::Packet)?;
        let Some(versions) = wire.get(ids.end()..) else {
            return Err(Error::Packet(decode::Error::Underflow {
                actual: wire.len(),
                required: ids.end(),
            }));
        };
        if versions.is_empty() || !versions.len().is_multiple_of(4) {
            return Err(Error::List {
                actual: versions.len(),
                unit: 4,
            });
        }
        for (index, encoded) in versions.as_chunks::<4>().0.iter().enumerate() {
            let actual = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
            if actual == 0 {
                return Err(Error::Zero {
                    offset: ids.end() + index * 4,
                });
            }
        }
        Ok(Self {
            dcid: ids.dcid(),
            scid: ids.scid(),
            versions,
        })
    }

    pub const fn dcid(&self) -> cid::Ref<'wire> {
        self.dcid
    }

    pub const fn scid(&self) -> cid::Ref<'wire> {
        self.scid
    }

    pub fn contains(&self, version: u32) -> bool {
        self.versions
            .as_chunks::<4>()
            .0
            .iter()
            .any(|encoded| *encoded == version.to_be_bytes())
    }
}
