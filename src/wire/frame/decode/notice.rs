use crate::wire::{frame, frame::decode, packet::cid, varint};
use o3::buffer::write::Sink;

use crate::wire::frame::decode::cursor::Cursor;
use decode::error;

/// A nonempty bounded connection ID and its reset token.
#[derive(Clone, PartialEq, Eq)]
pub struct Notice<C> {
    id: C,
    token: [u8; 16],
}

impl<'wire> Notice<cid::Ref<'wire>> {
    pub(super) fn decode(
        cursor: &mut Cursor<'wire>,
        sequence: varint::VarInt,
        prior: varint::VarInt,
    ) -> Result<(Self, decode::Retire), error::Fault> {
        let [width] = *cursor.array::<1>()?;
        let length = usize::from(width);
        if length == 0 {
            return Err(error::Fault::InvalidConnectionId {
                sequence_number: sequence.get(),
                retire_prior_to: prior.get(),
                length,
            });
        }
        let retire = decode::Retire::try_new(sequence, prior, length)?;
        let bytes = cursor.bytes(length, length + 16)?;
        let id = cid::Ref::new(bytes).map_err(|source| error::Fault::ConnectionIdLength {
            sequence_number: sequence.get(),
            retire_prior_to: prior.get(),
            source,
        })?;
        let token = *cursor.array::<16>()?;
        Ok((Self { id, token }, retire))
    }

    pub(crate) fn into_owned(self) -> Notice<cid::Id> {
        Notice {
            id: self.id.into_owned(),
            token: self.token,
        }
    }
}

impl<C> Notice<C> {
    pub fn id(&self) -> &C {
        &self.id
    }

    pub(crate) fn into_parts(self) -> (C, [u8; 16]) {
        (self.id, self.token)
    }
}

impl<C: AsRef<[u8]>> Notice<C> {
    pub(in crate::wire::frame) fn encode<W: Sink>(
        &self,
        out: &mut W,
        retire: decode::Retire,
    ) -> Result<(), W::Error> {
        let id = self.id.as_ref();
        let (sequence, prior) = retire.into_parts();
        out.write_slices([
            &[frame::TYPE_NEW_CONNECTION_ID],
            sequence.pack().as_ref(),
            prior.pack().as_ref(),
            &[id.len() as u8],
            id,
            &self.token,
        ])
    }
}
