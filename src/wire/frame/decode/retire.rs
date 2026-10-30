use crate::wire::{frame::decode::error, varint};

/// An announcement sequence whose retirement threshold does not exceed it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Retire {
    sequence: varint::VarInt,
    prior: varint::VarInt,
}

impl Retire {
    pub(super) fn try_new(
        sequence: varint::VarInt,
        prior: varint::VarInt,
        length: usize,
    ) -> Result<Self, error::Fault> {
        if prior > sequence {
            return Err(error::Fault::InvalidConnectionId {
                sequence_number: sequence.get(),
                retire_prior_to: prior.get(),
                length,
            });
        }
        Ok(Self { sequence, prior })
    }

    pub(crate) fn into_parts(self) -> (varint::VarInt, varint::VarInt) {
        (self.sequence, self.prior)
    }
}
