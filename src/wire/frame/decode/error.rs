use o3::{alloc, buffer::write::consume};

use crate::wire::varint;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Fault(Fault),
    Allocation(alloc::Error),
}

impl From<Fault> for Error {
    fn from(fault: Fault) -> Self {
        Self::Fault(fault)
    }
}

impl From<alloc::Error> for Error {
    fn from(error: alloc::Error) -> Self {
        Self::Allocation(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    Underflow {
        offset: usize,
        actual: usize,
        required: usize,
    },
    VarInt {
        offset: usize,
        source: varint::Error,
    },
    BadType {
        value: u8,
    },
    AckCount {
        actual: u64,
        maximum: u64,
    },
    AckFirst {
        largest: u64,
        range: u64,
    },
    AckGap {
        previous_smallest: u64,
        gap: u64,
    },
    AckRange {
        largest: u64,
        range: u64,
    },
    AckStorage {
        body: usize,
        offset: usize,
        length: usize,
        maximum: usize,
    },
    InvalidConnectionId {
        sequence_number: u64,
        retire_prior_to: u64,
        length: usize,
    },
    ConnectionIdLength {
        sequence_number: u64,
        retire_prior_to: u64,
        source: consume::Error,
    },
    InvalidToken {
        length: usize,
    },
    InvalidLength {
        offset: u64,
        length: u64,
    },
    InvalidStreamCount {
        value: u64,
    },
}

impl Fault {
    pub(in crate::wire::frame) fn check_span(
        offset: varint::VarInt,
        len: varint::VarInt,
    ) -> Result<(), Self> {
        if offset.get() + len.get() > varint::VarInt::MAX {
            return Err(Self::InvalidLength {
                offset: offset.get(),
                length: len.get(),
            });
        }
        Ok(())
    }

    pub(in crate::wire::frame) const fn underflow(
        len: usize,
        offset: usize,
        required: usize,
    ) -> Self {
        Self::Underflow {
            offset,
            actual: len.saturating_sub(offset),
            required,
        }
    }
}
