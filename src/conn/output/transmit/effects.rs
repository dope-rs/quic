use crate::conn::stream::state::transmit::log::journal::Entry;
use o3::buffer;

use std::mem;

use crate::conn::output::transmit::builder::pending;
use crate::stream;

/// Bitset describing frames committed by one output operation.
///
/// Values come from protected commit records after pending success.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct Effects(u8);

impl Effects {
    pub const ACK: Self = Self(1 << 0);
    pub const CRYPTO: Self = Self(1 << 1);
    pub const CONTROL: Self = Self(1 << 2);
    pub const STREAM: Self = Self(1 << 3);
    pub const DATAGRAM: Self = Self(1 << 4);
    pub const CLOSE: Self = Self(1 << 5);
    pub const PROBE: Self = Self(1 << 6);
    pub const FRESH_STREAM: Self = Self(1 << 7);

    pub(super) const EMPTY: Self = Self(0);

    pub const fn contains(self, effects: Self) -> bool {
        self.0 & effects.0 == effects.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub(super) fn insert(&mut self, effects: Self) {
        self.0 |= effects.0;
    }

    pub(super) fn packet<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>(
        pending: &pending::Packet<'_, DOMAIN, B, D>,
    ) -> Self {
        let plan = pending.plan();
        let mut effects = Self::EMPTY;
        if plan.flags.ack.is_included() {
            effects.insert(Self::ACK);
        }
        if pending.has_crypto() {
            effects.insert(Self::CRYPTO);
        }
        if !pending.controls().is_empty() {
            effects.insert(Self::CONTROL);
        }
        if !pending.streams().is_empty() {
            effects.insert(Self::STREAM);
        }
        if pending
            .streams()
            .iter()
            .any(|delivery| matches!(delivery, Entry::Fresh(_)))
        {
            effects.insert(Self::FRESH_STREAM);
        }
        if plan.flags.is_datagram() {
            effects.insert(Self::DATAGRAM);
        }
        if plan.flags.is_close() {
            effects.insert(Self::CLOSE);
        }
        if plan.flags.is_pto_probe() {
            effects.insert(Self::PROBE);
        }
        effects
    }
}

const _: () = assert!(mem::size_of::<Effects>() == 1);
