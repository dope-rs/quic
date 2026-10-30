use std::{
    mem,
    ops::{Deref, DerefMut},
};

use crate::conn;
use crate::conn::wire::path;
use crate::proto::recovery::{numbers, pmtud};
use crate::security::crypto::op;

pub(in crate::conn::output::transmit) struct Flags {
    pub(in crate::conn::output::transmit) ack: numbers::AckCommit,
    flags: u8,
}

const ACK_ELICITING: u8 = 1 << 0;
const IN_FLIGHT: u8 = 1 << 1;
const EARLY_DATA: u8 = 1 << 2;
const DATAGRAM: u8 = 1 << 3;
const CLOSE: u8 = 1 << 4;
const PTO_PROBE: u8 = 1 << 5;
const TRACKED: u8 = 1 << 6;
const QUEUED: u8 = 1 << 7;

pub(in crate::conn::output::transmit) struct Plan<N = op::Protected<numbers::Sealing>> {
    pub(in crate::conn::output::transmit) packet_number: N,
    body: Body,
}

pub(in crate::conn::output::transmit) struct Body {
    pub(in crate::conn::output::transmit) epoch: conn::Epoch,
    pub(in crate::conn::output::transmit) bytes: usize,
    pub(in crate::conn::output::transmit) flags: Flags,
    pub(in crate::conn::output::transmit) path: Path,
}

pub(in crate::conn::output::transmit) struct Path {
    pub(in crate::conn::output::transmit) pmtud_probe: Option<pmtud::Probe>,
    pub(in crate::conn::output::transmit) route: path::OutputRoute,
}

impl<N> Plan<N> {
    pub(in crate::conn::output::transmit) fn new(epoch: conn::Epoch, number: N) -> Self {
        Self {
            packet_number: number,
            body: Body {
                epoch,
                bytes: 0,
                flags: Flags {
                    ack: numbers::AckCommit::NONE,
                    flags: 0,
                },
                path: Path {
                    pmtud_probe: None,
                    route: path::OutputRoute::ACTIVE,
                },
            },
        }
    }

    pub(in crate::conn::output::transmit) fn try_number<M, O, E>(
        self,
        map: impl FnOnce(N) -> Result<(O, M), E>,
    ) -> Result<(O, Plan<M>), E> {
        let Self {
            packet_number: number,
            body,
        } = self;
        let (output, number) = map(number)?;
        Ok((
            output,
            Plan {
                packet_number: number,
                body,
            },
        ))
    }

    pub(in crate::conn::output::transmit) fn is_tracked(&self) -> bool {
        self.flags.is_set(TRACKED)
    }

    pub(in crate::conn::output::transmit) fn set_tracked(&mut self, enabled: bool) {
        self.flags.set(TRACKED, enabled);
    }

    pub(in crate::conn::output::transmit) fn is_queued(&self) -> bool {
        self.flags.is_set(QUEUED)
    }

    pub(in crate::conn::output::transmit) fn set_queued(&mut self, enabled: bool) {
        self.flags.set(QUEUED, enabled);
    }
}

impl Plan<numbers::Packet> {
    pub(in crate::conn::output::transmit) fn bind_number<'space>(
        self,
        space: &'space mut numbers::PnSpace,
    ) -> Result<Plan<numbers::Next<'space>>, Self> {
        let Self {
            packet_number: pn,
            body,
        } = self;
        match space.bind(pn) {
            Ok(pn) => Ok(Plan {
                packet_number: pn,
                body,
            }),
            Err(pn) => Err(Plan {
                packet_number: pn,
                body,
            }),
        }
    }
}

impl Plan<numbers::Next<'_>> {
    pub(in crate::conn::output::transmit) fn release(self) -> Plan<numbers::Packet> {
        let Self {
            packet_number: pn,
            body,
        } = self;
        Plan {
            packet_number: pn.release(),
            body,
        }
    }
}

impl<N> Deref for Plan<N> {
    type Target = Body;

    fn deref(&self) -> &Self::Target {
        &self.body
    }
}

impl<N> DerefMut for Plan<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.body
    }
}

impl Flags {
    fn is_set(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    fn set(&mut self, flag: u8, enabled: bool) {
        if enabled {
            self.flags |= flag;
        } else {
            self.flags &= !flag;
        }
    }

    pub(in crate::conn::output::transmit) fn is_eliciting(&self) -> bool {
        self.is_set(ACK_ELICITING)
    }

    pub(in crate::conn::output::transmit) fn set_elicit(&mut self, enabled: bool) {
        self.set(ACK_ELICITING, enabled);
    }

    pub(in crate::conn::output::transmit) fn is_in_flight(&self) -> bool {
        self.is_set(IN_FLIGHT)
    }

    pub(in crate::conn::output::transmit) fn set_flight(&mut self, enabled: bool) {
        self.set(IN_FLIGHT, enabled);
    }

    pub(in crate::conn::output::transmit) fn is_early(&self) -> bool {
        self.is_set(EARLY_DATA)
    }

    pub(in crate::conn::output::transmit) fn set_early(&mut self, enabled: bool) {
        self.set(EARLY_DATA, enabled);
    }

    pub(in crate::conn::output::transmit) fn is_datagram(&self) -> bool {
        self.is_set(DATAGRAM)
    }

    pub(in crate::conn::output::transmit) fn set_datagram(&mut self, enabled: bool) {
        self.set(DATAGRAM, enabled);
    }

    pub(in crate::conn::output::transmit) fn is_close(&self) -> bool {
        self.is_set(CLOSE)
    }

    pub(in crate::conn::output::transmit) fn set_close(&mut self, enabled: bool) {
        self.set(CLOSE, enabled);
    }

    pub(in crate::conn::output::transmit) fn is_pto_probe(&self) -> bool {
        self.is_set(PTO_PROBE)
    }

    pub(in crate::conn::output::transmit) fn set_probe(&mut self, enabled: bool) {
        self.set(PTO_PROBE, enabled);
    }
}

const _: () = assert!(mem::size_of::<Path>() == 2 * mem::size_of::<u64>());
const _: () = assert!(mem::size_of::<Plan<numbers::Sealing>>() == mem::size_of::<Plan>());
const _: () = assert!(
    mem::size_of::<Plan<numbers::Next<'_>>>() == mem::size_of::<Plan>() + mem::size_of::<usize>()
);
const _: () = assert!(!mem::needs_drop::<Plan>());
const _: () = assert!(mem::size_of::<Flags>() == 2);
