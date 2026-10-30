use std::time;

use crate::wire::packet::header::{self, widths};

use crate::{
    conn,
    wire::{frame, stream::Initiator},
};
use conn::wire::path;

mod check;
mod commit;
pub(in crate::conn::wire::ingress) mod ingest;
mod plan;
pub(in crate::conn) mod record;
pub(in crate::conn) mod sources;
mod streams;

pub(crate) use plan::CommitPermit;

#[derive(Clone, Copy)]
pub(super) struct PacketCid<'a> {
    pub(super) routed: Option<path::LocalCidKey>,
    pub(super) bytes: &'a [u8],
    pub(super) pto: time::Duration,
}

#[derive(Clone, Copy)]
pub(super) struct PacketMeta {
    identity: Identity,
    pub(super) now: time::Instant,
}

impl PacketMeta {
    pub(super) const fn new(kind: PacketKind, pn: header::Number, now: time::Instant) -> Self {
        Self {
            identity: Identity::new(kind, pn),
            now,
        }
    }

    pub(super) fn epoch(self) -> conn::Epoch {
        self.kind().epoch()
    }

    pub(super) fn kind(self) -> PacketKind {
        PacketKind((self.identity.0 >> Identity::KIND_SHIFT) as u8)
    }

    pub(super) const fn number(self) -> header::Number {
        header::Number::from_masked(self.identity.0)
    }
}

/// Authenticated packet kind and its bounded packet number in one machine
/// word. QUIC reserves exactly the upper two bits of every packet number, so
/// this representation preserves both proofs without another field.
#[derive(Clone, Copy)]
#[repr(transparent)]
struct Identity(u64);

impl Identity {
    const KIND_SHIFT: u32 = 62;

    const fn new(kind: PacketKind, number: header::Number) -> Self {
        Self(((kind.0 as u64) << Self::KIND_SHIFT) | number.get())
    }
}

/// Authenticated packet type, preserved independently from packet-number space.
/// In particular, 0-RTT and 1-RTT share a number space but not frame legality.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub(super) struct PacketKind(u8);

impl PacketKind {
    pub(super) const INITIAL: Self = Self(0);
    pub(super) const HANDSHAKE: Self = Self(1);
    pub(super) const ZERO_RTT: Self = Self(2);
    pub(super) const ONE_RTT: Self = Self(3);

    const fn epoch(self) -> conn::Epoch {
        match self.0 {
            0 => conn::Epoch::Initial,
            1 => conn::Epoch::Handshake,
            _ => conn::Epoch::Application,
        }
    }

    const fn is_app(self) -> bool {
        self.0 >= Self::ZERO_RTT.0
    }

    fn allows<Data, Ranges>(self, frame: &frame::Frame<Data, Ranges>, local: Initiator) -> bool {
        frame.kind().is_allowed(self.0, local)
    }
}

pub(super) enum Disposition {
    Commit,
    Drop,
}

pub(super) struct CommitState {
    lifecycle: conn::State,
    has_non_padding: bool,
    has_datagram: bool,
    notification_reserved: bool,
    pub(super) early_data_rejected: bool,
    pub(super) path_migrated: bool,
    pub(super) recovery_deadline_changed: bool,
    pub(super) recovery_deadline_requires_exact: bool,
}

impl CommitState {
    pub(super) fn new(state: conn::State) -> Self {
        Self {
            lifecycle: state,
            has_non_padding: false,
            has_datagram: false,
            notification_reserved: false,
            early_data_rejected: false,
            path_migrated: false,
            recovery_deadline_changed: false,
            recovery_deadline_requires_exact: false,
        }
    }

    pub(super) fn applied(&mut self, frames: &[record::FrameRecord<'_>], notified: bool) {
        self.has_non_padding = !frames.is_empty();
        self.has_datagram = frames
            .iter()
            .any(|frame| frame.admission() == record::Admission::Datagram);
        self.notification_reserved = notified;
    }

    pub(super) fn finish(self, state: conn::State) -> conn::Effects {
        let mut effects = conn::Effects::none();
        if self.has_non_padding {
            effects.insert(conn::Effects::OUTPUT);
        }
        if self.notification_reserved || self.has_datagram {
            effects.insert(conn::Effects::NOTIFY);
        }
        if state != self.lifecycle {
            effects.insert(conn::Effects::LIFECYCLE);
        }
        if self.early_data_rejected {
            effects.insert(conn::Effects::EARLY_DATA_REJECTED);
        }
        if self.path_migrated {
            effects.insert(conn::Effects::PATH);
        }
        if self.recovery_deadline_changed {
            effects.project(conn::DeadlineMode::Earlier);
        }
        if self.recovery_deadline_requires_exact || self.early_data_rejected {
            effects.project(conn::DeadlineMode::Exact);
        }
        effects
    }
}

/// Packet kind occupies padding already required by the packet number and timestamp.
const _: () =
    assert!(std::mem::size_of::<PacketMeta>() == std::mem::size_of::<(u64, time::Instant)>());
const _: () = {
    assert!(std::mem::size_of::<Identity>() == std::mem::size_of::<u64>());
    assert!(widths::MAX < 1_u64 << Identity::KIND_SHIFT);
    assert!(std::mem::size_of::<PacketKind>() == std::mem::size_of::<u8>());
    assert!(!std::mem::needs_drop::<PacketKind>());
    assert!(PacketKind::INITIAL.0 == 0);
    assert!(PacketKind::HANDSHAKE.0 == 1);
    assert!(PacketKind::ZERO_RTT.0 == 2);
    assert!(PacketKind::ONE_RTT.0 == 3);
};
