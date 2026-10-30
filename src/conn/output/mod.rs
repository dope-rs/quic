use std::collections;
use std::num::NonZero;
use std::time;

mod cc;
pub(in crate::conn) mod control;
mod count;
pub(in crate::conn) mod delivery;
mod derived;
pub(in crate::conn) mod journals;
pub mod recovery;
pub mod transmit;

pub use count::Count;
pub(super) use derived::Derived;

use crate::proto::recovery::{numbers, pmtud, rtt};
use crate::{errors, wire::varint};

use crate::conn;
use crate::conn::life::options;
use crate::conn::machine::storage::capacity;

pub(super) struct Setup {
    pub(super) packet_journal_capacity: capacity::Capacity<capacity::Packet>,
    pub(super) control_journal_capacity: capacity::Capacity<capacity::Control>,
    pub(super) stream_journal_capacity: capacity::Capacity<capacity::Stream>,
    pub(super) max_pmtu: pmtud::Maximum,
    pub(super) pending_datagrams_capacity: options::Capacity,
    pub(super) peer_address_validated: bool,
}

pub(super) struct Egress {
    pub(super) derived: Derived,
    pub(super) recovery: Recovery,
    pub(super) cc: cc::State,
    pub(super) datagrams: Datagram,
    pub(super) lifecycle: Lifecycle,
    pub(super) activity: Activity,
}

pub(super) struct Recovery {
    pub(super) spaces: [numbers::PnSpace; 3],
    pub(super) rtt: rtt::RttTracker,
    pub(super) timer: Timer,
    pub(super) probe: Probe,
    pub(super) peer_max_ack_delay: time::Duration,
    pub(super) streaks: [recovery::Streak; 3],
    pub(super) packet_journals: journals::Table,
}

pub(super) struct Timer {
    pub(super) idle: Option<time::Instant>,
    pub(super) loss: Option<time::Instant>,
    pub(super) pto_epoch: Option<conn::Epoch>,
}

pub(super) struct Probe {
    pub(super) count: PtoCount,
    pub(super) allowance: Allowance,
    pub(super) epoch: Option<conn::Epoch>,
}

pub(super) enum Consumption {
    Exhausted,
    Remaining,
    Drained,
}

#[derive(Clone, Copy, Default)]
#[repr(u8)]
pub(super) enum Allowance {
    #[default]
    Empty,
    One,
    Two,
}

impl Allowance {
    pub(super) const fn is_armed(self) -> bool {
        !matches!(self, Self::Empty)
    }

    pub(super) fn arm(&mut self) {
        *self = Self::Two;
    }

    pub(super) fn clear(&mut self) {
        *self = Self::Empty;
    }

    pub(super) fn consume(&mut self) -> Consumption {
        match self {
            Self::Empty => Consumption::Exhausted,
            Self::One => {
                *self = Self::Empty;
                Consumption::Drained
            }
            Self::Two => {
                *self = Self::One;
                Consumption::Remaining
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub(super) struct PtoCount(u8);

impl PtoCount {
    const MAX: u8 = 16;

    pub(super) fn increment(&mut self) {
        if self.0 < Self::MAX {
            self.0 += 1;
        }
    }

    pub(super) fn reset(&mut self) {
        self.0 = 0;
    }

    pub(super) const fn backoff(self) -> u32 {
        1u32 << self.0
    }
}

pub(super) struct Datagram {
    pub(super) pending_datagrams: collections::VecDeque<Vec<u8>>,
    pub(super) pending_datagrams_capacity: options::Capacity,
    bytes: usize,
}

impl Recovery {
    pub(super) fn in_flight(&self) -> Option<u64> {
        u64::try_from(self.packet_journals.flight()).ok()
    }
}

impl Datagram {
    pub(in crate::conn) fn try_push(
        &mut self,
        datagram: Vec<u8>,
    ) -> Result<(), errors::SendFailure<Vec<u8>>> {
        if self.pending_datagrams.len() >= self.pending_datagrams_capacity.get() {
            return Err(errors::SendFailure::Full(datagram));
        }
        let Some(next) = self.bytes.checked_add(datagram.len()) else {
            return Err(errors::SendFailure::Full(datagram));
        };
        if let Err(error) = self.pending_datagrams.try_reserve(1) {
            return Err(errors::SendFailure::Admission(
                datagram,
                transmit::Admission::Datagrams(error),
            ));
        }
        self.pending_datagrams.push_back(datagram);
        self.bytes = next;
        Ok(())
    }

    pub(in crate::conn) fn pop_front(&mut self) -> Option<Vec<u8>> {
        let len = self.pending_datagrams.front()?.len();
        let next = self.bytes.checked_sub(len)?;
        let datagram = self.pending_datagrams.pop_front()?;
        self.bytes = next;
        Some(datagram)
    }

    pub(in crate::conn) const fn bytes(&self) -> usize {
        self.bytes
    }
}

pub(super) struct Lifecycle {
    pub(super) pending_close: Option<PendingClose>,
    pub(super) state: conn::State,
    pub(super) sent_initial: bool,
    pub(super) handshake_confirmed: bool,
}

pub(super) struct Activity {
    pub(super) last_activity: Option<time::Instant>,
    pub(super) amplification_received: u64,
    pub(super) amplification_sent: u64,
    pub(super) ack_eliciting_sent_since_last_receive: bool,
    pub(super) peer_address_validated: bool,
}

#[repr(transparent)]
pub(super) struct AmpSent(u64);

impl Activity {
    pub(super) fn amp_credit(&self) -> u64 {
        if self.peer_address_validated {
            return u64::MAX;
        }
        let sent = self.amplification_sent;
        let room = u64::MAX - sent;
        let Some(auth) = self.amplification_received.checked_mul(3) else {
            return room;
        };
        auth.saturating_sub(sent).min(room)
    }

    pub(super) fn plan_amp(&self, bytes: NonZero<usize>) -> Option<AmpSent> {
        if self.peer_address_validated {
            return Some(AmpSent(self.amplification_sent));
        }
        let bytes = u64::try_from(bytes.get()).ok()?;
        (bytes <= self.amp_credit()).then(|| AmpSent(self.amplification_sent + bytes))
    }

    pub(super) fn commit_amp(&mut self, sent: AmpSent) {
        self.amplification_sent = sent.0;
    }
}

impl Egress {
    pub(super) fn new(setup: Setup) -> Self {
        Self {
            derived: Derived::default(),
            recovery: Recovery {
                spaces: Default::default(),
                rtt: rtt::RttTracker::default(),
                timer: Timer {
                    idle: None,
                    loss: None,
                    pto_epoch: None,
                },
                probe: Probe {
                    count: PtoCount::default(),
                    allowance: Allowance::default(),
                    epoch: None,
                },
                peer_max_ack_delay: time::Duration::ZERO,
                streaks: [recovery::Streak::default(); 3],
                packet_journals: journals::Table::new(
                    setup.packet_journal_capacity,
                    setup.control_journal_capacity,
                    setup.stream_journal_capacity,
                ),
            },
            cc: cc::State::new(setup.max_pmtu),
            datagrams: Datagram {
                pending_datagrams: collections::VecDeque::new(),
                pending_datagrams_capacity: setup.pending_datagrams_capacity,
                bytes: 0,
            },
            lifecycle: Lifecycle {
                pending_close: None,
                state: conn::State::Handshaking,
                sent_initial: false,
                handshake_confirmed: false,
            },
            activity: Activity {
                last_activity: None,
                amplification_received: 0,
                amplification_sent: 0,
                ack_eliciting_sent_since_last_receive: false,
                peer_address_validated: setup.peer_address_validated,
            },
        }
    }
}

#[derive(Clone)]
pub(super) enum PendingClose {
    Application {
        error_code: errors::Code,
        reason: Vec<u8>,
    },
    Transport {
        error_code: varint::VarInt,
        frame_type: varint::VarInt,
        reason: Vec<u8>,
    },
}

impl PendingClose {
    pub(super) fn application(code: errors::Code, reason: Vec<u8>) -> Self {
        Self::Application {
            error_code: code,
            reason,
        }
    }

    pub(super) fn transport(code: varint::VarInt, frame: varint::VarInt) -> Self {
        Self::Transport {
            error_code: code,
            frame_type: frame,
            reason: Vec::new(),
        }
    }
}

const _: () = assert!(std::mem::size_of::<journals::Packet>() == 48);
const _: () = assert!(std::mem::size_of::<AmpSent>() == std::mem::size_of::<u64>());
const _: () =
    assert!(std::mem::size_of::<Option<time::Instant>>() == std::mem::size_of::<time::Instant>());
/// Keeps split close variants within the former tagged-record layout.
const _: () = assert!(
    std::mem::size_of::<PendingClose>() <= std::mem::size_of::<(bool, u64, u64, Vec<u8>)>()
);
