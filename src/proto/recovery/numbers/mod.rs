use crate::{
    conn,
    wire::{
        packet::{
            self,
            header::{self, widths},
        },
        varint,
    },
};
use packet::kind;
use std::{marker, mem, time};

pub(crate) mod count;
mod ranges;

pub(crate) use ranges::Iter;

trait AckAuthority {}

/// Any ACK debt may be carried by a packet which was already going out.
struct Carry;
/// Only debt whose immediate condition or deadline has fired may create a
/// standalone ACK packet.
struct Due;

impl AckAuthority for Carry {}
impl AckAuthority for Due {}

/// A packet kind which is allowed to carry an ACK for exactly one packet
/// number space. The sealed, zero-sized kind is shared with packet protection,
/// so selecting ACK state and sealing the packet cannot name different spaces.
pub(crate) trait AckSpace {
    const DELAYED: bool;
    const EPOCH: conn::Epoch;
}

impl AckSpace for kind::Initial {
    const DELAYED: bool = false;
    const EPOCH: conn::Epoch = conn::Epoch::Initial;
}

impl AckSpace for kind::Handshake {
    const DELAYED: bool = false;
    const EPOCH: conn::Epoch = conn::Epoch::Handshake;
}

impl AckSpace for kind::OneRtt {
    const DELAYED: bool = true;
    const EPOCH: conn::Epoch = conn::Epoch::Application;
}

/// Borrowed proof that an ACK is pending in packet kind `K`'s exact receive
/// space. Its lifetime freezes the receive window through range encoding.
#[must_use = "an ACK intent must be encoded or deliberately dropped"]
struct AckIntent<'space, K: AckSpace, Authority: AckAuthority> {
    ranges: ranges::AckView<'space>,
    commit: AckCommit,
    kind: marker::PhantomData<fn() -> (K, Authority)>,
}

impl<'space, K: AckSpace, Authority: AckAuthority> AckIntent<'space, K, Authority> {
    fn into_parts(self) -> (ranges::AckView<'space>, AckCommit) {
        (self.ranges, self.commit)
    }
}

pub(crate) struct PendingAck<'space, K: AckSpace>(AckIntent<'space, K, Carry>);
pub(crate) struct DueAck<'space, K: AckSpace>(AckIntent<'space, K, Due>);

impl<'space, K: AckSpace> PendingAck<'space, K> {
    pub(crate) fn into_parts(self) -> (ranges::AckView<'space>, AckCommit) {
        self.0.into_parts()
    }
}

impl<'space, K: AckSpace> DueAck<'space, K> {
    pub(crate) fn into_parts(self) -> (ranges::AckView<'space>, AckCommit) {
        self.0.into_parts()
    }
}

/// One-byte proof of the exact ACK space committed by a published packet.
#[derive(Default, PartialEq, Eq)]
#[repr(transparent)]
#[must_use = "an encoded ACK must be committed with its protected packet"]
pub(crate) struct AckCommit(Option<conn::Epoch>);

impl AckCommit {
    pub(crate) const NONE: Self = Self(None);

    const fn from_epoch(epoch: conn::Epoch) -> Self {
        Self(Some(epoch))
    }

    pub(crate) const fn is_included(&self) -> bool {
        self.0.is_some()
    }

    pub(crate) fn take(&mut self) -> Self {
        mem::replace(self, Self::NONE)
    }

    pub(crate) fn apply(self, spaces: &mut Spaces) {
        if let Some(epoch) = self.0 {
            epoch.bind_mut(&mut spaces.spaces).ack_debt = AckDebt::None;
            if epoch == conn::Epoch::Application {
                spaces.application_ack_deadline = None;
            }
        }
    }
}

#[derive(Default)]
pub struct PnSpace {
    pub next_pn: u64,
    pub largest_acked: Option<u64>,
    pub time_of_last_ack_eliciting: Option<time::Instant>,
}

/// Full packet number coupled to its shortest unambiguous RFC 9000 width.
#[derive(Eq, PartialEq)]
#[repr(transparent)]
#[must_use = "a packet-number candidate must be protected or deliberately dropped"]
pub(crate) struct Packet(widths::Encoding);

impl Packet {
    pub(crate) const fn full(&self) -> u64 {
        self.0.number().get()
    }

    pub(crate) const fn encoded_len(&self) -> u8 {
        self.0.len()
    }

    pub(crate) const fn encoding(&self) -> widths::Encoding {
        self.0
    }

    /// Returns the full packet number admitted by this encoding.
    pub(crate) const fn protected(&self) -> header::Number {
        self.0.number()
    }

    const fn wire_len(value: u64) -> Option<u8> {
        if value <= u8::MAX as u64 {
            Some(1)
        } else if value <= u16::MAX as u64 {
            Some(2)
        } else if value <= 0x00ff_ffff {
            Some(3)
        } else if value <= u32::MAX as u64 {
            Some(4)
        } else {
            None
        }
    }

    /// Implements RFC 9000 Appendix A.2 without floating point: before the
    /// first ACK the complete integer is encoded; afterwards `2 * unacked`
    /// must fit in the selected 1..=4 byte reconstruction window.
    const fn select_len(full: u64, acked: Option<u64>) -> Option<u8> {
        let Some(acked) = acked else {
            return Self::wire_len(full);
        };
        let Some(unacked) = full.checked_sub(acked) else {
            return None;
        };
        let Some(range) = unacked.checked_mul(2) else {
            return None;
        };
        Self::wire_len(range)
    }
}

/// Proof that one packet number has been irreversibly assigned to an AEAD
/// attempt. Dropping this value leaves a legal gap; it never rolls the space
/// back.
#[derive(Eq, PartialEq)]
#[repr(transparent)]
#[must_use = "a sealing packet number must finish protection or remain a burned gap"]
pub(crate) struct Sealing(Packet);

/// Exclusive auth over the exact next number of one send space.
#[must_use = "a bound packet number must begin sealing or be released"]
pub(crate) struct Next<'space> {
    space: &'space mut PnSpace,
    packet: Packet,
}

impl Next<'_> {
    pub(crate) fn release(self) -> Packet {
        self.packet
    }

    pub(crate) fn begin(self) -> Sealing {
        self.space.next_pn = self.packet.full() + 1;
        Sealing(self.packet)
    }
}

impl Sealing {
    pub(crate) const fn full(&self) -> u64 {
        self.0.full()
    }

    pub(crate) const fn protected(&self) -> header::Number {
        self.0.protected()
    }
}

impl PnSpace {
    pub(crate) const fn is_exhausted(&self) -> bool {
        self.next_pn > conn::MAX_PACKET_NUMBER
    }

    /// Snapshots the next send number only when QUIC's nonce bound and packet
    /// number reconstruction rule can both be satisfied.
    pub(crate) const fn next(&self) -> Option<Packet> {
        let number = match header::Number::new(self.next_pn) {
            Some(number) => number,
            None => return None,
        };
        let Some(width) = Packet::select_len(self.next_pn, self.largest_acked) else {
            return None;
        };
        let encoding = match widths::Encoding::new(number, width) {
            Some(encoding) => encoding,
            None => return None,
        };
        Some(Packet(encoding))
    }

    /// Burns a packet number immediately before entering AEAD protection.
    /// This is deliberately earlier than every encryption and publication
    /// failure: QUIC permits gaps, whereas nonce reuse is forbidden.
    pub(crate) fn bind(&mut self, packet: Packet) -> Result<Next<'_>, Packet> {
        if self.next_pn != packet.full() {
            return Err(packet);
        }
        Ok(Next {
            space: self,
            packet,
        })
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
enum AckDebt {
    #[default]
    None,
    Waiting,
    Ready,
}

#[derive(Default)]
pub(crate) struct Receive {
    packets: ranges::Window,
    pub(crate) largest_time: Option<time::Instant>,
    max_ack_delay_ms: u16,
    ack_debt: AckDebt,
    ack_delay_exponent: u8,
}

/// Dense receive spaces addressed only by typed ACK auth or closed `Epoch`.
#[repr(C)]
pub(crate) struct Spaces {
    pub(crate) spaces: [Receive; 3],
    application_ack_deadline: Option<time::Instant>,
}

impl Spaces {
    pub(crate) fn new(delay: u16, exponent: u8) -> Self {
        let mut spaces = [Receive::default(), Receive::default(), Receive::default()];
        let app = conn::Epoch::Application.bind_mut(&mut spaces);
        app.max_ack_delay_ms = delay;
        app.ack_delay_exponent = exponent;
        Self {
            spaces,
            application_ack_deadline: None,
        }
    }

    pub(crate) fn has_ack<K: AckSpace>(&self) -> bool {
        K::EPOCH.bind(&self.spaces).ack_debt != AckDebt::None
    }

    pub(crate) fn is_ack_ready<K: AckSpace>(&self, now: time::Instant) -> bool {
        let receive = K::EPOCH.bind(&self.spaces);
        if receive.ack_debt == AckDebt::None {
            return false;
        }
        if !K::DELAYED || receive.ack_debt == AckDebt::Ready {
            return true;
        }
        self.application_ack_deadline
            .is_some_and(|deadline| deadline <= now)
    }

    pub(crate) fn ack_deadline(&self) -> Option<time::Instant> {
        (conn::Epoch::Application.bind(&self.spaces).ack_debt == AckDebt::Waiting)
            .then_some(self.application_ack_deadline)
            .flatten()
    }

    pub(crate) fn pending_ack<K: AckSpace>(&self, now: time::Instant) -> Option<PendingAck<'_, K>> {
        if !self.has_ack::<K>() {
            return None;
        }
        self.ack_intent::<K, Carry>(now).map(PendingAck)
    }

    pub(crate) fn due_ack<K: AckSpace>(&self, now: time::Instant) -> Option<DueAck<'_, K>> {
        if !self.is_ack_ready::<K>(now) {
            return None;
        }
        self.ack_intent::<K, Due>(now).map(DueAck)
    }

    fn ack_intent<K: AckSpace, Authority: AckAuthority>(
        &self,
        now: time::Instant,
    ) -> Option<AckIntent<'_, K, Authority>> {
        let receive = K::EPOCH.bind(&self.spaces);
        let mut ranges = receive.packets.ack()?;
        if K::DELAYED {
            let received = receive.largest_time.unwrap_or(now);
            let micros = now.saturating_duration_since(received).as_micros()
                >> u32::from(receive.ack_delay_exponent);
            ranges.delay = varint::VarInt::saturate(micros);
        }
        Some(AckIntent {
            ranges,
            commit: AckCommit::from_epoch(K::EPOCH),
            kind: marker::PhantomData,
        })
    }

    /// Commits one admitted packet and updates the exact ACK debt owner.
    /// A changed schedule requires the mux deadline projection to be reconsidered.
    pub(crate) fn commit(
        &mut self,
        epoch: conn::Epoch,
        fresh: Fresh,
        elicits: bool,
        now: time::Instant,
    ) -> Schedule {
        let receive = epoch.bind_mut(&mut self.spaces);
        let order = receive.record(fresh, now);
        if !elicits {
            return Schedule::Same;
        }
        if epoch != conn::Epoch::Application {
            let changed = receive.ack_debt != AckDebt::Ready;
            receive.ack_debt = AckDebt::Ready;
            return if changed {
                Schedule::Changed
            } else {
                Schedule::Same
            };
        }

        match receive.ack_debt {
            AckDebt::None => {
                let delay = time::Duration::from_millis(u64::from(receive.max_ack_delay_ms));
                self.application_ack_deadline = Some(now.checked_add(delay).unwrap_or(now));
                receive.ack_debt = if order == Order::Gap || delay.is_zero() {
                    AckDebt::Ready
                } else {
                    AckDebt::Waiting
                };
                Schedule::Changed
            }
            AckDebt::Waiting => {
                receive.ack_debt = AckDebt::Ready;
                Schedule::Changed
            }
            AckDebt::Ready => Schedule::Same,
        }
    }

    pub(crate) fn discard(&mut self, epoch: conn::Epoch) {
        let receive = epoch.bind_mut(&mut self.spaces);
        let delay = receive.max_ack_delay_ms;
        let exponent = receive.ack_delay_exponent;
        *receive = Receive {
            max_ack_delay_ms: delay,
            ack_delay_exponent: exponent,
            ..Receive::default()
        };
        if epoch == conn::Epoch::Application {
            self.application_ack_deadline = None;
        }
    }
}

#[must_use = "a fresh packet number is meaningful only inside a receive txn"]
#[repr(transparent)]
pub(crate) struct Fresh(header::Number);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Order {
    Next,
    Gap,
}

pub(crate) enum Schedule {
    Same,
    Changed,
}

impl Receive {
    pub(crate) fn expected_pn(&self) -> u64 {
        self.packets.largest().map_or(0, |pn| pn.get() + 1)
    }

    pub(crate) fn admit(&self, pn: header::Number) -> Option<Fresh> {
        self.packets.is_fresh(pn).then_some(Fresh(pn))
    }

    fn record(&mut self, fresh: Fresh, now: time::Instant) -> Order {
        let pn = fresh.0;
        let prior = self.packets.largest();
        self.packets.insert(fresh);
        if prior.is_none_or(|largest| pn > largest) {
            self.largest_time = Some(now);
        }
        if prior.map_or(pn.get() == 0, |largest| largest.get() + 1 == pn.get()) {
            Order::Next
        } else {
            Order::Gap
        }
    }
}

/// Audits the normative packet-number width selector at compile time.
const _: () = {
    assert!(mem::size_of::<Packet>() == mem::size_of::<u64>());
    assert!(!mem::needs_drop::<Packet>());
    assert!(mem::size_of::<Sealing>() == mem::size_of::<u64>());
    assert!(!mem::needs_drop::<Sealing>());
    assert!(mem::size_of::<Next<'_>>() == 2 * mem::size_of::<u64>());
    assert!(!mem::needs_drop::<Next<'_>>());
    assert!(matches!(Packet::select_len(0, None), Some(1)));
    assert!(matches!(Packet::select_len(255, None), Some(1)));
    assert!(matches!(Packet::select_len(256, None), Some(2)));
    assert!(matches!(Packet::select_len(u32::MAX as u64, None), Some(4)));
    assert!(Packet::select_len(u32::MAX as u64 + 1, None).is_none());
    assert!(matches!(Packet::select_len(127, Some(0)), Some(1)));
    assert!(matches!(Packet::select_len(128, Some(0)), Some(2)));
    assert!(matches!(Packet::select_len(32_767, Some(0)), Some(2)));
    assert!(matches!(Packet::select_len(32_768, Some(0)), Some(3)));
    assert!(matches!(Packet::select_len(8_388_607, Some(0)), Some(3)));
    assert!(matches!(Packet::select_len(8_388_608, Some(0)), Some(4)));
    assert!(matches!(
        Packet::select_len(conn::MAX_PACKET_NUMBER, Some(conn::MAX_PACKET_NUMBER - 1)),
        Some(1)
    ));
};
const _: () = assert!(mem::size_of::<Fresh>() == mem::size_of::<u64>());
const _: () = assert!(!mem::needs_drop::<Fresh>());
const _: () = assert!(mem::size_of::<AckCommit>() == mem::size_of::<bool>());
const _: () = assert!(
    mem::size_of::<Spaces>()
        == mem::size_of::<[Receive; 3]>() + mem::size_of::<Option<time::Instant>>()
);
const _: () = assert!(mem::align_of::<Spaces>() == mem::align_of::<[Receive; 3]>());
