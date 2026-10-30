use crate::wire::packet::header;
use std::{num, time};

use crate::{
    proto::recovery::pacer, proto::recovery::pmtud, proto::recovery::reno, proto::recovery::rtt,
};

/// Application-space packet number encoded as nonzero `pn + 1`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub(in crate::conn) struct Packet(num::NonZero<u64>);

impl Packet {
    pub(in crate::conn) fn from_epoch(
        epoch: crate::conn::Epoch,
        number: header::Number,
    ) -> Option<Self> {
        if epoch != crate::conn::Epoch::Application {
            return None;
        }
        Some(Self(num::NonZero::<u64>::MIN.saturating_add(number.get())))
    }
}

/// Couples one path's congestion, pacing, and discovered MTU transitions.
pub(in crate::conn) struct State {
    cc: reno::NewReno,
    pacer: pacer::Pacer,
    pmtud: pmtud::Pmtud,
    packet_ceiling: usize,
    probe: Option<(Packet, pmtud::Probe)>,
}

/// Read-only proto metrics projected from one path's congestion state.
#[derive(Clone, Copy)]
pub(in crate::conn) struct Metrics<'a> {
    state: &'a State,
}

impl State {
    pub(in crate::conn) fn new(max_pmtu: pmtud::Maximum) -> Self {
        let pmtud = pmtud::Pmtud::new(max_pmtu);
        let cc = reno::NewReno::new(pmtud.current());
        let pacer = pacer::Pacer::new(cc.window(), rtt::INITIAL_RTT, cc.mtu());
        Self {
            cc,
            pacer,
            pmtud,
            packet_ceiling: max_pmtu.get() as usize,
            probe: None,
        }
    }

    pub(in crate::conn) fn allows_send(&self, now: time::Instant, flight: u64) -> bool {
        self.cc.allows_send(flight) && self.pacer.allows_send(now)
    }

    pub(in crate::conn) fn has_window(&self, flight: u64) -> bool {
        self.cc.allows_send(flight)
    }

    pub(in crate::conn) fn deadline(&self, now: time::Instant) -> time::Instant {
        self.pacer.release_at().unwrap_or(now).max(now)
    }

    pub(in crate::conn) fn release(&self) -> Option<time::Instant> {
        self.pacer.release_at()
    }

    pub(in crate::conn) fn packet_sent(
        &mut self,
        bytes: u64,
        flight: bool,
        now: time::Instant,
        probe: Option<(Packet, pmtud::Probe)>,
    ) {
        if flight {
            self.pacer
                .packet_sent(bytes, now, self.cc.window(), self.cc.mtu());
        }
        if let Some((number, probe)) = probe {
            self.probe = Some((number, probe));
        }
    }

    pub(in crate::conn) fn packet_acked(
        &mut self,
        bytes: u64,
        sent: time::Instant,
        flight: bool,
        number: Option<Packet>,
    ) {
        self.cc.packet_acked(bytes, sent, flight);
        if let Some((_, probe)) = self.probe.take_if(|(tracked, _)| Some(*tracked) == number) {
            self.pmtud.probe_acked(probe);
            self.sync_mtu();
        }
    }

    pub(in crate::conn) fn packets_lost(&mut self, latest: time::Instant, now: time::Instant) {
        self.cc.packets_lost(latest, now);
    }

    /// Returns the tracked PMTU probe exempt from congestion reduction.
    /// Its journal still accounts for flight.
    pub(in crate::conn) fn packet_lost(&mut self, number: Packet) -> Option<pmtud::Probe> {
        let (_, probe) = self.probe.take_if(|(tracked, _)| *tracked == number)?;
        self.pmtud.probe_lost(probe);
        Some(probe)
    }

    pub(in crate::conn) fn collapse(&mut self) {
        self.cc.collapse();
    }

    /// Completes one feedback txn after every ACK/loss mutation and
    /// RTT sample have committed. Expensive rate division occurs exactly once
    /// per feedback batch, never once per emitted packet.
    pub(in crate::conn) fn finish(&mut self, now: time::Instant, rtt: time::Duration) {
        self.pacer
            .reconfigure(now, self.cc.window(), rtt, self.cc.mtu());
    }

    pub(in crate::conn) fn set_peer_max(&mut self, max: u64) -> Option<pmtud::Capped> {
        let capped = self.pmtud.cap(max)?;
        Some(capped)
    }

    pub(in crate::conn) fn restart_path(&mut self) {
        self.pmtud.restart_path();
        self.probe = None;
        self.cc = reno::NewReno::new(self.pmtud.current());
        self.pacer = pacer::Pacer::new(self.cc.window(), rtt::INITIAL_RTT, self.cc.mtu());
    }

    pub(in crate::conn) const fn metrics(&self) -> Metrics<'_> {
        Metrics { state: self }
    }

    fn sync_mtu(&mut self) {
        let current = self.pmtud.current();
        if self.cc.mtu() != current {
            self.cc.set_mtu(current);
        }
    }
}

impl Metrics<'_> {
    pub(in crate::conn) fn current_mtu(&self) -> u64 {
        self.state.pmtud.current()
    }

    pub(in crate::conn) fn next_probe(&self) -> Option<pmtud::Probe> {
        if self.state.probe.is_some() {
            return None;
        }
        self.state.pmtud.next_probe()
    }

    pub(in crate::conn) const fn ceiling(&self) -> usize {
        self.state.packet_ceiling
    }

    pub(in crate::conn) const fn window(&self) -> u64 {
        self.state.cc.window()
    }

    pub(in crate::conn) const fn slow_limit(&self) -> u64 {
        self.state.cc.threshold()
    }
}

const _: () = assert!(std::mem::size_of::<Option<Packet>>() == 8);
const _: () = assert!(pmtud::MAX_PMTU <= usize::MAX as u64);
/// Caps the per-path cached-rate state paid by every connection.
const _: () = assert!(std::mem::size_of::<State>() <= 160);
