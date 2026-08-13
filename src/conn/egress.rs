use std::collections;
use std::time;

use crate::new_reno;
use crate::pacer;
use crate::pmtud;
use crate::pn_space;
use crate::rtt;

use crate::conn;
use crate::conn::control;
use crate::conn::datagram;
use crate::conn::journal;
use crate::conn::path;
use control::Write as _;

const HANDSHAKE_DONE: u8 = 1 << 0;
const NEW_CONNECTION_IDS: u8 = 1 << 1;

/// Durable owner-local work that survives bounded-control backpressure.
/// Armed bits select owner maps for reconciliation; the steady state pays one
/// zero test while values remain with their natural owners.
#[derive(Default)]
#[repr(transparent)]
pub(super) struct DerivedControls(u8);

const _: () = assert!(std::mem::size_of::<DerivedControls>() == 1);

impl DerivedControls {
    pub(super) fn is_pending(&self) -> bool {
        self.0 != 0
    }

    pub(super) fn is_sendable(&self, path: &path::Path, control: &control::Pending) -> bool {
        let remaining = control.remaining_capacity();
        let handshake_done = control.handshake_done_control_slots();
        let local_cids = path.issued_local_cid_control_slots();
        self.0 & HANDSHAKE_DONE != 0 && handshake_done != 0 && handshake_done <= remaining
            || self.0 & NEW_CONNECTION_IDS != 0 && local_cids != 0 && local_cids <= remaining
    }

    pub(super) fn arm_established(&mut self, server: bool, local_cids: usize) {
        if server {
            self.0 |= HANDSHAKE_DONE;
        }
        if local_cids != 0 {
            self.0 |= NEW_CONNECTION_IDS;
        }
    }

    pub(super) fn arm_new_connection_ids(&mut self, local_cids: usize) {
        if local_cids != 0 {
            self.0 |= NEW_CONNECTION_IDS;
        }
    }

    pub(super) fn reconcile(&mut self, path: &mut path::Path, control: &mut control::Pending) {
        if self.0 == 0 {
            return;
        }

        if self.0 & HANDSHAKE_DONE != 0 {
            let slots = control.handshake_done_control_slots();
            if slots == 0 {
                self.0 &= !HANDSHAKE_DONE;
            } else if let Some(mut permit) = control.try_reserve(slots) {
                permit.handshake_done();
                self.0 &= !HANDSHAKE_DONE;
            }
        }

        if self.0 & NEW_CONNECTION_IDS != 0 {
            let slots = path.issued_local_cid_control_slots();
            if slots == 0 {
                self.0 &= !NEW_CONNECTION_IDS;
            } else if let Some(mut permit) = control.try_reserve(slots) {
                path.queue_issued_local_cids(&mut permit);
                self.0 &= !NEW_CONNECTION_IDS;
            }
        }
    }
}

pub(super) struct Setup {
    pub(super) packet_journal_capacity: usize,
    pub(super) control_journal_capacity: usize,
    pub(super) stream_journal_capacity: usize,
    pub(super) max_pmtu: u64,
    pub(super) datagram_congestion_control: datagram::CongestionControl,
    pub(super) pending_datagrams_capacity: usize,
    pub(super) peer_address_validated: bool,
}

pub(super) struct Egress {
    pub(super) derived_controls: DerivedControls,
    pub(super) spaces: [pn_space::PnSpace; 3],
    pub(super) rtt: rtt::RttTracker,
    pub(super) pto_count: u32,
    pub(super) loss_timer: Option<time::Instant>,
    pub(super) pto_probe_allowance: u8,
    pub(super) pto_probe_epoch: Option<conn::Epoch>,
    pub(super) packet_journals: journal::Table,
    pub(super) pending_datagrams: collections::VecDeque<Vec<u8>>,
    pub(super) pending_close: Option<PendingClose>,
    pub(super) cc: new_reno::NewReno,
    pub(super) pacer: pacer::Pacer,
    pub(super) pmtud: pmtud::Pmtud,
    pub(super) packet_ceiling: usize,
    pub(super) pmtud_probe_pn: Option<u64>,
    pub(super) datagram_congestion_control: datagram::CongestionControl,
    pub(super) pending_datagrams_capacity: usize,
    pub(super) last_activity: time::Instant,
    pub(super) amplification_received: u64,
    pub(super) amplification_sent: u64,
    pub(super) state: conn::State,
    pub(super) sent_initial: bool,
    pub(super) handshake_confirmed: bool,
    pub(super) ack_eliciting_sent_since_last_receive: bool,
    pub(super) peer_address_validated: bool,
}

impl Egress {
    pub(super) fn new(setup: Setup) -> Self {
        let Ok(packet_ceiling) = usize::try_from(setup.max_pmtu) else {
            unreachable!("connection setup validates the PMTU against usize")
        };
        Self {
            derived_controls: DerivedControls::default(),
            spaces: Default::default(),
            rtt: rtt::RttTracker::default(),
            pto_count: 0,
            loss_timer: None,
            pto_probe_allowance: 0,
            pto_probe_epoch: None,
            packet_journals: journal::Table::new(
                setup.packet_journal_capacity,
                setup.control_journal_capacity,
                setup.stream_journal_capacity,
            ),
            pending_datagrams: collections::VecDeque::new(),
            pending_close: None,
            cc: new_reno::NewReno::default(),
            pacer: pacer::Pacer::new(time::Instant::now()),
            pmtud: pmtud::Pmtud::new(setup.max_pmtu),
            packet_ceiling,
            pmtud_probe_pn: None,
            datagram_congestion_control: setup.datagram_congestion_control,
            pending_datagrams_capacity: setup.pending_datagrams_capacity,
            last_activity: time::Instant::now(),
            amplification_received: 0,
            amplification_sent: 0,
            state: conn::State::Handshaking,
            sent_initial: false,
            handshake_confirmed: false,
            ack_eliciting_sent_since_last_receive: false,
            peer_address_validated: setup.peer_address_validated,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct PendingClose {
    pub(super) is_application: bool,
    pub(super) error_code: u64,
    pub(super) frame_type: u64,
    pub(super) reason: Vec<u8>,
}
