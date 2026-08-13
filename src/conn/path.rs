use std::{num, ops};

use o3::collections::fixed::array;
use subtle::ConstantTimeEq as _;

use crate::packet;

use crate::conn;
use crate::conn::control;
use crate::conn::control::Write as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct StatelessResetToken([u8; 16]);

impl StatelessResetToken {
    pub(crate) fn new(bytes: [u8; 16]) -> Option<Self> {
        (bytes != [0; 16]).then_some(Self(bytes))
    }

    pub(crate) fn from_datagram(datagram: &[u8]) -> Option<Self> {
        if datagram.len() < 21 {
            return None;
        }
        let mut bytes = [0; 16];
        bytes.copy_from_slice(&datagram[datagram.len() - 16..]);
        Self::new(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct LocalCidKey(num::NonZeroU64);

impl LocalCidKey {
    fn new(slot: usize, generation: u32) -> Option<Self> {
        let slot = u32::try_from(slot).ok()?.checked_add(1)?;
        num::NonZeroU64::new((u64::from(generation) << 32) | u64::from(slot)).map(Self)
    }

    pub(crate) const fn slot(self) -> usize {
        ((self.0.get() as u32) - 1) as usize
    }

    const fn generation(self) -> u32 {
        (self.0.get() >> 32) as u32
    }
}

#[derive(Clone, Copy)]
pub(crate) enum RouteUpdate {
    Add {
        key: LocalCidKey,
        cid: packet::ConnectionId,
    },
    Remove(LocalCidKey),
}

pub(crate) const MAX_ROUTE_UPDATES: usize = conn::MAX_ACTIVE_CONNECTION_IDS * 2;

#[repr(transparent)]
#[derive(Clone, Copy)]
pub(crate) struct RouteUpdates(array::CopyInline<RouteUpdate, MAX_ROUTE_UPDATES>);

impl RouteUpdates {
    fn new() -> Self {
        Self(array::CopyInline::new())
    }
}

impl ops::Deref for RouteUpdates {
    type Target = array::CopyInline<RouteUpdate, MAX_ROUTE_UPDATES>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ops::DerefMut for RouteUpdates {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

struct LocalCid {
    sequence: u64,
    id: packet::ConnectionId,
    reset_token: [u8; 16],
    control: Option<control::OwnerKey<control::kind::NewConnectionId>>,
}

struct LocalCidSlot {
    generation: u32,
    cid: Option<LocalCid>,
}

struct LocalCidSet {
    slots: Vec<LocalCidSlot>,
    next_sequence: u64,
    largest_sent: u64,
    active: u8,
    target: u8,
}

impl LocalCidSet {
    fn new(initial: packet::ConnectionId) -> Self {
        let mut slots = Vec::with_capacity(conn::MAX_ACTIVE_CONNECTION_IDS);
        slots.push(LocalCidSlot {
            generation: 0,
            cid: Some(LocalCid {
                sequence: 0,
                id: initial,
                reset_token: [0; 16],
                control: None,
            }),
        });
        Self {
            slots,
            next_sequence: 1,
            largest_sent: 0,
            active: 1,
            target: 1,
        }
    }

    fn key(&self, index: usize) -> Option<LocalCidKey> {
        let slot = self.slots.get(index)?;
        slot.cid.as_ref()?;
        LocalCidKey::new(index, slot.generation)
    }

    fn resolve(&self, key: LocalCidKey) -> Option<&LocalCid> {
        let slot = self.slots.get(key.slot())?;
        (slot.generation == key.generation())
            .then_some(slot.cid.as_ref())
            .flatten()
    }

    fn find_sequence(&self, sequence: u64) -> Option<(LocalCidKey, &LocalCid)> {
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            let cid = slot.cid.as_ref().filter(|cid| cid.sequence == sequence)?;
            Some((LocalCidKey::new(index, slot.generation)?, cid))
        })
    }

    fn insert(&mut self, cid: LocalCid) -> Option<LocalCidKey> {
        let index = match self.slots.iter().position(|slot| slot.cid.is_none()) {
            Some(index) => index,
            None if self.slots.len() < conn::MAX_ACTIVE_CONNECTION_IDS => {
                self.slots.push(LocalCidSlot {
                    generation: 0,
                    cid: None,
                });
                self.slots.len() - 1
            }
            None => return None,
        };
        let slot = &mut self.slots[index];
        slot.cid = Some(cid);
        self.active = self.active.checked_add(1)?;
        LocalCidKey::new(index, slot.generation)
    }

    fn remove(&mut self, key: LocalCidKey) -> Option<LocalCid> {
        let slot = self.slots.get_mut(key.slot())?;
        if slot.generation != key.generation() {
            return None;
        }
        let generation = slot.generation.checked_add(1)?;
        let cid = slot.cid.take()?;
        slot.generation = generation;
        self.active = self.active.checked_sub(1)?;
        Some(cid)
    }

    fn iter(&self) -> impl Iterator<Item = &LocalCid> {
        self.slots.iter().filter_map(|slot| slot.cid.as_ref())
    }
}

#[derive(Clone, Copy)]
struct PeerCid {
    sequence: u64,
    id: packet::ConnectionId,
    reset_token: Option<StatelessResetToken>,
}

impl PeerCid {
    fn matches(&self, id: packet::ConnectionId, reset_token: Option<StatelessResetToken>) -> bool {
        self.id == id && self.reset_token == reset_token
    }
}

struct Challenge {
    data: [u8; 8],
    control: Option<control::OwnerKey<control::kind::PathChallenge>>,
    outstanding: bool,
}

#[repr(transparent)]
struct PathState(u32);

impl PathState {
    const COUNT_MASK: u32 = 0x7f;
    const CHALLENGE_SHIFT: u32 = 0;
    const RESPONSE_SHIFT: u32 = 7;
    const RETIREMENT_SHIFT: u32 = 14;
    const AUTO_ISSUED: u32 = 1 << 21;
    const STATELESS_RESET_RECEIVED: u32 = 1 << 22;
    const RETRY_PROCESSED: u32 = 1 << 23;

    const fn new() -> Self {
        Self(0)
    }

    const fn auto_issued(&self) -> bool {
        self.0 & Self::AUTO_ISSUED != 0
    }

    fn mark_auto_issued(&mut self) {
        self.0 |= Self::AUTO_ISSUED;
    }

    const fn challenge_dirty(&self) -> usize {
        self.count(Self::CHALLENGE_SHIFT)
    }

    fn add_challenge(&mut self) {
        self.add(Self::CHALLENGE_SHIFT, conn::MAX_PATH_TOKENS);
    }

    fn materialize_challenge(&mut self) {
        self.materialize(Self::CHALLENGE_SHIFT);
    }

    const fn response_dirty(&self) -> usize {
        self.count(Self::RESPONSE_SHIFT)
    }

    fn add_response(&mut self) {
        self.add(Self::RESPONSE_SHIFT, conn::MAX_PATH_TOKENS);
    }

    fn materialize_response(&mut self) {
        self.materialize(Self::RESPONSE_SHIFT);
    }

    const fn retirement_dirty(&self) -> usize {
        self.count(Self::RETIREMENT_SHIFT)
    }

    fn add_retirement(&mut self) {
        self.add(
            Self::RETIREMENT_SHIFT,
            conn::MAX_PENDING_RETIRE_CONNECTION_IDS,
        );
    }

    fn materialize_retirement(&mut self) {
        self.materialize(Self::RETIREMENT_SHIFT);
    }

    fn mark_stateless_reset(&mut self) {
        self.0 |= Self::STATELESS_RESET_RECEIVED;
    }

    const fn was_stateless_reset(&self) -> bool {
        self.0 & Self::STATELESS_RESET_RECEIVED != 0
    }

    fn mark_retry_processed(&mut self) {
        self.0 |= Self::RETRY_PROCESSED;
    }

    const fn retry_processed(&self) -> bool {
        self.0 & Self::RETRY_PROCESSED != 0
    }

    const fn count(&self, shift: u32) -> usize {
        ((self.0 >> shift) & Self::COUNT_MASK) as usize
    }

    fn add(&mut self, shift: u32, maximum: usize) {
        debug_assert!(self.count(shift) < maximum);
        self.0 += 1 << shift;
    }

    fn materialize(&mut self, shift: u32) {
        debug_assert_ne!(self.count(shift), 0);
        self.0 -= 1 << shift;
    }
}

pub(super) struct Path {
    peer: PeerCidState,
    local: LocalCidState,
    pub(super) handshake: HandshakeState,
    pub(super) validation: ValidationState,
}

struct PeerCidState {
    active_peer_cid: PeerCid,
    spare_peer_cids: Vec<PeerCid>,
    peer_retire_prior_to: u64,
}

struct LocalCidState {
    initial_local_cid: packet::ConnectionId,
    local_cids: LocalCidSet,
    route_updates: Box<RouteUpdates>,
    routing_enabled: bool,
    cid_prefix: Option<u8>,
    stateless_reset_secret: Option<[u8; 32]>,
    local_active_connection_id_limit: u64,
}

pub(super) struct HandshakeState {
    pub(super) original_dcid: packet::ConnectionId,
    pub(super) peer_first_scid: Option<packet::ConnectionId>,
    pub(super) retry_token: Vec<u8>,
}

pub(super) struct ValidationState {
    challenges: Vec<Challenge>,
    pub(super) validated_tokens: Vec<[u8; 8]>,
    response_controls: Vec<(
        [u8; 8],
        Option<control::OwnerKey<control::kind::PathResponse>>,
    )>,
    retirements: Vec<(
        u64,
        Option<control::OwnerKey<control::kind::RetireConnectionId>>,
    )>,
    state: PathState,
}

impl Path {
    pub(super) fn new(
        local_cid: packet::ConnectionId,
        original_dcid: packet::ConnectionId,
        peer_cid: packet::ConnectionId,
        peer_first_scid: Option<packet::ConnectionId>,
        cid_prefix: Option<u8>,
        stateless_reset_secret: Option<[u8; 32]>,
        local_active_connection_id_limit: u64,
    ) -> Self {
        Self {
            peer: PeerCidState {
                active_peer_cid: PeerCid {
                    sequence: 0,
                    id: peer_cid,
                    reset_token: None,
                },
                spare_peer_cids: Vec::with_capacity(conn::MAX_ACTIVE_CONNECTION_IDS - 1),
                peer_retire_prior_to: 0,
            },
            local: LocalCidState {
                initial_local_cid: local_cid,
                local_cids: LocalCidSet::new(local_cid),
                route_updates: Box::new(RouteUpdates::new()),
                routing_enabled: false,
                cid_prefix,
                stateless_reset_secret,
                local_active_connection_id_limit,
            },
            handshake: HandshakeState {
                original_dcid,
                peer_first_scid,
                retry_token: Vec::new(),
            },
            validation: ValidationState {
                challenges: Vec::with_capacity(conn::MAX_PATH_TOKENS),
                validated_tokens: Vec::with_capacity(conn::MAX_PATH_TOKENS),
                response_controls: Vec::with_capacity(conn::MAX_PATH_TOKENS),
                retirements: Vec::with_capacity(conn::MAX_PENDING_RETIRE_CONNECTION_IDS),
                state: PathState::new(),
            },
        }
    }

    pub(super) fn matches_reset(&self, candidate: StatelessResetToken) -> bool {
        let mut matched = subtle::Choice::from(0);
        for known in self.peer_reset_tokens() {
            matched |= candidate.0[..].ct_eq(&known.0[..]);
        }
        bool::from(matched)
    }

    pub(super) fn peer_reset_tokens(&self) -> impl Iterator<Item = StatelessResetToken> + '_ {
        self.peer.active_peer_cid.reset_token.into_iter().chain(
            self.peer
                .spare_peer_cids
                .iter()
                .filter_map(|cid| cid.reset_token),
        )
    }

    pub(super) fn peer_cid(&self) -> &[u8] {
        self.peer.active_peer_cid.id.as_slice()
    }

    pub(super) fn local_cid(&self) -> &[u8] {
        self.local.initial_local_cid.as_slice()
    }

    pub(super) const fn local_cid_id(&self) -> packet::ConnectionId {
        self.local.initial_local_cid
    }

    pub(crate) fn enable_cid_routing(&mut self) -> (LocalCidKey, packet::ConnectionId) {
        self.local.routing_enabled = true;
        (
            self.local
                .local_cids
                .key(0)
                .expect("the initial local CID remains active before routing starts"),
            self.local.initial_local_cid,
        )
    }

    pub(crate) fn take_route_updates(&mut self) -> RouteUpdates {
        let updates = *self.local.route_updates;
        self.local.route_updates.clear();
        updates
    }

    fn queue_route_update(&mut self, update: RouteUpdate) {
        if !self.local.routing_enabled {
            return;
        }
        self.local
            .route_updates
            .push(update)
            .unwrap_or_else(|_| unreachable!("local CID route updates are bounded"));
    }

    pub(crate) fn local_cid_frame(&self, key: LocalCidKey) -> Option<(u64, &[u8], [u8; 16])> {
        let cid = self.local.local_cids.resolve(key)?;
        Some((cid.sequence, cid.id.as_slice(), cid.reset_token))
    }

    pub(crate) fn local_cid_sent(&mut self, key: LocalCidKey) {
        if let Some(cid) = self.local.local_cids.resolve(key) {
            self.local.local_cids.largest_sent =
                self.local.local_cids.largest_sent.max(cid.sequence);
        }
    }

    pub(crate) fn local_cids(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.local
            .local_cids
            .iter()
            .map(|cid| (cid.sequence, cid.id.as_slice()))
    }

    pub(super) fn set_initial_peer_cid(&mut self, connection_id: packet::ConnectionId) {
        debug_assert_eq!(self.peer.active_peer_cid.sequence, 0);
        self.peer.active_peer_cid.id = connection_id;
    }

    pub(super) fn set_first_peer_cid(&mut self, id: packet::ConnectionId) {
        debug_assert_eq!(self.peer.active_peer_cid.sequence, 0);
        self.peer.active_peer_cid.id = id;
        self.handshake.peer_first_scid = Some(id);
    }

    pub(super) fn set_initial_peer_reset_token(&mut self, reset_token: [u8; 16]) {
        debug_assert_eq!(self.peer.active_peer_cid.sequence, 0);
        self.peer.active_peer_cid.reset_token = StatelessResetToken::new(reset_token);
    }

    pub(super) fn mark_stateless_reset(&mut self) {
        self.validation.state.mark_stateless_reset();
    }

    pub(super) fn was_stateless_reset(&self) -> bool {
        self.validation.state.was_stateless_reset()
    }

    pub(super) fn retry_processed(&self) -> bool {
        self.validation.state.retry_processed()
    }

    pub(super) fn mark_retry_processed(&mut self) {
        self.validation.state.mark_retry_processed();
    }

    fn derive_cid(&self, sequence: u64) -> packet::ConnectionId {
        let initial = self.local.initial_local_cid.as_slice();
        let mut bytes = [0; crate::packet::MAX_CONNECTION_ID_LEN];
        bytes[..initial.len()].copy_from_slice(initial);
        let prefix_len = usize::from(self.local.cid_prefix.is_some());
        for (byte, sequence) in bytes[prefix_len..initial.len()]
            .iter_mut()
            .zip(sequence.to_le_bytes())
        {
            *byte ^= sequence;
        }
        if let Some(prefix) = self.local.cid_prefix
            && !initial.is_empty()
        {
            bytes[0] = prefix;
        }
        packet::ConnectionId::new(&bytes[..initial.len()])
            .expect("a derived CID retains its fixed length")
    }

    pub(super) fn accept_peer_cid(
        &mut self,
        sequence: u64,
        retire_prior_to: u64,
        connection_id: &[u8],
        reset_token: [u8; 16],
        control: &control::Pending,
    ) -> Result<(), conn::Error> {
        if connection_id.is_empty() || retire_prior_to > sequence {
            return Err(conn::Error::ProtocolViolation);
        }
        let Some(connection_id) = packet::ConnectionId::new(connection_id) else {
            return Err(conn::Error::ProtocolViolation);
        };
        let reset_token = StatelessResetToken::new(reset_token);
        let known = if self.peer.active_peer_cid.sequence == sequence {
            Some(&self.peer.active_peer_cid)
        } else {
            self.peer
                .spare_peer_cids
                .iter()
                .find(|candidate| candidate.sequence == sequence)
        };
        if let Some(existing) = known
            && !existing.matches(connection_id, reset_token)
        {
            return Err(conn::Error::ProtocolViolation);
        }
        let known = known.is_some();
        let retire_prior_to = self.peer.peer_retire_prior_to.max(retire_prior_to);

        let dirty = self.validation.state.retirement_dirty();
        let live = self.validation.retirements.len() - dirty;
        let mut index = 0;
        self.validation.retirements.retain(|(_, owner)| {
            let keep = index >= live || control.owner_is_live(*owner);
            index += 1;
            keep
        });
        let mut retiring = [0; conn::MAX_ACTIVE_CONNECTION_IDS + 1];
        let mut retirement_count = 0;
        {
            let mut record_retirement = |sequence| {
                if !retiring[..retirement_count].contains(&sequence) {
                    retiring[retirement_count] = sequence;
                    retirement_count += 1;
                }
            };
            if self.peer.active_peer_cid.sequence < retire_prior_to {
                record_retirement(self.peer.active_peer_cid.sequence);
            }
            for cid in &self.peer.spare_peer_cids {
                if cid.sequence < retire_prior_to {
                    record_retirement(cid.sequence);
                }
            }
            if !known && sequence < retire_prior_to {
                record_retirement(sequence);
            }
        }

        let retained = usize::from(self.peer.active_peer_cid.sequence >= retire_prior_to)
            + self
                .peer
                .spare_peer_cids
                .iter()
                .filter(|cid| cid.sequence >= retire_prior_to)
                .count();
        let admit = !known && sequence >= retire_prior_to;
        let final_count = retained + usize::from(admit);
        if final_count == 0
            || final_count > conn::MAX_ACTIVE_CONNECTION_IDS
            || final_count as u64 > self.local.local_active_connection_id_limit
        {
            return Err(conn::Error::ConnectionIdLimit);
        }

        let additional = retiring[..retirement_count]
            .iter()
            .filter(|candidate| {
                !self
                    .validation
                    .retirements
                    .iter()
                    .any(|(sequence, _)| sequence == *candidate)
            })
            .count();
        if self.validation.retirements.len().saturating_add(additional)
            > conn::MAX_PENDING_RETIRE_CONNECTION_IDS
        {
            return Err(conn::Error::ConnectionIdLimit);
        }
        self.peer.peer_retire_prior_to = retire_prior_to;
        let mut incoming = admit.then_some(PeerCid {
            sequence,
            id: connection_id,
            reset_token,
        });
        let mut index = 0;
        while index < self.peer.spare_peer_cids.len() {
            if self.peer.spare_peer_cids[index].sequence < retire_prior_to {
                self.peer.spare_peer_cids.swap_remove(index);
            } else {
                index += 1;
            }
        }
        if self.peer.active_peer_cid.sequence < retire_prior_to {
            self.peer.active_peer_cid = if let Some(replacement) = self
                .peer
                .spare_peer_cids
                .iter()
                .position(|cid| cid.sequence >= retire_prior_to)
            {
                self.peer.spare_peer_cids.swap_remove(replacement)
            } else {
                incoming
                    .take()
                    .expect("a NEW_CONNECTION_ID frame supplies a non-retired CID")
            };
        }
        if let Some(incoming) = incoming {
            debug_assert!(self.peer.spare_peer_cids.len() < conn::MAX_ACTIVE_CONNECTION_IDS - 1);
            self.peer.spare_peer_cids.push(incoming);
        }
        for &retired in &retiring[..retirement_count] {
            if self
                .validation
                .retirements
                .iter()
                .any(|(sequence, _)| *sequence == retired)
            {
                continue;
            }
            self.validation.retirements.push((retired, None));
            self.validation.state.add_retirement();
        }
        Ok(())
    }

    pub(super) fn queue_challenge(&mut self, data: [u8; 8]) {
        if self
            .validation
            .challenges
            .iter()
            .any(|challenge| challenge.data == data)
        {
            return;
        }
        if self.validation.challenges.len() == conn::MAX_PATH_TOKENS {
            return;
        }
        self.validation.challenges.push(Challenge {
            data,
            control: None,
            outstanding: false,
        });
        self.validation.state.add_challenge();
    }

    pub(super) fn reconcile_controls(&mut self, control: &mut control::Pending, mut work: usize) {
        while work != 0 && self.validation.state.response_dirty() != 0 {
            let index =
                self.validation.response_controls.len() - self.validation.state.response_dirty();
            let (data, owner) = &mut self.validation.response_controls[index];
            debug_assert!(owner.is_none());
            let Some(mut permit) = control.try_reserve(1) else {
                return;
            };
            permit.queue_path_response(owner, *data);
            self.validation.state.materialize_response();
            work -= 1;
        }
        while work != 0 && self.validation.state.retirement_dirty() != 0 {
            let index =
                self.validation.retirements.len() - self.validation.state.retirement_dirty();
            let (sequence, owner) = &mut self.validation.retirements[index];
            debug_assert!(owner.is_none());
            let Some(mut permit) = control.try_reserve(1) else {
                return;
            };
            permit.retire_connection_id(owner, *sequence);
            self.validation.state.materialize_retirement();
            work -= 1;
        }
        while work != 0 && self.validation.state.challenge_dirty() != 0 {
            let index = self.validation.challenges.len() - self.validation.state.challenge_dirty();
            let challenge = &mut self.validation.challenges[index];
            debug_assert!(challenge.control.is_none());
            let Some(mut permit) = control.try_reserve(1) else {
                return;
            };
            permit.queue_path_challenge(&mut challenge.control, challenge.data);
            drop(permit);
            self.validation.state.materialize_challenge();
            work -= 1;
        }
    }

    pub(super) fn controls_pending(&self) -> bool {
        self.validation.state.response_dirty() != 0
            || self.validation.state.retirement_dirty() != 0
            || self.validation.state.challenge_dirty() != 0
    }

    pub(super) fn controls_sendable(&self, control: &control::Pending) -> bool {
        self.controls_pending() && control.remaining_capacity() != 0
    }

    pub(super) fn challenge_sent(&mut self, data: [u8; 8]) {
        if let Some(challenge) = self
            .validation
            .challenges
            .iter_mut()
            .find(|challenge| challenge.data == data)
        {
            challenge.outstanding = true;
        }
    }

    pub(super) fn queue_response(&mut self, data: [u8; 8], control: &control::Pending) {
        let dirty = self.validation.state.response_dirty();
        let live = self.validation.response_controls.len() - dirty;
        let mut position = 0;
        self.validation.response_controls.retain(|(_, owner)| {
            let keep = position >= live || control.owner_is_live(*owner);
            position += 1;
            keep
        });
        let index = self
            .validation
            .response_controls
            .iter()
            .position(|(candidate, _)| *candidate == data);
        let index = match index {
            Some(index) => index,
            None if self.validation.response_controls.len() == conn::MAX_PATH_TOKENS => return,
            None => {
                self.validation.response_controls.push((data, None));
                self.validation.state.add_response();
                self.validation.response_controls.len() - 1
            }
        };
        debug_assert_eq!(self.validation.response_controls[index].0, data);
    }

    pub(super) fn record_response<C: control::Write>(&mut self, token: [u8; 8], control: &mut C) {
        let Some(index) = self
            .validation
            .challenges
            .iter()
            .position(|challenge| challenge.data == token && challenge.outstanding)
        else {
            return;
        };
        let dirty = self.validation.state.challenge_dirty();
        debug_assert!(index < self.validation.challenges.len() - dirty);
        let mut challenge = self.validation.challenges.swap_remove(index);
        let new_live_len = self.validation.challenges.len().saturating_sub(dirty);
        if dirty != 0 && index < new_live_len {
            self.validation.challenges.swap(index, new_live_len);
        }
        control.remove_control(&mut challenge.control);
        if self.validation.validated_tokens.contains(&token) {
            return;
        }
        if self.validation.validated_tokens.len() == conn::MAX_PATH_TOKENS {
            self.validation.validated_tokens.swap_remove(0);
        }
        self.validation.validated_tokens.push(token);
    }

    pub(super) fn issue_local_cids(&mut self, limit: u64) -> usize {
        if self.validation.state.auto_issued() {
            return 0;
        }
        self.validation.state.mark_auto_issued();
        if self.local.initial_local_cid.as_slice().is_empty()
            || self.local.stateless_reset_secret.is_none()
        {
            return 0;
        }
        self.local.local_cids.target = limit.min(conn::MAX_ACTIVE_CONNECTION_IDS as u64) as u8;
        let mut issued = 0;
        while self.local.local_cids.active < self.local.local_cids.target && self.issue_local_cid()
        {
            issued += 1;
        }
        issued
    }

    fn issue_local_cid(&mut self) -> bool {
        let sequence = self.local.local_cids.next_sequence;
        if crate::varint::VarInt::new(sequence).is_none() {
            return false;
        }
        let variable_bytes = self
            .local
            .initial_local_cid
            .len()
            .saturating_sub(usize::from(self.local.cid_prefix.is_some()))
            .min(std::mem::size_of::<u64>());
        if variable_bytes < std::mem::size_of::<u64>() && sequence >= 1u64 << (variable_bytes * 8) {
            return false;
        }
        let Some(next_sequence) = sequence.checked_add(1) else {
            return false;
        };
        let id = self.derive_cid(sequence);
        debug_assert!(self.local.local_cids.iter().all(|cid| cid.id != id));
        let Some(secret) = self.local.stateless_reset_secret else {
            return false;
        };
        let reset_token = crate::secrets::StatelessResetSecret(secret).token_for(id.as_slice());
        let Some(key) = self.local.local_cids.insert(LocalCid {
            sequence,
            id,
            reset_token,
            control: None,
        }) else {
            return false;
        };
        self.local.local_cids.next_sequence = next_sequence;
        self.queue_route_update(RouteUpdate::Add { key, cid: id });
        true
    }

    pub(super) fn issued_local_cid_control_slots(&self) -> usize {
        self.local
            .local_cids
            .iter()
            .filter(|cid| cid.sequence != 0 && cid.control.is_none())
            .count()
    }

    pub(super) fn queue_issued_local_cids<C: control::Write>(&mut self, control: &mut C) {
        for (index, slot) in self.local.local_cids.slots.iter_mut().enumerate() {
            let Some(cid) = slot
                .cid
                .as_mut()
                .filter(|cid| cid.sequence != 0 && cid.control.is_none())
            else {
                continue;
            };
            let key = LocalCidKey::new(index, slot.generation)
                .expect("a bounded CID slot has a typed key");
            control.queue_new_connection_id(&mut cid.control, cid.sequence, key);
        }
    }

    pub(super) fn retire_local_cid<C: control::Write>(
        &mut self,
        sequence: u64,
        routed: Option<LocalCidKey>,
        packet_dcid: &[u8],
        control: &mut C,
    ) -> Result<usize, conn::Error> {
        if self.local.initial_local_cid.as_slice().is_empty()
            || sequence > self.local.local_cids.largest_sent
        {
            return Err(conn::Error::ProtocolViolation);
        }
        let Some((key, cid)) = self.local.local_cids.find_sequence(sequence) else {
            return Ok(0);
        };
        if routed == Some(key) || cid.id.as_slice() == packet_dcid {
            return Err(conn::Error::ProtocolViolation);
        }
        let mut retired = self
            .local
            .local_cids
            .remove(key)
            .ok_or(conn::Error::ConnectionIdLimit)?;
        control.remove_control(&mut retired.control);
        self.queue_route_update(RouteUpdate::Remove(key));
        let mut issued = 0;
        while self.local.local_cids.active < self.local.local_cids.target && self.issue_local_cid()
        {
            issued += 1;
        }
        Ok(issued)
    }
}

const _: () = assert!(std::mem::size_of::<PathState>() == 4);
const _: () = assert!(std::mem::size_of::<packet::ConnectionId>() == 21);
const _: () = assert!(std::mem::size_of::<LocalCidKey>() == 8);
const _: () = assert!(std::mem::size_of::<PeerCid>() == 48);
