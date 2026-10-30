use rustls::quic;
use std::{cell, mem, time};

use crate::{
    conn,
    conn::wire::{
        Tls,
        tls::{ciphers, packets},
    },
    security::{crypto, qkdf},
    wire::packet::kind,
};
use ciphers::Update;
use crypto::{Generation, Key, op};
use qkdf::origin;

pub(super) struct Previous {
    pub(super) generation: Generation<origin::Peer, op::Open>,
    due: time::Instant,
}

pub(super) struct ReadKeys {
    pub(super) current: Key<kind::OneRtt, origin::Peer, op::Open>,
    pub(super) next: Generation<origin::Peer, op::Open>,
    lookahead: Option<Generation<origin::Peer, op::Open>>,
    pub(super) previous: Option<Previous>,
    secrets: quic::Secrets,
    pub(super) phase: bool,
    pub(super) first_current_pn: Option<u64>,
    peer_update_unconfirmed: bool,
}

impl ReadKeys {
    fn try_new(
        keys: quic::DirectionalKeys,
        packet: Box<dyn quic::PacketKey>,
        mut secrets: quic::Secrets,
        fails: &mut ciphers::Failures,
    ) -> Result<Self, conn::Error> {
        let cur = Key::try_new(keys)?;
        let next = cur.try_next(packet).map_err(crypto::Error::from)?;
        let ahead = next
            .try_next(secrets.next_packet_keys().remote)
            .map_err(crypto::Error::from)?;
        fails.admit(
            cur.open_limit()
                .min(next.open_limit())
                .min(ahead.open_limit()),
        )?;
        Ok(Self {
            current: cur,
            next,
            lookahead: Some(ahead),
            previous: None,
            secrets,
            phase: false,
            first_current_pn: None,
            peer_update_unconfirmed: false,
        })
    }

    pub(super) fn expire(&mut self, now: time::Instant) {
        if self.previous.as_ref().is_some_and(|prev| now >= prev.due) {
            self.previous = None;
        }
    }

    fn rotate(&mut self, now: time::Instant, pto: time::Duration) -> Result<(), Update> {
        self.lookahead.as_ref().ok_or(Update::Key)?;
        let due = conn::Timing::try_deadline(now, conn::Timing::try_mul(pto, 3)?)?;
        let next = self.lookahead.take().ok_or(Update::Key)?;
        let old = self.current.replace(mem::replace(&mut self.next, next));
        self.previous = Some(Previous {
            generation: old,
            due,
        });
        self.phase = !self.phase;
        Ok(())
    }

    pub(super) fn promote(
        &mut self,
        pn: u64,
        now: time::Instant,
        pto: time::Duration,
    ) -> Result<(), Update> {
        if self.peer_update_unconfirmed {
            return Err(Update::Key);
        }
        self.rotate(now, pto)?;
        self.first_current_pn = Some(pn);
        self.peer_update_unconfirmed = true;
        Ok(())
    }

    pub(super) fn can_advance(&self) -> bool {
        !self.peer_update_unconfirmed && self.lookahead.is_some()
    }

    fn initiate(&mut self, now: time::Instant, pto: time::Duration) -> Result<(), Update> {
        self.rotate(now, pto)?;
        self.first_current_pn = None;
        Ok(())
    }

    fn try_fill(&mut self, fails: &mut ciphers::Failures) -> Result<(), Update> {
        if self.lookahead.is_none() {
            let mut secrets = self.secrets.clone();
            let next = self.next.try_next(secrets.next_packet_keys().remote)?;
            fails.admit(next.open_limit())?;
            self.secrets = secrets;
            self.lookahead = Some(next);
        }
        Ok(())
    }

    fn confirm(&mut self) {
        self.peer_update_unconfirmed = false;
    }
}

pub(super) struct WriteKeys {
    pub(super) current: Key<kind::OneRtt, origin::Local, op::Seal>,
    next: Option<Generation<origin::Local, op::Seal>>,
    secrets: quic::Secrets,
    pub(super) phase: bool,
    generation: u64,
    encrypted: ciphers::Usage,
    first_current_pn: cell::Cell<Option<u64>>,
    acknowledged_at: Option<time::Instant>,
}

impl WriteKeys {
    fn try_new(
        keys: quic::DirectionalKeys,
        packet: Box<dyn quic::PacketKey>,
        secrets: quic::Secrets,
    ) -> Result<Self, crypto::Error> {
        let cur = Key::try_new(keys)?;
        let next = cur.try_next(packet)?;
        let limit = cur.seal_limit();
        Ok(Self {
            current: cur,
            next: Some(next),
            secrets,
            phase: false,
            generation: 0,
            encrypted: ciphers::Usage::new(limit),
            first_current_pn: cell::Cell::new(None),
            acknowledged_at: None,
        })
    }

    pub(super) fn advance(&mut self) -> Result<(), Update> {
        let next = self.next.take().ok_or(Update::Key)?;
        drop(self.current.replace(next));
        self.phase = !self.phase;
        self.generation = self.generation.checked_add(1).ok_or(Update::Key)?;
        self.encrypted = ciphers::Usage::new(self.current.seal_limit());
        self.first_current_pn.set(None);
        self.acknowledged_at = None;
        Ok(())
    }

    pub(super) fn can_advance(&self) -> bool {
        self.next.is_some() && self.generation != u64::MAX
    }

    fn try_fill(&mut self) -> Result<(), crypto::Dimensions> {
        if self.next.is_none() {
            let mut secrets = self.secrets.clone();
            let next = self.current.try_next(secrets.next_packet_keys().local)?;
            self.secrets = secrets;
            self.next = Some(next);
        }
        Ok(())
    }

    fn can_update(&self, ready: bool, now: time::Instant, pto: time::Duration) -> bool {
        if !ready {
            return false;
        }
        if self.generation == 0 {
            return true;
        }
        self.acknowledged_at
            .and_then(|acked| now.checked_duration_since(acked))
            .is_some_and(|elapsed| elapsed / 3 >= pto)
    }

    pub(super) fn begin(&self) -> Result<(), crypto::Error> {
        self.encrypted.record()?;
        Ok(())
    }

    pub(super) fn finish(&self, pn: u64) {
        if self.first_current_pn.get().is_none() {
            self.first_current_pn.set(Some(pn));
        }
    }
}

/// Both directions are installed by the same native OneRtt transition.
/// A pending server pair remains owned here across subsequent handshake reads.
pub(super) struct Pair {
    read: ReadKeys,
    write: WriteKeys,
    state: ReadState,
}

enum ReadState {
    Pending,
    Active,
}

/// Exclusive activation access admitted at native handshake completion.
pub(super) struct Pending<'a> {
    state: &'a mut ReadState,
}

impl Pending<'_> {
    pub(super) fn activate(self) {
        *self.state = ReadState::Active;
    }
}

enum Rejection {
    AeadLimitReached,
    KeyUpdate,
}

impl Pair {
    /// Consumes the native OneRtt keys once, publishing both directions only
    /// after their fallible construction and admission have succeeded.
    pub(super) fn try_install(
        target: &mut Option<Self>,
        keys: quic::Keys,
        mut next: quic::Secrets,
        fails: &mut ciphers::Failures,
    ) -> Result<(), conn::Error> {
        let packet = next.next_packet_keys();
        let read = ReadKeys::try_new(keys.remote, packet.remote, next.clone(), fails)?;
        let write = WriteKeys::try_new(keys.local, packet.local, next)?;
        *target = Some(Self {
            read,
            write,
            state: ReadState::Pending,
        });
        Ok(())
    }

    /// Admits native completion once and lends the same published pair's state.
    pub(super) fn try_pending(&mut self) -> Result<Pending<'_>, conn::Error> {
        match self.state {
            ReadState::Active => Err(conn::Error::Tls(Tls::ActiveApplicationKeys)),
            ReadState::Pending => Ok(Pending {
                state: &mut self.state,
            }),
        }
    }

    pub(super) fn read<'a>(
        &'a mut self,
        fails: &'a mut ciphers::Failures,
    ) -> Option<packets::Read<'a>> {
        if !matches!(self.state, ReadState::Active) {
            return None;
        }
        Some(packets::Read::new(&mut self.read, &mut self.write, fails))
    }

    pub(super) fn write(&self) -> packets::Write<'_> {
        packets::Write::new(&self.write)
    }

    pub(super) fn prepare(
        &mut self,
        ready: bool,
        now: time::Instant,
        pto: time::Duration,
        fails: &mut ciphers::Failures,
    ) -> Result<(), Update> {
        if self.write.encrypted.is_near() {
            self.advance(ready, now, pto, Rejection::AeadLimitReached)?;
        }
        self.try_fill(fails)?;
        if let ReadState::Active = self.state {
            self.read.expire(now);
        }
        Ok(())
    }

    pub(super) fn initiate(
        &mut self,
        ready: bool,
        now: time::Instant,
        pto: time::Duration,
        fails: &mut ciphers::Failures,
    ) -> Result<(), Update> {
        self.advance(ready, now, pto, Rejection::KeyUpdate)?;
        self.try_fill(fails)
    }

    pub(super) fn acknowledge(&mut self, pn: u64, now: time::Instant) {
        if self
            .write
            .first_current_pn
            .get()
            .is_some_and(|first| pn >= first)
        {
            self.write.acknowledged_at.get_or_insert(now);
        }
    }

    pub(super) fn confirm(&mut self) {
        if let ReadState::Active = self.state {
            self.read.confirm();
        }
    }

    fn advance(
        &mut self,
        ready: bool,
        now: time::Instant,
        pto: time::Duration,
        reject: Rejection,
    ) -> Result<(), Update> {
        if !self.write.can_update(ready, now, pto) {
            return Err(match reject {
                Rejection::AeadLimitReached => Update::AeadLimitReached,
                Rejection::KeyUpdate => Update::Key,
            });
        }
        if !matches!(self.state, ReadState::Active)
            || !self.write.can_advance()
            || !self.read.can_advance()
        {
            return Err(Update::Key);
        }
        self.read.initiate(now, pto)?;
        self.write.advance()
    }

    fn try_fill(&mut self, fails: &mut ciphers::Failures) -> Result<(), Update> {
        self.write.try_fill()?;
        if let ReadState::Active = self.state {
            self.read.try_fill(fails)?;
        }
        Ok(())
    }
}

const _: () = {
    assert!(
        mem::size_of::<Option<Pair>>()
            <= mem::size_of::<ReadKeys>() + mem::size_of::<WriteKeys>() + mem::align_of::<Pair>()
    );
};
