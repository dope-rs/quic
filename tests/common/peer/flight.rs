use std::time::Instant;

use dope_quic::conn::output::transmit;
use dope_quic::conn::wire::packet;
use dope_quic::{conn, stream};

pub const PAYLOAD: [u8; 512] = [0x42; 512];

#[derive(Debug)]
pub enum Delivery {
    Time { sent_at: Instant, at: Instant },
    Input(super::Transfer),
}

/// A committed packet batch bound to its emission timestamp and effects.
#[must_use = "a committed flight must be inspected or delivered"]
pub struct Flight<'batch> {
    batch: &'batch mut packet::Batch,
    sent_at: Instant,
    effects: transmit::Effects,
}

impl<'batch> Flight<'batch> {
    pub fn emit_at<const DOMAIN: u8, B: stream::Recv>(
        conn: &mut conn::Connection<DOMAIN, B>,
        batch: &'batch mut packet::Batch,
        sent_at: Instant,
        count: usize,
        bytes: usize,
    ) -> Result<Self, transmit::Failure> {
        let effects =
            conn.with_scope(|mut scope| scope.output().send_effects(batch, sent_at, count, bytes))?;
        Ok(Self {
            batch,
            sent_at,
            effects,
        })
    }

    pub fn emit_due<const DOMAIN: u8, B: stream::Recv>(
        conn: &mut conn::Connection<DOMAIN, B>,
        batch: &'batch mut packet::Batch,
        ready_at: Instant,
        count: usize,
        bytes: usize,
    ) -> Result<Self, transmit::Failure> {
        let sent_at = conn.view().recovery().send_at(ready_at);
        Self::emit_at(conn, batch, sent_at, count, bytes)
    }

    pub const fn sent_at(&self) -> Instant {
        self.sent_at
    }

    pub const fn effects(&self) -> transmit::Effects {
        self.effects
    }

    pub fn is_empty(&self) -> bool {
        self.batch.is_empty()
    }

    pub fn deliver<R: super::Receiver>(
        self,
        work: &mut conn::Workspace,
        receiver: &mut R,
    ) -> Result<(), Delivery> {
        let at = self.sent_at;
        self.deliver_at(work, receiver, at)
    }

    pub fn deliver_at<R: super::Receiver>(
        self,
        work: &mut conn::Workspace,
        receiver: &mut R,
        at: Instant,
    ) -> Result<(), Delivery> {
        if at < self.sent_at {
            return Err(Delivery::Time {
                sent_at: self.sent_at,
                at,
            });
        }
        receiver
            .receive_all(work, self.batch, at)
            .map_err(Delivery::Input)
    }
}
