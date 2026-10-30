use std::time;

use o3::{
    buffer::{self, storage},
    mem::rc,
};

use dope::core::driver::schedule::clock;

use crate::{conn, security::crypto, stream, wire::packet::cid};
use conn::life;

/// Packet-protection and TLS-owned connection commands.
#[repr(C)]
pub struct Security<
    'access,
    const DOMAIN: u8,
    B: stream::Recv = Vec<u8>,
    const RECONCILE: bool = false,
    D: buffer::raw::Segment = storage::Shared,
    T = (),
> {
    pub(in crate::conn::scope) machine: &'access mut conn::Machine<DOMAIN, B, D>,
    pub(in crate::conn::scope) time: T,
}

impl<'access, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    Security<'access, DOMAIN, B, true, D>
{
    pub(super) fn raw(
        machine: &'access mut conn::Machine<DOMAIN, B, D>,
        now: time::Instant,
    ) -> Security<'access, DOMAIN, B, true, D, time::Instant> {
        Security { machine, time: now }
    }
}

impl<const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment>
    Security<'_, DOMAIN, B, RECONCILE, D>
{
    pub(super) fn new(
        machine: &mut conn::Machine<DOMAIN, B, D>,
    ) -> Security<'_, DOMAIN, B, RECONCILE, D> {
        Security { machine, time: () }
    }
}

impl<const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment, T>
    Security<'_, DOMAIN, B, RECONCILE, D, T>
{
    pub(super) fn rotate(&mut self, now: time::Instant) -> Result<(), conn::Error> {
        let (_, pto) = self.machine.try_pto()?;
        let ready = self.machine.egress.lifecycle.handshake_confirmed;
        self.machine
            .handshake
            .keys
            .update(ready, now, pto)
            .map_err(|error| {
                if let conn::Error::Timing(timing) = error {
                    self.machine.fail_timing(timing);
                } else if matches!(
                    error,
                    conn::Error::Crypto(crypto::Error::KeyDimensions { .. })
                        | conn::Error::AeadLimitReached
                ) && let Some(change) = self.machine.close(&error)
                {
                    self.machine.record::<RECONCILE>(change.effects().bits());
                }
                error
            })?;
        self.machine.record::<RECONCILE>(conn::Effects::TRANSMIT);
        Ok(())
    }

    /// Extracts reconnect auth, preserving both owners if retaining it fails.
    pub fn try_saved(&mut self) -> Result<Option<life::Reconnect>, rc::Error> {
        let Some(route) = self.saved_route() else {
            return Ok(None);
        };
        self.machine.handshake.peer.try_saved(route)
    }

    /// Called only by the consuming closing event before transport retirement.
    pub(crate) fn take_final(&mut self) -> Option<life::Reconnect> {
        let route = self.saved_route()?;
        let (token, auth, peer) = self.machine.handshake.peer.take_final()?;
        Some(life::Reconnect::new(token, auth, peer, route))
    }

    fn saved_route(&self) -> Option<cid::Id> {
        self.machine
            .peer
            .transport_params
            .as_ref()?
            .identity()
            .initial()
            .copied()
    }
}

impl<'access, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    Security<'access, DOMAIN, B, false, D>
{
    /// Binds an untracked standalone view to the caller's explicit turn time.
    pub fn at(self, now: time::Instant) -> Security<'access, DOMAIN, B, false, D, time::Instant> {
        Security {
            machine: self.machine,
            time: now,
        }
    }
}

impl<const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment>
    Security<'_, DOMAIN, B, RECONCILE, D, time::Instant>
{
    pub fn update(&mut self) -> Result<(), conn::Error> {
        self.rotate(self.time)
    }
}

impl<'d, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    Security<'_, DOMAIN, B, true, D, clock::Moment<'d>>
{
    pub fn update(&mut self) -> Result<(), conn::Error> {
        let now = self.time;
        now.at(self).apply(|security, now| security.rotate(now))
    }
}
