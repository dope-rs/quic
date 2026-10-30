use o3::buffer::{self, write};
use rustls::{Error, quic};
use std::{cell, mem, time};

use crate::{
    conn,
    security::{crypto, qkdf},
    wire::packet::{header, kind, long},
};
use crypto::op;
use qkdf::origin;

use crate::conn::wire::tls::{keys, packets};

pub(in crate::conn) enum Update {
    AeadLimitReached,
    Key,
    UnexpectedEpoch,
    Timing(conn::Timing),
    Dimensions(crypto::Dimensions),
}

impl From<conn::Timing> for Update {
    fn from(error: conn::Timing) -> Self {
        Self::Timing(error)
    }
}

impl From<crypto::Dimensions> for Update {
    fn from(error: crypto::Dimensions) -> Self {
        Self::Dimensions(error)
    }
}

impl From<Update> for conn::Error {
    fn from(error: Update) -> Self {
        match error {
            Update::AeadLimitReached => Self::AeadLimitReached,
            Update::Key => Self::KeyUpdate,
            Update::UnexpectedEpoch => Self::UnexpectedEpoch,
            Update::Timing(error) => Self::Timing(error),
            Update::Dimensions(error) => Self::Crypto(error.into()),
        }
    }
}

pub(super) struct Failures {
    count: u64,
    limit: u64,
}

impl Failures {
    const fn new(limit: u64) -> Self {
        Self { count: 0, limit }
    }

    pub(super) fn admit(&mut self, limit: u64) -> Result<(), Update> {
        self.limit = self.limit.min(limit);
        if self.count >= self.limit {
            return Err(Update::AeadLimitReached);
        }
        Ok(())
    }

    pub(super) fn record(&mut self) -> Result<(), conn::Error> {
        let Some(next) = self.count.checked_add(1) else {
            return Err(conn::Error::AeadLimitReached);
        };
        if next >= self.limit {
            Err(conn::Error::AeadLimitReached)
        } else {
            self.count = next;
            Ok(())
        }
    }
}

pub(super) struct Usage {
    encrypted: cell::Cell<u64>,
    limit: u64,
}

impl Usage {
    pub(super) const fn new(limit: u64) -> Self {
        Self {
            encrypted: cell::Cell::new(0),
            limit,
        }
    }

    fn count(&self) -> u64 {
        self.encrypted.get()
    }

    pub(super) fn is_near(&self) -> bool {
        self.count() >= self.limit.saturating_sub(1)
    }

    fn is_exhausted(&self) -> bool {
        self.count() >= self.limit
    }

    pub(super) fn record(&self) -> Result<(), crypto::Error> {
        if self.is_exhausted() {
            return Err(crypto::Error::Limit);
        }
        self.encrypted.set(self.count() + 1);
        Ok(())
    }
}

/// Encryption auth for one non-updatable long-header key.
pub(in crate::conn) struct LongWrite<K: kind::Long> {
    protection: crypto::Key<K, origin::Local, op::Seal>,
    usage: Usage,
}

/// Borrowed admission auth for a long-header write key.
pub(in crate::conn) struct LongAccess<'key, K: kind::Long> {
    key: &'key crypto::Key<K, origin::Local, op::Seal>,
    usage: &'key Usage,
}

/// A single reserved long-header encryption operation.
#[repr(transparent)]
pub(in crate::conn) struct LongPermit<'key, K: kind::Long> {
    key: &'key crypto::Key<K, origin::Local, op::Seal>,
}

impl<K: kind::Long> LongWrite<K> {
    pub(super) fn new(key: crypto::Key<K, origin::Local, op::Seal>) -> Self {
        let usage = Usage::new(key.seal_limit());
        Self {
            protection: key,
            usage,
        }
    }

    fn is_exhausted(&self) -> bool {
        self.usage.is_exhausted()
    }

    pub(in crate::conn) const fn access(&self) -> LongAccess<'_, K> {
        LongAccess {
            key: &self.protection,
            usage: &self.usage,
        }
    }
}

impl<'key, K: kind::Long> LongAccess<'key, K> {
    pub(in crate::conn) fn permit(self) -> Result<LongPermit<'key, K>, crypto::Error> {
        self.usage.record()?;
        Ok(LongPermit { key: self.key })
    }
}

impl<K: kind::Long> LongPermit<'_, K> {
    pub(in crate::conn) fn seal_into<'packet, A>(
        self,
        dst: write::Append<'packet>,
        header: header::Body<'_, '_, K>,
        auth: A,
    ) -> Result<(op::Wire<'packet, K>, op::Protected<A>), crypto::Error> {
        self.key.seal(dst, header, auth)
    }
}

pub(in crate::conn::wire) struct LongRead<'key, K: kind::Long> {
    key: &'key crypto::Key<K, origin::Peer, op::Open>,
    fails: &'key mut Failures,
}

impl<K: kind::Long> LongRead<'_, K> {
    pub(in crate::conn::wire) fn decrypt<P>(
        self,
        packet: long::Protected<K, P>,
        next: u64,
    ) -> Result<long::Decrypted<K, P>, conn::Error>
    where
        P: buffer::raw::Mutable,
    {
        match packet.decrypt(self.key, next) {
            Ok(packet) => Ok(packet),
            Err(error) => {
                if matches!(error, crypto::Error::Decrypt(Error::DecryptError)) {
                    self.fails.record()?;
                }
                Err(conn::Error::Crypto(error))
            }
        }
    }
}

pub(in crate::conn) struct LongKeys {
    pub(super) initial_read: Option<crypto::Key<kind::Initial, origin::Peer, op::Open>>,
    pub(super) handshake_read: Option<crypto::Key<kind::Handshake, origin::Peer, op::Open>>,
    pub(super) initial_write: Option<LongWrite<kind::Initial>>,
    pub(super) handshake_write: Option<LongWrite<kind::Handshake>>,
    pub(super) zero_rtt_read: Option<crypto::Key<kind::ZeroRtt, origin::Peer, op::Open>>,
    pub(super) zero_rtt_write: Option<LongWrite<kind::ZeroRtt>>,
}

impl LongKeys {
    fn new(
        rx: crypto::Key<kind::Initial, origin::Peer, op::Open>,
        tx: crypto::Key<kind::Initial, origin::Local, op::Seal>,
    ) -> Self {
        Self {
            initial_read: Some(rx),
            handshake_read: None,
            initial_write: Some(LongWrite::new(tx)),
            handshake_write: None,
            zero_rtt_read: None,
            zero_rtt_write: None,
        }
    }

    pub(in crate::conn) fn can_retry(&self) -> bool {
        self.handshake_read.is_none()
    }

    pub(in crate::conn) fn initial(&self) -> Option<&LongWrite<kind::Initial>> {
        self.initial_write.as_ref()
    }

    pub(in crate::conn) fn handshake(&self) -> Option<&LongWrite<kind::Handshake>> {
        self.handshake_write.as_ref()
    }

    pub(in crate::conn) fn early(&self) -> Option<&LongWrite<kind::ZeroRtt>> {
        self.zero_rtt_write.as_ref()
    }

    pub(in crate::conn) fn is_exhausted(&self) -> bool {
        self.initial_write
            .as_ref()
            .is_some_and(LongWrite::is_exhausted)
            || self
                .handshake_write
                .as_ref()
                .is_some_and(LongWrite::is_exhausted)
            || self
                .zero_rtt_write
                .as_ref()
                .is_some_and(LongWrite::is_exhausted)
    }

    pub(in crate::conn) fn replace(
        &mut self,
        read: crypto::Key<kind::Initial, origin::Peer, op::Open>,
        write: crypto::Key<kind::Initial, origin::Local, op::Seal>,
    ) {
        self.initial_read = Some(read);
        self.initial_write = Some(LongWrite::new(write));
    }

    fn discard(&mut self, epoch: conn::Epoch) {
        match epoch {
            conn::Epoch::Initial => {
                self.initial_read = None;
                self.initial_write = None;
            }
            conn::Epoch::Handshake => {
                self.handshake_read = None;
                self.handshake_write = None;
            }
            conn::Epoch::Application => {}
        }
    }
}

pub(in crate::conn) struct State {
    pub(in crate::conn) long: LongKeys,
    pub(super) app: Option<keys::Pair>,
    failures: Failures,
}

impl State {
    pub(super) fn new(
        rx: crypto::Key<kind::Initial, origin::Peer, op::Open>,
        tx: crypto::Key<kind::Initial, origin::Local, op::Seal>,
    ) -> Self {
        let failures = Failures::new(rx.open_limit());
        Self {
            long: LongKeys::new(rx, tx),
            app: None,
            failures,
        }
    }

    /// Consumes Rustls' unique owned OneRtt transition as one directional pair.
    pub(super) fn try_install(
        &mut self,
        keys: quic::Keys,
        next: quic::Secrets,
    ) -> Result<(), conn::Error> {
        keys::Pair::try_install(&mut self.app, keys, next, &mut self.failures)
    }

    pub(in crate::conn::wire) fn initial(&mut self) -> Option<LongRead<'_, kind::Initial>> {
        let key = self.long.initial_read.as_ref()?;
        Some(LongRead {
            key,
            fails: &mut self.failures,
        })
    }

    pub(in crate::conn::wire) fn handshake(&mut self) -> Option<LongRead<'_, kind::Handshake>> {
        let key = self.long.handshake_read.as_ref()?;
        Some(LongRead {
            key,
            fails: &mut self.failures,
        })
    }

    pub(in crate::conn::wire) fn read(&mut self) -> Option<packets::Read<'_>> {
        self.app.as_mut()?.read(&mut self.failures)
    }

    pub(in crate::conn) fn has_write(&self) -> bool {
        self.app.is_some()
    }

    pub(in crate::conn) fn write(&self) -> Option<packets::Write<'_>> {
        self.app.as_ref().map(keys::Pair::write)
    }

    pub(in crate::conn) fn prepare(
        &mut self,
        ready: bool,
        now: time::Instant,
        pto: time::Duration,
    ) -> Result<(), Update> {
        self.app.as_mut().ok_or(Update::UnexpectedEpoch)?.prepare(
            ready,
            now,
            pto,
            &mut self.failures,
        )
    }

    pub(in crate::conn) fn update(
        &mut self,
        ready: bool,
        now: time::Instant,
        pto: time::Duration,
    ) -> Result<(), conn::Error> {
        self.app
            .as_mut()
            .ok_or(conn::Error::UnexpectedEpoch)?
            .initiate(ready, now, pto, &mut self.failures)
            .map_err(Into::into)
    }

    pub(in crate::conn) fn acknowledge(&mut self, pn: u64, now: time::Instant) {
        if let Some(pair) = &mut self.app {
            pair.acknowledge(pn, now);
        }
    }

    pub(in crate::conn) fn confirm(&mut self) {
        if let Some(pair) = &mut self.app {
            pair.confirm();
        }
    }

    pub(in crate::conn::wire) fn early(&mut self) -> Option<LongRead<'_, kind::ZeroRtt>> {
        let key = self.long.zero_rtt_read.as_ref()?;
        Some(LongRead {
            key,
            fails: &mut self.failures,
        })
    }

    pub(super) fn try_pending(&mut self) -> Result<keys::Pending<'_>, conn::Error> {
        self.app
            .as_mut()
            .ok_or(conn::Error::Tls(conn::wire::Tls::MissingApplicationKeys))?
            .try_pending()
    }

    pub(super) fn try_admit(&mut self, limit: u64) -> Result<(), conn::Error> {
        self.failures.admit(limit).map_err(Into::into)
    }

    pub(in crate::conn) fn drop_early(&mut self) {
        self.long.zero_rtt_read = None;
        self.long.zero_rtt_write = None;
    }

    pub(super) fn discard(&mut self, epoch: conn::Epoch) {
        self.long.discard(epoch);
        if epoch == conn::Epoch::Application {
            self.app = None;
        }
    }
}

const _: () = {
    assert!(
        mem::size_of::<State>()
            <= mem::size_of::<Option<keys::Pair>>()
                + mem::size_of::<LongKeys>()
                + mem::size_of::<Failures>()
    );
    assert!(
        mem::size_of::<LongAccess<'_, kind::Initial>>()
            == 2 * mem::size_of::<&crypto::Key<kind::Initial, origin::Local, op::Seal>>()
    );
    assert!(!mem::needs_drop::<LongAccess<'_, kind::Initial>>());
    assert!(
        mem::size_of::<LongPermit<'_, kind::Initial>>()
            == mem::size_of::<&crypto::Key<kind::Initial, origin::Local, op::Seal>>()
    );
    assert!(!mem::needs_drop::<LongPermit<'_, kind::Initial>>());
};
