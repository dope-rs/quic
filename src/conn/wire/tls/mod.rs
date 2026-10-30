use o3::alloc;
use rustls::{Error, HandshakeKind, quic};

use crate::conn::life::tls::clients;
use crate::conn::machine::storage::capacity;
use crate::conn::wire::crypto::tx;
use crate::conn::{self, wire};
use crate::security::{crypto, qkdf};
use crate::wire::packet::kind;
use crypto::op;
use qkdf::origin;

mod borrow;
pub(in crate::conn) use borrow::Borrow;
pub(in crate::conn) mod ciphers;
mod finish;
mod keys;
pub(in crate::conn) mod packets;
mod peers;
mod progress;
use progress::{Early, Progress, State};

pub(in crate::conn) use finish::Finish;

/// Maximum retained CRYPTO output in one packet-number space.
pub(in crate::conn) const MAX_CRYPTO_BYTES: usize = 64 * 1024;

pub(in crate::conn) struct Handshake<const DOMAIN: u8, A = Option<clients::Authority>> {
    tls: quic::Connection,
    progress: Progress,
    pub(in crate::conn) keys: ciphers::State,
    pub(in crate::conn) crypto: tx::Tx,
    pub(in crate::conn) peer: peers::State<A>,
}

pub(in crate::conn) struct Outcome<'a> {
    pub(in crate::conn) done: Option<Completion<'a>>,
    pub(in crate::conn) keys_changed: bool,
}

/// Completion retains activation access to the published application keys.
pub(in crate::conn) struct Completion<'a> {
    keys: keys::Pending<'a>,
    params: Option<&'a [u8]>,
    early: bool,
}

#[derive(Default)]
struct Change {
    done: bool,
    reject_early: bool,
    keys_changed: bool,
}

impl<const DOMAIN: u8> Handshake<DOMAIN, ()> {
    pub(in crate::conn) fn bind_auth(self, auth: clients::Authority) -> Handshake<DOMAIN> {
        Handshake {
            tls: self.tls,
            progress: self.progress,
            keys: self.keys,
            crypto: self.crypto,
            peer: self.peer.bind_auth(auth),
        }
    }
}

impl<const DOMAIN: u8, A> Handshake<DOMAIN, A> {
    pub(in crate::conn) fn keys(&self) -> Borrow<'_, DOMAIN> {
        Borrow { keys: &self.keys }
    }

    pub(in crate::conn) fn parts(&mut self) -> (&mut tx::Tx, Borrow<'_, DOMAIN>) {
        (&mut self.crypto, Borrow { keys: &self.keys })
    }

    pub(in crate::conn) fn try_new(
        tls: quic::Connection,
        rx: crypto::Key<kind::Initial, origin::Peer, op::Open>,
        tx: crypto::Key<kind::Initial, origin::Local, op::Seal>,
        cap: capacity::Capacity<capacity::Crypto>,
        auth: A,
    ) -> Result<Self, alloc::Error> {
        Ok(Self {
            tls,
            progress: Progress::new(),
            keys: ciphers::State::new(rx, tx),
            crypto: tx::Tx::try_new(cap)?,
            peer: peers::State::new(auth),
        })
    }

    pub(in crate::conn) fn is_pending(&self) -> bool {
        !matches!(self.progress.state, State::Complete)
    }

    pub(in crate::conn) fn read<'a>(
        &'a mut self,
        epoch: conn::Epoch,
        data: &[u8],
        failure: &mut impl FnMut(&Error),
        reject: impl FnOnce(&mut Self) -> Result<(), conn::Error>,
    ) -> Result<Outcome<'a>, conn::Error> {
        if matches!(self.progress.state, State::Failed) {
            return Err(conn::Error::ProtocolViolation);
        }
        if epoch != self.progress.read {
            self.progress.state = State::Failed;
            return Err(conn::Error::Tls(wire::Tls::Epoch(epoch)));
        }
        self.read_tls(data, failure)?;
        let change = self.advance()?;
        if change.reject_early {
            reject(self)?;
        }
        let done = if change.done {
            Some(Completion {
                keys: self.keys.try_pending()?,
                params: self.tls.quic_transport_parameters(),
                early: self.peer.is_early(),
            })
        } else {
            None
        };
        Ok(Outcome {
            done,
            keys_changed: change.keys_changed,
        })
    }

    fn read_tls(
        &mut self,
        data: &[u8],
        failure: &mut impl FnMut(&Error),
    ) -> Result<(), conn::Error> {
        self.tls.read_hs(data).map_err(|error| {
            self.progress.state = State::Failed;
            if matches!(
                error,
                Error::InvalidCertificate(_)
                    | Error::InvalidCertRevocationList(_)
                    | Error::NoCertificatesPresented
                    | Error::UnsupportedNameType
            ) {
                failure(&error);
            }
            conn::Error::Handshake(wire::Handshake {
                error,
                alert: self.tls.alert(),
            })
        })
    }

    pub(in crate::conn) fn try_start(&mut self) -> Result<(), conn::Error> {
        self.advance().map(|_| ())
    }

    pub(in crate::conn) fn early_params(&self) -> Option<Result<&[u8], conn::Error>> {
        if !matches!(self.progress.early, Early::Offered) {
            return None;
        }
        Some(self.params())
    }

    fn params(&self) -> Result<&[u8], conn::Error> {
        self.tls
            .quic_transport_parameters()
            .ok_or(conn::Error::TransportParameterMismatch)
    }

    fn advance(&mut self) -> Result<Change, conn::Error> {
        if matches!(self.progress.state, State::Failed) {
            return Err(conn::Error::ProtocolViolation);
        }
        let result = self.drain();
        if result.is_err() {
            self.progress.state = State::Failed;
        }
        result
    }

    /// Commits each flight before publishing its next keys; failure is terminal.
    fn drain(&mut self) -> Result<Change, conn::Error> {
        let mut outcome = Change::default();
        if matches!(
            self.tls.handshake_kind(),
            Some(HandshakeKind::FullWithHelloRetryRequest)
        ) {
            outcome.reject_early = matches!(self.progress.early, Early::Offered)
                && matches!(self.tls, quic::Connection::Client(_));
            self.progress.early = Early::Rejected;
            self.keys.drop_early();
        }
        if matches!(self.progress.early, Early::Unavailable)
            && self.progress.write == conn::Epoch::Initial
            && let Some(keys) = self.tls.zero_rtt_keys()
        {
            match self.tls {
                quic::Connection::Client(_) => {
                    let key = crypto::Key::try_new(keys)?;
                    self.keys.long.zero_rtt_write = Some(ciphers::LongWrite::new(key));
                }
                quic::Connection::Server(_) => {
                    self.keys.try_admit(keys.packet.integrity_limit())?;
                    self.keys.long.zero_rtt_read = Some(crypto::Key::try_new(keys)?);
                }
            }
            self.progress.early = Early::Offered;
        }
        loop {
            let change = self
                .crypto
                .bytes
                .try_write(self.progress.write, &mut self.tls)
                .map_err(conn::Error::Tls)?;
            match change {
                Some(quic::KeyChange::Handshake { keys }) => {
                    self.keys.try_admit(keys.remote.packet.integrity_limit())?;
                    let read = crypto::Key::try_new(keys.remote)?;
                    let write = crypto::Key::try_new(keys.local)?;
                    self.keys.long.handshake_read = Some(read);
                    self.keys.long.handshake_write = Some(ciphers::LongWrite::new(write));
                    self.progress.read = conn::Epoch::Handshake;
                    self.progress.write = conn::Epoch::Handshake;
                }
                Some(quic::KeyChange::OneRtt { keys, next }) => {
                    self.keys.try_install(keys, next)?;
                    self.keys.long.zero_rtt_write = None;
                    self.progress.write = conn::Epoch::Application;
                }
                None => break,
            }
            outcome.keys_changed = true;
        }
        if matches!(self.progress.state, State::Handshaking) && !self.tls.is_handshaking() {
            let accepted = match &self.tls {
                quic::Connection::Client(tls) => tls.is_early_data_accepted(),
                quic::Connection::Server(_) => matches!(self.progress.early, Early::Offered),
            };
            if accepted {
                self.peer.accept_early();
            } else if matches!(self.progress.early, Early::Offered) {
                self.keys.long.zero_rtt_write = None;
                self.progress.early = Early::Rejected;
                outcome.reject_early = true;
            }
            self.progress.state = State::Complete;
            self.progress.read = conn::Epoch::Application;
            outcome.done = true;
        }
        Ok(outcome)
    }

    pub(in crate::conn) fn discard(&mut self, epoch: conn::Epoch) {
        self.keys.discard(epoch);
        self.crypto.discard(epoch);
    }
}
