use crate::security::crypto::output;
use o3::{buffer::write, mem::Rejected};
use rustls::Error;
use std::{mem, time};

use crate::{
    conn,
    conn::wire::tls::{ciphers, keys},
    proto::recovery::numbers,
    security::crypto,
    wire::packet::{header, kind, long, short},
};
use crypto::op;

#[derive(Clone, Copy)]
enum Candidate {
    Current,
    Previous,
    Next,
}

pub(in crate::conn::wire) struct Read<'key> {
    read: &'key mut keys::ReadKeys,
    write: &'key mut keys::WriteKeys,
    fails: &'key mut ciphers::Failures,
}

impl<'key> Read<'key> {
    pub(super) fn new(
        read: &'key mut keys::ReadKeys,
        write: &'key mut keys::WriteKeys,
        fails: &'key mut ciphers::Failures,
    ) -> Self {
        Self { read, write, fails }
    }

    pub(in crate::conn::wire) fn open<P: long::Buffer>(
        self,
        wire: short::Protected<P>,
        next: u64,
        now: time::Instant,
        pto: time::Duration,
    ) -> Result<crypto::Opened<P>, Rejected<P, conn::Error>> {
        self.read.expire(now);
        let opened = self.read.current.unprotect(wire, next, |number, phase| {
            let pn = number.get();
            if phase == self.read.phase {
                (Candidate::Current, self.read.current.packet_key())
            } else if let Some(previous) = self.read.previous.as_ref()
                && self.read.first_current_pn.is_none_or(|first| pn < first)
            {
                (Candidate::Previous, previous.generation.packet_key())
            } else {
                (Candidate::Next, self.read.next.packet_key())
            }
        });
        let (key, opened) = match opened {
            Ok(opened) => opened,
            Err(error) => {
                if matches!(error.error, crypto::Error::Decrypt(Error::DecryptError))
                    && let Err(limit) = self.fails.record()
                {
                    return Err(Rejected::new(error.packet, limit));
                }
                return Err(Rejected::new(
                    error.packet,
                    conn::Error::Crypto(error.error),
                ));
            }
        };
        let pn = opened.number().get();
        match key {
            Candidate::Current => {
                self.read.first_current_pn.get_or_insert(pn);
            }
            Candidate::Previous => {}
            Candidate::Next => {
                if !self.read.can_advance() || !self.write.can_advance() {
                    let (_, packet, _) = opened.into_parts();
                    return Err(Rejected::new(packet, conn::Error::KeyUpdate));
                }
                if let Err(error) = self.read.promote(pn, now, pto) {
                    let (_, packet, _) = opened.into_parts();
                    return Err(Rejected::new(packet, error.into()));
                }
                if self.write.phase != self.read.phase
                    && let Err(error) = self.write.advance()
                {
                    let (_, packet, _) = opened.into_parts();
                    return Err(Rejected::new(packet, error.into()));
                }
            }
        }
        if !opened.is_valid() {
            let (_, packet, _) = opened.into_parts();
            return Err(Rejected::new(packet, conn::Error::ProtocolViolation));
        }
        Ok(opened)
    }
}

#[repr(transparent)]
pub(in crate::conn) struct Write<'key> {
    write: &'key keys::WriteKeys,
}

/// A single reserved app-key encryption operation.
#[repr(transparent)]
pub(in crate::conn) struct Permit<'key> {
    write: &'key keys::WriteKeys,
}

impl<'key> Write<'key> {
    pub(super) fn new(write: &'key keys::WriteKeys) -> Self {
        Self { write }
    }

    pub(in crate::conn) const fn is_key_phase(&self) -> bool {
        self.write.phase
    }

    pub(in crate::conn) fn permit(self) -> Result<Permit<'key>, crypto::Error> {
        self.write.begin()?;
        Ok(Permit { write: self.write })
    }
}

impl Permit<'_> {
    pub(in crate::conn) fn seal<'packet, A>(
        self,
        dst: write::Append<'packet>,
        header: header::Body<'_, '_, kind::OneRtt>,
        auth: A,
    ) -> Result<(op::Wire<'packet>, op::Protected<A>), crypto::Error> {
        let pn = header.number();
        let (head, proof) = self.write.current.seal(dst, header, auth)?;
        self.write.finish(pn);
        Ok((head, proof))
    }

    pub(in crate::conn) fn seal_draft<'packet>(
        self,
        draft: output::Draft<'packet>,
        auth: numbers::Sealing,
    ) -> Result<(op::Wire<'packet>, op::Protected<numbers::Sealing>), crypto::Error> {
        let pn = auth.full();
        let (head, proof) = self.write.current.seal_draft(draft, auth)?;
        self.write.finish(pn);
        Ok((head, proof))
    }

    pub(in crate::conn) fn protect<'packet, A>(
        self,
        packet: output::Packet<'packet>,
        auth: A,
    ) -> Result<(op::Wire<'packet>, op::Protected<A>), crypto::Error> {
        let pn = packet.number();
        let (wire, proof) = self.write.current.protect(packet, auth)?;
        self.write.finish(pn);
        Ok((wire, proof))
    }
}

const _: () = {
    assert!(mem::size_of::<Write<'_>>() == mem::size_of::<&keys::WriteKeys>());
    assert!(mem::size_of::<Permit<'_>>() == mem::size_of::<&keys::WriteKeys>());
    assert!(!mem::needs_drop::<Permit<'_>>());
};
