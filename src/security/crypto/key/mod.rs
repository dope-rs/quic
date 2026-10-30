use crate::{security, wire};
use o3::{
    base::num::bounded,
    buffer::{bytes::scope, write},
};
use rustls::quic;
use security::{
    crypto::{Dimensions, Error, KeyOperation, Opened, Plain, op, output, plain},
    qkdf::{self, origin},
};
use std::{marker, mem, num::NonZero, ops};
use wire::packet::{
    header::{self, Number, widths},
    kind, long,
    short::Protected,
};

pub(in crate::security::crypto) mod cipher;

/// Packet protection branded by packet kind, sender origin, and operation.
#[repr(transparent)]
pub struct Key<K: kind::Kind, O: qkdf::KeyOrigin, U: KeyOperation> {
    key: cipher::Cipher<U>,
    kind: marker::PhantomData<fn() -> K>,
    origin: marker::PhantomData<fn() -> O>,
}

/// An application packet generation retaining its sender and operation proofs.
#[repr(transparent)]
pub(crate) struct Generation<O: qkdf::KeyOrigin, U: KeyOperation> {
    key: cipher::Packet<U>,
    origin: marker::PhantomData<fn() -> O>,
}

impl<K: kind::Kind, O: qkdf::KeyOrigin, U: KeyOperation> Key<K, O, U> {
    /// Admits the TLS owner's sample and tag dimensions after epoch and sender mapping.
    pub(crate) fn try_new(keys: quic::DirectionalKeys) -> Result<Self, Error> {
        Ok(Self {
            key: cipher::Cipher::try_new(keys)?,
            kind: marker::PhantomData,
            origin: marker::PhantomData,
        })
    }

    pub(crate) fn seal_limit(&self) -> u64 {
        self.key.packet.seal_limit()
    }

    pub(crate) fn open_limit(&self) -> u64 {
        self.key.packet.open_limit()
    }
}

impl<O: qkdf::KeyOrigin, U: KeyOperation> Key<kind::OneRtt, O, U> {
    /// Admits another packet generation while retaining this direction's header owner.
    pub(crate) fn try_next(
        &self,
        packet: Box<dyn quic::PacketKey>,
    ) -> Result<Generation<O, U>, Dimensions> {
        Ok(Generation {
            key: self.key.packet.try_next(packet)?,
            origin: marker::PhantomData,
        })
    }

    /// Replaces only the packet generation; the admitted header owner stays fixed.
    pub(crate) fn replace(&mut self, next: Generation<O, U>) -> Generation<O, U> {
        Generation {
            key: mem::replace(&mut self.key.packet, next.key),
            origin: marker::PhantomData,
        }
    }
}

impl<O: qkdf::KeyOrigin, U: KeyOperation> Generation<O, U> {
    pub(crate) fn try_next(&self, packet: Box<dyn quic::PacketKey>) -> Result<Self, Dimensions> {
        Ok(Self {
            key: self.key.try_next(packet)?,
            origin: marker::PhantomData,
        })
    }

    pub(crate) fn open_limit(&self) -> u64 {
        self.key.open_limit()
    }
}

impl<K: kind::Kind, O: qkdf::KeyOrigin> Key<K, O, op::Seal> {
    pub(crate) fn seal<'a, A>(
        &self,
        dst: write::Append<'a>,
        head: header::Body<'_, '_, K>,
        proof: A,
    ) -> Result<(op::Wire<'a, K>, op::Protected<A>), Error> {
        let packet = output::Packet::try_append(dst, head)?.encrypt(&self.key)?;
        Ok((packet, op::Protected::new(proof)))
    }
}

impl<O: qkdf::KeyOrigin> Key<kind::OneRtt, O, op::Seal> {
    pub(crate) fn seal_draft<'a, A>(
        &self,
        draft: output::Draft<'a>,
        proof: A,
    ) -> Result<(op::Wire<'a>, op::Protected<A>), Error> {
        let packet = draft.try_prepare()?.encrypt(&self.key)?;
        Ok((packet, op::Protected::new(proof)))
    }

    pub(crate) fn protect<'a, A>(
        &self,
        packet: output::Packet<'a>,
        proof: A,
    ) -> Result<(op::Wire<'a>, op::Protected<A>), Error> {
        let packet = packet.encrypt(&self.key)?;
        Ok((packet, op::Protected::new(proof)))
    }
}

impl<K: kind::Long, O: qkdf::KeyOrigin> Key<K, O, op::Open> {
    pub(crate) fn open_long(
        &self,
        wire: &mut [u8],
        pn_at: NonZero<usize>,
        next: u64,
    ) -> Result<(Number, ops::Range<usize>), Error> {
        let (number, body, bits) = open(&self.key.packet, self.unmask(wire, pn_at, next)?, 0x0c)?;
        if bits != 0 {
            return Err(Error::ReservedBits {
                actual: bits,
                mask: 0x0c,
            });
        }
        Ok((number, body))
    }
}

impl<O: qkdf::KeyOrigin> Key<kind::OneRtt, O, op::Open> {
    pub(crate) fn unprotect<'key, P: long::Buffer, C>(
        &'key self,
        sealed: Protected<P>,
        next: u64,
        select: impl FnOnce(Number, bool) -> (C, &'key cipher::Packet<op::Open>),
    ) -> Result<(C, Opened<P>), plain::Failure<P>> {
        let (mut packet, cid) = sealed.into_parts();
        let pn_at = NonZero::<usize>::MIN.saturating_add(usize::from(cid.get()));
        let result = self.unmask(packet.as_mut(), pn_at, next).and_then(|plain| {
            let (selected, key) = select(plain.packet_number, plain.first & 0x04 != 0);
            open(key, plain, 0x18).map(|opened| (selected, opened))
        });
        match result {
            Ok((selected, (number, body, bits))) => Ok((
                selected,
                Opened {
                    packet,
                    packet_number: number,
                    body,
                    reserved_bits: bits,
                    cid,
                },
            )),
            Err(error) => Err(plain::Failure { packet, error }),
        }
    }

    pub(crate) fn packet_key(&self) -> &cipher::Packet<op::Open> {
        &self.key.packet
    }
}

impl<O: qkdf::KeyOrigin> Generation<O, op::Open> {
    pub(crate) fn packet_key(&self) -> &cipher::Packet<op::Open> {
        &self.key
    }
}

fn open(
    key: &cipher::Packet<op::Open>,
    plain: Plain<'_>,
    reserved: u8,
) -> Result<(Number, ops::Range<usize>, u8), Error> {
    let Plain {
        head,
        body,
        packet_number: number,
        first,
    } = plain;
    let head_end = head.len();
    let bound = body.len();
    let size = key.open(number, head, body).map_err(Error::Decrypt)?.len();
    if size > bound {
        return Err(Error::BodyDimensions {
            actual: size,
            available: bound,
        });
    }
    Ok((number, head_end..head_end + size, first & reserved))
}

impl<K: kind::Kind, O: qkdf::KeyOrigin> Key<K, O, op::Open> {
    /// Retains the sample and adjacent mutable regions of this exact packet.
    fn unmask<'packet>(
        &self,
        wire: &'packet mut [u8],
        pn_at: NonZero<usize>,
        next: u64,
    ) -> Result<Plain<'packet>, Error> {
        let actual = wire.len();
        let required = pn_at.get() + header::SAMPLE_END;
        let Some(mut packet) = scope::raw::Window::<
            { header::SAMPLE_OFFSET },
            { header::SAMPLE_LEN },
        >::try_at(wire, pn_at) else {
            return Err(Error::Sample { actual, required });
        };
        let (first, number, sample) = packet.parts();
        self.key.unmask(sample, first, number)?;
        let first = *first;
        let width = widths::Width::from_first(first);
        let pn_len = width.get();
        let short = number
            .iter()
            .take(pn_len)
            .fold(0u64, |short, byte| (short << 8) | u64::from(*byte));
        let Some(number) = Number::decode(next, short, width) else {
            return Err(Error::Number {
                next,
                truncated: short,
                width: pn_len as u8,
            });
        };
        let (head, body) = packet.split(bounded::U64::<0, 3>::mask(u64::from(first)));
        Ok(Plain {
            head,
            body,
            packet_number: number,
            first,
        })
    }
}

const _: () = {
    assert!(
        mem::size_of::<Key<kind::Initial, origin::Client, op::Seal>>()
            == mem::size_of::<cipher::Cipher<op::Seal>>()
    );
};
