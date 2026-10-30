use crate::{
    conn::{
        output::transmit::{self, builder::pending, packet::plan::Plan},
        wire::tls::{self, ciphers, packets},
    },
    proto::{datagram, recovery::numbers},
    security::crypto,
    stream,
    wire::packet::{self, header, kind, long},
};
use crypto::{op, output};
use o3::buffer::{self, write};
use std::{mem, num::NonZero};

pub(in crate::conn::output::transmit) struct Sealed<T> {
    output: T,
    bytes: usize,
    packet_number: op::Protected<numbers::Sealing>,
}

pub(in crate::conn::output::transmit) enum Failure<P, T> {
    Retry(P, T),
    Crypto(crypto::Error),
}

/// Packet sealing whose permit borrows its key epoch.
pub(in crate::conn::output::transmit) trait Seal<const DOMAIN: u8>:
    output::Extent + Sized
{
    type Output;
    type Permit<'a>
    where
        Self: 'a;

    fn reserve<'key>(
        state: tls::Borrow<'key, DOMAIN>,
    ) -> Result<Option<Self::Permit<'key>>, crypto::Error>
    where
        Self: 'key;

    fn seal<'key>(
        self,
        permit: Self::Permit<'key>,
        number: numbers::Sealing,
    ) -> Result<Sealed<Self::Output>, crypto::Error>
    where
        Self: 'key;
}

pub(in crate::conn::output::transmit) trait LongKind<const DOMAIN: u8>:
    kind::Long + Sized
{
    fn write_key<'key>(state: tls::Borrow<'key, DOMAIN>)
    -> Option<ciphers::LongAccess<'key, Self>>;
}

impl<const DOMAIN: u8> LongKind<DOMAIN> for kind::Initial {
    fn write_key<'key>(
        state: tls::Borrow<'key, DOMAIN>,
    ) -> Option<ciphers::LongAccess<'key, Self>> {
        state.get().long.initial().map(ciphers::LongWrite::access)
    }
}

impl<const DOMAIN: u8> LongKind<DOMAIN> for kind::Handshake {
    fn write_key<'key>(
        state: tls::Borrow<'key, DOMAIN>,
    ) -> Option<ciphers::LongAccess<'key, Self>> {
        state.get().long.handshake().map(ciphers::LongWrite::access)
    }
}

impl<const DOMAIN: u8> LongKind<DOMAIN> for kind::ZeroRtt {
    fn write_key<'key>(
        state: tls::Borrow<'key, DOMAIN>,
    ) -> Option<ciphers::LongAccess<'key, Self>> {
        state.get().long.early().map(ciphers::LongWrite::access)
    }
}

pub(in crate::conn::output::transmit) struct Long<'a, 'b, 'c, K: kind::Long> {
    dst: write::Append<'a>,
    header: header::Body<'b, 'c, K>,
}

impl<'a, 'b, 'c, K: kind::Long> Long<'a, 'b, 'c, K> {
    pub(in crate::conn::output::transmit) fn new(
        dst: &'a mut write::Append<'_>,
        header: header::Body<'b, 'c, K>,
    ) -> Self {
        Self {
            dst: dst.append(),
            header,
        }
    }
}

impl<K: kind::Long> output::Extent for Long<'_, '_, '_, K> {
    fn wire_len(&self) -> NonZero<usize> {
        self.header.wire_len()
    }
}

impl<'a, 'b, 'c, const DOMAIN: u8, K: LongKind<DOMAIN>> Seal<DOMAIN> for Long<'a, 'b, 'c, K> {
    type Output = ();
    type Permit<'key>
        = ciphers::LongPermit<'key, K>
    where
        Self: 'key;

    fn reserve<'key>(
        state: tls::Borrow<'key, DOMAIN>,
    ) -> Result<Option<Self::Permit<'key>>, crypto::Error>
    where
        Self: 'key,
    {
        K::write_key(state)
            .map(ciphers::LongAccess::permit)
            .transpose()
    }

    fn seal<'key>(
        self,
        permit: Self::Permit<'key>,
        number: numbers::Sealing,
    ) -> Result<Sealed<Self::Output>, crypto::Error>
    where
        Self: 'key,
    {
        let (wire, number) = permit.seal_into(self.dst, self.header, number)?;
        Ok(Sealed {
            output: (),
            bytes: wire.into_len(),
            packet_number: number,
        })
    }
}

pub(in crate::conn::output::transmit) struct Segments<'a, 'b, 'c> {
    dst: write::Append<'a>,
    header: header::Body<'b, 'c, kind::OneRtt>,
}

impl<'a, 'b, 'c> Segments<'a, 'b, 'c> {
    pub(in crate::conn::output::transmit) fn new(
        dst: &'a mut write::Append<'_>,
        header: header::Ref<'b, kind::OneRtt>,
        payload: &'c [u8],
    ) -> Self {
        Self {
            dst: dst.append(),
            header: header::Body::new(header, payload),
        }
    }
}

impl output::Extent for Segments<'_, '_, '_> {
    fn wire_len(&self) -> NonZero<usize> {
        self.header.wire_len()
    }
}

impl<'a, const DOMAIN: u8> Seal<DOMAIN> for output::Draft<'a> {
    type Output = ();
    type Permit<'key>
        = packets::Permit<'key>
    where
        Self: 'key;

    fn reserve<'key>(
        state: tls::Borrow<'key, DOMAIN>,
    ) -> Result<Option<Self::Permit<'key>>, crypto::Error>
    where
        Self: 'key,
    {
        state.get().write().map(packets::Write::permit).transpose()
    }

    fn seal<'key>(
        self,
        permit: Self::Permit<'key>,
        number: numbers::Sealing,
    ) -> Result<Sealed<Self::Output>, crypto::Error>
    where
        Self: 'key,
    {
        let (wire, number) = permit.seal_draft(self, number)?;
        Ok(Sealed {
            output: (),
            bytes: wire.into_len(),
            packet_number: number,
        })
    }
}

impl<'a, 'b, 'c, const DOMAIN: u8> Seal<DOMAIN> for Segments<'a, 'b, 'c> {
    type Output = ();
    type Permit<'key>
        = packets::Permit<'key>
    where
        Self: 'key;

    fn reserve<'key>(
        state: tls::Borrow<'key, DOMAIN>,
    ) -> Result<Option<Self::Permit<'key>>, crypto::Error>
    where
        Self: 'key,
    {
        state.get().write().map(packets::Write::permit).transpose()
    }

    fn seal<'key>(
        self,
        permit: Self::Permit<'key>,
        number: numbers::Sealing,
    ) -> Result<Sealed<Self::Output>, crypto::Error>
    where
        Self: 'key,
    {
        let (wire, number) = permit.seal(self.dst, self.header, number)?;
        Ok(Sealed {
            output: (),
            bytes: wire.into_len(),
            packet_number: number,
        })
    }
}

impl<'a, const DOMAIN: u8> Seal<DOMAIN> for output::Prepared<'a> {
    type Output = datagram::Sealed<'a>;
    type Permit<'key>
        = packets::Permit<'key>
    where
        Self: 'key;

    fn reserve<'key>(
        state: tls::Borrow<'key, DOMAIN>,
    ) -> Result<Option<Self::Permit<'key>>, crypto::Error>
    where
        Self: 'key,
    {
        state.get().write().map(packets::Write::permit).transpose()
    }

    fn seal<'key>(
        self,
        permit: Self::Permit<'key>,
        number: numbers::Sealing,
    ) -> Result<Sealed<Self::Output>, crypto::Error>
    where
        Self: 'key,
    {
        let (packet, (bytes, number)) = self.protect(|packet| {
            let (wire, number) = permit.protect(packet, number)?;
            Ok((wire.into_len(), number))
        })?;
        Ok(Sealed {
            output: packet,
            bytes,
            packet_number: number,
        })
    }
}

pub(in crate::conn::output::transmit) fn packet<const DOMAIN: u8, P: Seal<DOMAIN>>(
    state: tls::Borrow<'_, DOMAIN>,
    space: &mut numbers::PnSpace,
    seal: P,
    plan: Plan<numbers::Packet>,
) -> Result<(P::Output, Plan), Failure<P, Plan<numbers::Packet>>> {
    let plan = match plan.bind_number(space) {
        Ok(plan) => plan,
        Err(plan) => return Err(Failure::Retry(seal, plan)),
    };
    let Some(permit) = P::reserve(state).map_err(Failure::Crypto)? else {
        return Err(Failure::Retry(seal, plan.release()));
    };
    let sealed = plan.try_number(|number| {
        let number = number.begin();
        let Sealed {
            output,
            bytes,
            packet_number: number,
        } = seal.seal(permit, number)?;
        Ok::<_, crypto::Error>(((output, bytes), number))
    });
    let ((output, bytes), mut plan) = sealed.map_err(Failure::Crypto)?;
    plan.bytes = bytes;
    Ok((output, plan))
}

pub(in crate::conn::output::transmit) fn long<'a, const DOMAIN: u8, B, D, K>(
    dst: &mut write::Append<'_>,
    frames: &[u8],
    mut pending: pending::Packet<'a, DOMAIN, B, D, numbers::Packet, ()>,
) -> transmit::Protected<'a, DOMAIN, B, D, (), ()>
where
    B: stream::Recv,
    D: buffer::raw::Segment,
    K: LongKind<DOMAIN> + numbers::AckSpace,
{
    let number = pending.plan().packet_number.encoding();
    let mut header = mem::take(&mut pending.scratch().header);
    header.clear();
    let encoded = {
        let conn = pending.conn();
        let token = (K::TYPE == packet::LONG_INITIAL).then(|| conn.path.origin.initial());
        header::Body::<K>::try_new(
            long::Fields {
                version: packet::QUIC_V1,
                dcid: conn.path.peer.id().as_ref_id(),
                scid: conn.path.local.cid(),
                token,
                packet_number: number,
            },
            &mut header,
            frames,
        )
    };
    let encoded = match encoded {
        Ok(encoded) => encoded,
        Err(error) => {
            header.clear();
            pending.scratch().header = header;
            return Err(pending::Failure::Admission(
                (),
                pending.reject(),
                transmit::Admission::Header {
                    epoch: K::EPOCH,
                    error,
                },
            ));
        }
    };
    let ((), mut pending) = match pending.protect(Long::new(dst, encoded)) {
        Ok(sealed) => sealed,
        Err(failure) => {
            let mut failure = failure.release();
            header.clear();
            failure.scratch().header = header;
            return Err(failure);
        }
    };
    header.clear();
    pending.scratch().header = header;
    Ok(((), pending))
}
