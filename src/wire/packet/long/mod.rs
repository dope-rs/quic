use std::{marker, mem, num::NonZero, ops};

use crate::wire::packet::header;
use dope::manifold::network::datagram::packet;
use o3::buffer::write::consume;
use o3::buffer::{self, storage::provided};

use crate::security::crypto::{self, op};
use crate::wire::packet::{cid, decode, kind};
use crate::{conn, security::qkdf, wire::varint};

pub mod early;
mod fields;
pub mod initial;
pub mod retry;
pub(crate) mod sequence;
pub mod setup;

pub(crate) use fields::Fields;

pub(crate) trait Buffer: buffer::raw::Mutable + Sized {}

impl Buffer for &mut [u8] {}

impl<'d, T: provided::Mutable<'d>> Buffer for packet::Packet<'_, 'd, T> {}

impl<'d, T: provided::Mutable<'d>> Buffer for packet::Head<'_, '_, 'd, T> {}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

impl Type {
    const KINDS: [Self; 4] = [Self::Initial, Self::ZeroRtt, Self::Handshake, Self::Retry];

    fn decode(first: u8) -> Result<Self, decode::Error> {
        if first & super::FORM_LONG == 0 {
            return Err(decode::Error::Form { first });
        }
        if first & super::FIXED_BIT == 0 {
            return Err(decode::Error::Fixed { first });
        }
        let bits = (first & super::LONG_TYPE_MASK) >> 4;
        Ok(Self::KINDS[usize::from(bits)])
    }
}

struct Prefix<'wire> {
    first: u8,
    kind: Type,
    ids: super::Ids<'wire>,
}

impl<'wire> Prefix<'wire> {
    fn decode(input: &'wire [u8]) -> Result<Self, decode::Error> {
        if input.len() < 5 {
            return Err(decode::Error::Underflow {
                actual: input.len(),
                required: 5,
            });
        }
        let first = input[0];
        let kind = Type::decode(first)?;
        let ver = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);
        if ver != super::QUIC_V1 {
            return Err(decode::Error::Version { actual: ver });
        }
        let ids = super::Ids::decode(input)?;
        Ok(Self { first, kind, ids })
    }

    fn ensure(self, want: Type) -> Result<Self, decode::Error> {
        if self.kind != want {
            return Err(decode::Error::Type { first: self.first });
        }
        Ok(self)
    }
}

fn decode_length(input: &[u8], pos: &mut usize) -> Result<varint::VarInt, decode::Error> {
    let offset = *pos;
    let Some(tail) = input.get(offset..) else {
        return Err(decode::Error::Underflow {
            actual: input.len(),
            required: offset,
        });
    };
    let (length, used) = match varint::VarInt::decode(tail) {
        Ok(read) => read,
        Err(error) => return Err(decode::Error::VarInt { offset, error }),
    };
    *pos = offset + used;
    Ok(length)
}

#[derive(Clone)]
pub(super) struct Layout<'wire, T = ()> {
    ids: super::Ids<'wire>,
    pub(super) token: T,
    pub(super) pn_offset: NonZero<usize>,
    pub(super) length: usize,
    pub(super) packet_len: NonZero<usize>,
}

#[derive(Clone, Copy)]
struct Proof {
    scid: cid::Span,
    pn_offset: NonZero<usize>,
}

/// Decoding the length consumes at least one byte, proving a nonempty packet extent.
/// The admitted slice offset plus a 62-bit length fits usize.
fn measure<'wire, T>(
    prefix: Prefix<'wire>,
    mut pos: usize,
    token: T,
) -> Result<Layout<'wire, T>, decode::Error> {
    let size = decode_length(prefix.ids.input, &mut pos)?;
    let length = size.get() as usize;
    let total = pos + length;
    let total = NonZero::<usize>::MIN.saturating_add(total - 1);
    Ok(Layout {
        ids: prefix.ids,
        token,
        pn_offset: NonZero::<usize>::MIN.saturating_add(pos - 1),
        length,
        packet_len: total,
    })
}

fn finish<'wire, T>(
    prefix: Prefix<'wire>,
    pos: usize,
    token: T,
) -> Result<Layout<'wire, T>, decode::Error> {
    let layout = measure(prefix, pos, token)?;
    consume::Error::check(layout.packet_len.get(), layout.ids.input.len())
        .map_err(decode::Error::Packet)?;
    Ok(layout)
}

fn take(
    input: &[u8],
    pos: &mut usize,
    size: varint::VarInt,
) -> Result<ops::Range<usize>, decode::Error> {
    let start = *pos;
    let length = size.get() as usize;
    let Some(left) = input.len().checked_sub(start) else {
        return Err(decode::Error::Underflow {
            actual: input.len(),
            required: start,
        });
    };
    if length > left {
        let required = start + length;
        return Err(decode::Error::Underflow {
            actual: input.len(),
            required,
        });
    }
    let end = start + length;
    *pos = end;
    Ok(start..end)
}

fn initial(prefix: Prefix<'_>) -> Result<Layout<'_, ops::Range<usize>>, decode::Error> {
    let input = prefix.ids.input;
    let mut pos = prefix.ids.end();
    let size = decode_length(input, &mut pos)?;
    let token = take(input, &mut pos, size)?;
    finish(prefix, pos, token)
}

fn initial_head(prefix: Prefix<'_>) -> Result<Layout<'_, ops::Range<usize>>, decode::Error> {
    let input = prefix.ids.input;
    let mut pos = prefix.ids.end();
    let size = decode_length(input, &mut pos)?;
    let token = take(input, &mut pos, size)?;
    measure(prefix, pos, token)
}

pub(super) fn decode_initial(input: &[u8]) -> Result<Layout<'_, ops::Range<usize>>, decode::Error> {
    let prefix = Prefix::decode(input)?.ensure(Type::Initial)?;
    initial(prefix)
}

fn plain(prefix: Prefix<'_>) -> Result<Layout<'_>, decode::Error> {
    let pos = prefix.ids.end();
    finish(prefix, pos, ())
}

fn plain_head(prefix: Prefix<'_>) -> Result<Layout<'_>, decode::Error> {
    let pos = prefix.ids.end();
    measure(prefix, pos, ())
}

fn decode_plain(input: &[u8], kind: Type) -> Result<Layout<'_>, decode::Error> {
    let prefix = Prefix::decode(input)?.ensure(kind)?;
    plain(prefix)
}

/// Whether a prefix has the routing shape of a QUIC Initial.
pub(crate) fn has_initial_form(input: &[u8]) -> bool {
    matches!(input.first(), Some(&first) if first & 0xb0 == super::FORM_LONG)
}

pub(crate) const fn is_initial_size(len: usize) -> bool {
    len >= conn::MIN_INITIAL_LEN
}

struct Route {
    dcid: cid::Span,
    scid: cid::Span,
    token: ops::Range<usize>,
}

/// A minimum-sized server Initial owning its decoded datagram.
#[must_use = "validated Initial storage must be consumed or deliberately dropped"]
pub(crate) struct Admission<P> {
    packet: P,
    route: Route,
}

impl<P: buffer::raw::Source> Admission<P> {
    pub(crate) fn try_new(packet: P) -> Result<Self, decode::Error> {
        let route = {
            let input = packet.as_ref();
            if !is_initial_size(input.len()) {
                return Err(decode::Error::Size {
                    actual: input.len(),
                    minimum: conn::MIN_INITIAL_LEN,
                });
            }
            let read = decode_initial(input)?;
            Route {
                dcid: read.ids.dcid,
                scid: read.ids.scid,
                token: read.token,
            }
        };
        Ok(Self { packet, route })
    }

    pub(crate) fn dcid(&self) -> cid::Ref<'_> {
        // SAFETY: admission retains the exact source whose CID extent was decoded.
        unsafe { self.route.dcid.get(self.packet.as_ref()) }
    }

    pub(crate) fn scid(&self) -> cid::Ref<'_> {
        // SAFETY: admission retains the exact source whose CID extent was decoded.
        unsafe { self.route.scid.get(self.packet.as_ref()) }
    }

    pub(crate) fn token(&self) -> &[u8] {
        // SAFETY: construction admitted this token in the retained stable source.
        unsafe { self.packet.as_ref().get_unchecked(self.route.token.clone()) }
    }

    pub(crate) fn datagram_len(&self) -> usize {
        self.packet.as_ref().len()
    }

    pub(crate) fn into_inner(self) -> P {
        self.packet
    }
}

/// A protected long header refined to its encoded packet kind.
pub enum Parsed<P> {
    Initial(Protected<kind::Initial, P>),
    ZeroRtt(Protected<kind::ZeroRtt, P>),
    Handshake(Protected<kind::Handshake, P>),
}

/// A protected long header bound to its owner and packet kind.
pub struct Protected<K: kind::Long, P> {
    packet: P,
    proof: Proof,
    marker: marker::PhantomData<fn() -> K>,
}

#[derive(Clone, Copy)]
enum Shape {
    Initial,
    ZeroRtt,
    Handshake,
}

#[derive(Clone, Copy)]
struct Read {
    proof: Proof,
    len: NonZero<usize>,
    shape: Shape,
}

impl Read {
    fn bind<P>(self, packet: P) -> Parsed<P> {
        match self.shape {
            Shape::Initial => Parsed::Initial(Protected::new(packet, self.proof)),
            Shape::ZeroRtt => Parsed::ZeroRtt(Protected::new(packet, self.proof)),
            Shape::Handshake => Parsed::Handshake(Protected::new(packet, self.proof)),
        }
    }

    fn decode(input: &[u8]) -> Result<Self, decode::Error> {
        let read = Self::first(input)?;
        consume::Error::check(read.len.get(), input.len()).map_err(decode::Error::Packet)?;
        Ok(read)
    }

    fn first(input: &[u8]) -> Result<Self, decode::Error> {
        let prefix = Prefix::decode(input)?;
        match prefix.kind {
            Type::Initial => initial_head(prefix).map(|layout| layout.into_read(Shape::Initial)),
            Type::ZeroRtt => plain_head(prefix).map(|layout| layout.into_read(Shape::ZeroRtt)),
            Type::Handshake => plain_head(prefix).map(|layout| layout.into_read(Shape::Handshake)),
            Type::Retry => Err(decode::Error::Type {
                first: prefix.first,
            }),
        }
    }
}

impl<'wire> Layout<'wire, ops::Range<usize>> {
    fn token(&self) -> &'wire [u8] {
        // SAFETY: initial decoding admitted the token in this retained source.
        unsafe { self.ids.input.get_unchecked(self.token.clone()) }
    }
}

impl<T> Layout<'_, T> {
    fn into_read(self, shape: Shape) -> Read {
        Read {
            proof: Proof {
                scid: self.ids.scid,
                pn_offset: self.pn_offset,
            },
            len: self.packet_len,
            shape,
        }
    }
}

impl<P: buffer::raw::Source> Parsed<P> {
    pub fn parse(packet: P) -> Result<Self, decode::Error> {
        let input = packet.as_ref();
        let read = Read::decode(input)?;
        let wire = input.len();
        let total = read.len;
        if total.get() != wire {
            return Err(decode::Error::Trailing {
                packet: total,
                datagram: wire,
            });
        }
        Ok(read.bind(packet))
    }

    pub fn kind(&self) -> Type {
        match self {
            Self::Initial(_) => Type::Initial,
            Self::ZeroRtt(_) => Type::ZeroRtt,
            Self::Handshake(_) => Type::Handshake,
        }
    }

    pub fn scid(&self) -> cid::Id {
        match self {
            Self::Initial(packet) => packet.scid(),
            Self::ZeroRtt(packet) => packet.scid(),
            Self::Handshake(packet) => packet.scid(),
        }
    }
}

impl<K: kind::Long, P> Protected<K, P> {
    fn new(packet: P, proof: Proof) -> Self {
        Self {
            packet,
            proof,
            marker: marker::PhantomData,
        }
    }
}

impl<K: kind::Long, P: buffer::raw::Source> Protected<K, P> {
    pub fn scid(&self) -> cid::Id {
        // SAFETY: parsing binds the decoded extent to this exact stable source.
        unsafe { self.proof.scid.get(self.packet.as_ref()) }.into_owned()
    }
}

impl<K: kind::Long, P: buffer::raw::Mutable> Protected<K, P> {
    pub fn decrypt<O: qkdf::KeyOrigin>(
        mut self,
        key: &crypto::Key<K, O, op::Open>,
        next: u64,
    ) -> Result<Decrypted<K, P>, crypto::Error> {
        let (number, body) = key.open_long(self.packet.as_mut(), self.proof.pn_offset, next)?;
        Ok(Decrypted {
            packet: self.packet,
            packet_number: number,
            body,
            marker: marker::PhantomData,
        })
    }
}

pub struct Decrypted<K: kind::Long, P> {
    packet: P,
    packet_number: header::Number,
    body: ops::Range<usize>,
    marker: marker::PhantomData<fn() -> K>,
}

impl<K: kind::Long, P: buffer::raw::Source> Decrypted<K, P> {
    pub fn number(&self) -> u64 {
        self.packet_number.get()
    }

    pub fn body(&self) -> &[u8] {
        // SAFETY: successful open_long admitted this range in this exact
        // stable owner, whose extent cannot change through shared access.
        unsafe { self.packet.as_ref().get_unchecked(self.body.clone()) }
    }

    pub fn into_parts(self) -> (u64, P, ops::Range<usize>) {
        (self.packet_number.get(), self.packet, self.body)
    }

    pub(crate) fn into_bound(self) -> (header::Number, P, ops::Range<usize>) {
        (self.packet_number, self.packet, self.body)
    }
}

const _: () = assert!(usize::BITS >= 64);
const _: () = assert!(mem::size_of::<Proof>() <= 16);
const _: () = assert!(mem::size_of::<Admission<&[u8]>>() <= mem::size_of::<&[u8]>() + 24);
