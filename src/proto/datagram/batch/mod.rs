use crate::{
    conn::{self, output::transmit},
    errors,
    proto::datagram,
    security::crypto,
};
use datagram::batch;
use o3::depot;
use o3::{
    buffer::pool::borrowed,
    depot::{
        array::{self, init},
        capacity,
    },
    mem::{Rejected, Return as _},
};
use std::{mem, ops};
pub use writable::Writable;

mod writable;

/// Reusable, size-validated acquisition plan tied to one packet arena.
pub struct Source<'pool, const N: usize, const SUFFIX: usize = 0> {
    source: borrowed::Split<'pool>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Advance {
    Empty,
    More,
    Drained,
}

/// One failed packet position, including failures that consumed its plaintext.
#[derive(PartialEq, Debug)]
pub enum Error {
    Admission(usize, transmit::Admission),
    Closed(usize),
    Full(usize),
    TooLarge(usize),
    Unsupported(usize),
    Crypto { index: usize, cause: crypto::Error },
}

impl<'pool, const N: usize> Source<'pool, N> {
    pub fn try_new(arena: &'pool datagram::Arena, length: usize) -> Result<Self, borrowed::Error> {
        let source = borrowed::Source::try_new(&arena.pool, length, conn::TAG_LEN)?;
        Ok(Self {
            source: source.into_split(),
        })
    }

    pub fn try_split<const SUFFIX: usize>(
        self,
    ) -> Result<Source<'pool, N, SUFFIX>, borrowed::Error> {
        Ok(Source {
            source: self.source.try_suffix(SUFFIX)?,
        })
    }
}

impl<'pool, const N: usize, const SUFFIX: usize> Source<'pool, N, SUFFIX> {
    pub fn try_acquire(&self) -> Result<Writable<'pool, N, SUFFIX>, datagram::Full> {
        let mut packets = mem::MaybeUninit::uninit();
        let mut guard = init::Guard::<_, N>::new(&mut packets);
        let packets = loop {
            let vacant = match guard.next() {
                ops::ControlFlow::Break(packets) => break packets.into_array(),
                ops::ControlFlow::Continue(vacant) => vacant,
            };
            let Some(lease) = self.source.acquire() else {
                return Err(datagram::Full);
            };
            guard = vacant.insert(lease);
        };
        Ok(Writable::new(packets))
    }
}

const _: () = assert!(
    mem::size_of::<Source<'static, 1>>() == 3 * mem::size_of::<usize>()
        && mem::size_of::<Result<Writable<'static, 1>, datagram::Full>>()
            == mem::size_of::<Option<Writable<'static, 1>>>()
);

/// A fixed flight of packets retaining its original pool borrow.
#[must_use = "a QUIC datagram batch owns every packet not yet accepted"]
pub struct Pending<'pool, const N: usize> {
    packets: array::IntoIter<datagram::Packet<'pool>, N>,
}

impl<'pool, const N: usize> Pending<'pool, N> {
    pub(in crate::proto::datagram::batch) fn new(packets: [datagram::Packet<'pool>; N]) -> Self {
        Self {
            packets: array::Vec::from(packets).into_iter(),
        }
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn into_packets(self) -> impl Iterator<Item = datagram::Packet<'pool>> {
        self.packets
    }

    pub fn try_send(
        &mut self,
        send: impl FnOnce(
            datagram::Packet<'pool>,
        ) -> Result<(), errors::SendFailure<datagram::Packet<'pool>>>,
    ) -> Result<batch::Advance, batch::Error> {
        self.try_with((), |(), packet| match send(packet) {
            Ok(()) => Ok(()),
            Err(error) => Err(Rejected::new((), error)),
        })
        .map_err(Rejected::discard)
    }

    /// Retains the send context on every failure, including consumed plaintext.
    pub fn try_with<C>(
        &mut self,
        context: C,
        send: impl FnOnce(
            C,
            datagram::Packet<'pool>,
        )
            -> Result<(), Rejected<C, errors::SendFailure<datagram::Packet<'pool>>>>,
    ) -> Result<batch::Advance, Rejected<C, batch::Error>> {
        let Some(front) = self.packets.remove_front() else {
            return Ok(batch::Advance::Empty);
        };
        let (vacant, packet) = front.into_parts();
        if let Err(failure) = send(context, packet) {
            let index = vacant.index();
            let (context, failure) = failure.into_parts();
            let (packet, error) = match failure {
                errors::SendFailure::Crypto(cause) => {
                    return Err(Rejected::new(
                        context,
                        batch::Error::Crypto { index, cause },
                    ));
                }
                errors::SendFailure::Admission(packet, cause) => {
                    (packet, batch::Error::Admission(index, cause.into_error()))
                }
                errors::SendFailure::Closed(packet) => (packet, batch::Error::Closed(index)),
                errors::SendFailure::Full(packet) => (packet, batch::Error::Full(index)),
                errors::SendFailure::TooLarge(packet) => (packet, batch::Error::TooLarge(index)),
                errors::SendFailure::Unsupported(packet) => {
                    (packet, batch::Error::Unsupported(index))
                }
            };
            vacant.return_item(packet);
            return Err(Rejected::new(context, error));
        }
        Ok(if self.is_empty() {
            batch::Advance::Drained
        } else {
            batch::Advance::More
        })
    }
}

// SAFETY: the exclusive packet loan fixes its exact unread suffix until admission.
unsafe impl<'pool, T, const N: usize> depot::raw::Input<T> for &mut Pending<'pool, N> {
    type Item = datagram::Packet<'pool>;
    type Error = capacity::Shortage;
    type Context = ();
    type Output = ();

    fn count(&self) -> capacity::Count {
        depot::raw::Exact::remaining(&self.packets)
    }

    fn reject(self, cause: capacity::Shortage) -> Self::Error {
        cause
    }
}

// SAFETY: successful admission consumes only the unchanged suffix under its exclusive loan.
unsafe impl<'pool, T, const N: usize> depot::raw::Start<T> for &mut Pending<'pool, N> {
    fn start(self) -> (impl depot::raw::Exact<Item = Self::Item, Output = ()>, ()) {
        (&mut self.packets, ())
    }
}

const _: () = {
    assert!(size_of::<Pending<'static, 0>>() == 8);
    assert!(size_of::<Pending<'static, 1>>() == size_of::<datagram::Packet<'static>>() + 8);
};
