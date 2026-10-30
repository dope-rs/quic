use std::{marker, mem, num::NonZero};

use crate::conn;

pub(in crate::conn) trait Role {
    const MIN: NonZero<u16>;
}

pub(in crate::conn) enum Packet {}

pub(in crate::conn) enum Crypto {}

pub(in crate::conn) enum Control {}

pub(in crate::conn) enum Stream {}

impl Role for Packet {
    const MIN: NonZero<u16> = NonZero::<u16>::MIN.saturating_add(1);
}

impl Role for Crypto {
    const MIN: NonZero<u16> = NonZero::<u16>::MIN;
}

impl Role for Control {
    const MIN: NonZero<u16> =
        NonZero::<u16>::MIN.saturating_add(conn::PACKET_CONTROL_CAPACITY as u16 * 2 - 1);
}

impl Role for Stream {
    const MIN: NonZero<u16> =
        NonZero::<u16>::MIN.saturating_add(conn::PACKET_STREAM_CAPACITY as u16 * 2 - 1);
}

/// Exact, role-bound journal capacity promoted at configuration.
#[repr(transparent)]
pub(in crate::conn) struct Capacity<R: Role>(NonZero<u16>, marker::PhantomData<fn(R) -> R>);

impl<R: Role> Capacity<R> {
    pub(in crate::conn) fn try_new(value: usize) -> Option<Self> {
        let value = NonZero::<u16>::new(u16::try_from(value).ok()?)?;
        (value >= R::MIN).then_some(Self(value, marker::PhantomData))
    }

    pub(in crate::conn) const fn constant<const N: usize>() -> Self {
        const { assert!(N >= R::MIN.get() as usize && N <= u16::MAX as usize) }
        Self(
            NonZero::<u16>::MIN.saturating_add(N as u16 - 1),
            marker::PhantomData,
        )
    }

    pub(in crate::conn) const fn get(self) -> u16 {
        self.0.get()
    }

    pub(in crate::conn) const fn as_u32(&self) -> u32 {
        self.0.get() as u32
    }
}

impl Capacity<Packet> {
    pub(in crate::conn) const fn crypto_epoch(self) -> Self {
        const CEILING: NonZero<u16> = NonZero::<u16>::MIN.saturating_add(127);
        Self(
            if self.get() < CEILING.get() {
                self.0
            } else {
                CEILING
            },
            marker::PhantomData,
        )
    }
}

impl<R: Role> Clone for Capacity<R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R: Role> Copy for Capacity<R> {}

#[derive(Clone, Copy)]
pub(in crate::conn) struct Capacities {
    packet: Capacity<Packet>,
    crypto: Capacity<Crypto>,
    control: Capacity<Control>,
    stream: Capacity<Stream>,
}

impl Capacities {
    pub(in crate::conn) fn new(
        packet: Capacity<Packet>,
        crypto: Capacity<Crypto>,
        control: Capacity<Control>,
        stream: Capacity<Stream>,
    ) -> Self {
        Self {
            packet,
            crypto,
            control,
            stream,
        }
    }

    pub(in crate::conn) const fn packet(self) -> Capacity<Packet> {
        self.packet
    }

    pub(in crate::conn) const fn crypto(self) -> Capacity<Crypto> {
        self.crypto
    }

    pub(in crate::conn) const fn control(self) -> Capacity<Control> {
        self.control
    }

    pub(in crate::conn) const fn stream(self) -> Capacity<Stream> {
        self.stream
    }
}

impl Default for Capacities {
    fn default() -> Self {
        Self {
            packet: Capacity::constant::<{ conn::PACKET_JOURNAL_CAPACITY }>(),
            crypto: Capacity::constant::<{ conn::CRYPTO_JOURNAL_CAPACITY }>(),
            control: Capacity::constant::<{ conn::CONTROL_JOURNAL_CAPACITY }>(),
            stream: Capacity::constant::<{ conn::STREAM_JOURNAL_CAPACITY }>(),
        }
    }
}

const _: () = {
    assert!(mem::size_of::<Capacity<Packet>>() == mem::size_of::<u16>());
    assert!(mem::size_of::<Option<Capacity<Crypto>>>() == mem::size_of::<u16>());
    assert!(mem::size_of::<Capacities>() == 4 * mem::size_of::<u16>());
    assert!(!mem::needs_drop::<Capacities>());
};
