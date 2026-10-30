use std::{net, num};

use crate::wire::packet::long::retry;
use o3::buffer::{self, storage};

use crate::runtime::mux::output;

/// One nonempty allocation crossing the mux-to-proto ownership boundary.
#[repr(transparent)]
pub struct Flight(Kind);

pub(in crate::runtime) enum Kind {
    Plain(net::SocketAddr, storage::NonEmpty<Vec<u8>>),
    Suffix(net::SocketAddr, retry::Suffix),
    Batch(
        net::SocketAddr,
        storage::NonEmpty<Vec<u8>>,
        num::NonZero<u16>,
        num::NonZero<u8>,
    ),
}

impl Flight {
    pub(in crate::runtime) fn plain(
        addr: net::SocketAddr,
        payload: storage::NonEmpty<Vec<u8>>,
    ) -> Self {
        Self(Kind::Plain(addr, payload))
    }

    pub(in crate::runtime) fn suffix(addr: net::SocketAddr, payload: retry::Suffix) -> Self {
        Self(Kind::Suffix(addr, payload))
    }

    pub(in crate::runtime) fn batch(
        addr: net::SocketAddr,
        payload: storage::NonEmpty<Vec<u8>>,
        size: num::NonZero<u16>,
        packets: num::NonZero<u8>,
    ) -> Self {
        Self(Kind::Batch(addr, payload, size, packets))
    }

    pub(in crate::runtime) fn into_kind(self) -> Kind {
        self.0
    }

    pub fn addr(&self) -> net::SocketAddr {
        match self.0 {
            Kind::Plain(addr, _) | Kind::Suffix(addr, _) | Kind::Batch(addr, ..) => addr,
        }
    }

    pub fn payload(&self) -> &[u8] {
        match &self.0 {
            Kind::Plain(_, payload) | Kind::Batch(_, payload, ..) => payload,
            Kind::Suffix(_, payload) => payload.as_ref(),
        }
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        match &mut self.0 {
            Kind::Plain(_, payload) | Kind::Batch(_, payload, ..) => payload,
            Kind::Suffix(_, payload) => payload.as_mut(),
        }
    }

    /// Iterates over the exact UDP datagrams carried by this allocation.
    pub fn segments_mut(&mut self) -> output::Segments<'_> {
        match &mut self.0 {
            Kind::Plain(_, payload) => output::Segments::one(payload),
            Kind::Suffix(_, payload) => output::Segments::one(payload.as_mut()),
            Kind::Batch(_, payload, size, _) => output::Segments::batch(payload, (*size).into()),
        }
    }

    pub fn packet_count(&self) -> num::NonZero<usize> {
        match &self.0 {
            Kind::Plain(_, _) | Kind::Suffix(_, _) => num::NonZero::<usize>::MIN,
            Kind::Batch(_, _, _, packets) => (*packets).into(),
        }
    }

    pub fn byte_len(&self) -> usize {
        self.payload().len()
    }

    pub const fn is_segmented(&self) -> bool {
        matches!(self.0, Kind::Batch(..))
    }

    pub const fn is_suffix(&self) -> bool {
        matches!(self.0, Kind::Suffix(..))
    }

    pub(in crate::runtime) const fn segment_size(&self) -> Option<num::NonZero<u16>> {
        match &self.0 {
            Kind::Batch(_, _, size, _) => Some(*size),
            Kind::Plain(..) | Kind::Suffix(..) => None,
        }
    }

    pub(in crate::runtime::mux) fn into_storage(self) -> Vec<u8> {
        match self.0 {
            Kind::Plain(_, payload) | Kind::Batch(_, payload, ..) => payload.into_storage(),
            Kind::Suffix(_, payload) => payload.into_storage(),
        }
    }
}

impl buffer::Residency for Flight {
    fn resident(&self) -> usize {
        match &self.0 {
            Kind::Plain(_, payload) | Kind::Batch(_, payload, ..) => payload.resident(),
            Kind::Suffix(_, payload) => payload.resident(),
        }
    }
}
