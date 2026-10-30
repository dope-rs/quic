//! One canonical routing format shared by QUIC CID construction and the
//! native UDP reuse-port selector.

pub(in crate::runtime) mod registry;

use std::{mem, net};

use dope::core::io::datagram;
use dope_sys::io::socket::route::{count, selector::Selector};

use crate::wire::packet::{self, cid};

mod sealed;
pub(crate) use sealed::Sealed;

/// Unmodified entropy carried by both plain and routed connection IDs.
pub const ENTROPY_LEN: usize = 8;
/// One shard byte followed by [`ENTROPY_LEN`] bytes of entropy.
pub const CONNECTION_ID_LEN: usize = ENTROPY_LEN + 1;

const SHORT_KEY_OFFSET: u8 = 1;
const LONG_LENGTH_OFFSET: u8 = 5;
const LONG_KEY_OFFSET: u8 = 6;
const SHORT_MINIMUM_LEN: u8 = SHORT_KEY_OFFSET + CONNECTION_ID_LEN as u8;
const LONG_MINIMUM_LEN: u8 = LONG_KEY_OFFSET + CONNECTION_ID_LEN as u8 + 1;

const SELECTOR: Selector = Selector::fixed::<
    0,
    { packet::FORM_LONG },
    SHORT_KEY_OFFSET,
    SHORT_MINIMUM_LEN,
    LONG_LENGTH_OFFSET,
    { CONNECTION_ID_LEN as u8 },
    LONG_KEY_OFFSET,
    LONG_MINIMUM_LEN,
>();

/// Validated number of densely numbered QUIC shards.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub struct Count(count::Count);

impl Count {
    pub const MIN: Self = Self(count::Count::MIN);

    pub const fn get(self) -> u16 {
        self.0.encode()
    }

    pub(crate) fn iter(self) -> impl ExactSizeIterator<Item = Shard> + DoubleEndedIterator {
        self.0.indices().map(Shard::from)
    }

    pub fn dense_len(self, paths: usize) -> Option<usize> {
        if paths == 0 {
            return None;
        }
        self.iter().len().checked_mul(paths)
    }

    pub fn resolve(self, paths: usize, index: usize) -> Option<(Shard, usize)> {
        if index >= self.dense_len(paths)? {
            return None;
        }
        let shard = self.iter().nth(index / paths)?;
        let path = index % paths;
        Some((shard, path))
    }

    pub fn index(self, paths: usize, shard: Shard, path: usize) -> Option<usize> {
        if paths == 0 || path >= paths {
            return None;
        }
        let index = self.0.index(shard.index())?;
        index.into_raw().checked_mul(paths)?.checked_add(path)
    }
}

impl TryFrom<u16> for Count {
    type Error = count::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(Self(count::Count::try_from(value)?))
    }
}

/// The exact dense worker selected by the first byte of a routed CID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Shard(u8);

impl Shard {
    pub const fn from_index(index: u8) -> Self {
        Self(index)
    }

    pub const fn index(self) -> u8 {
        self.0
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        (bytes.len() == CONNECTION_ID_LEN).then(|| Self(bytes[0]))
    }
}

impl From<count::Index> for Shard {
    fn from(index: count::Index) -> Self {
        Self::from_index(index.into_raw() as u8)
    }
}

impl Sealed for Shard {}

/// Compile-time local-CID auth carried by one mux.
/// Sealing prevents external fabrication of socket routing auth.
#[doc(hidden)]
pub trait LocalRoute: Sealed {
    const CONNECTION_ID_LEN: usize;

    fn issue(&self, entropy: [u8; ENTROPY_LEN]) -> cid::Id;
}

/// Initial CID issuance and peer routing policy for one client topology.
/// Only an explicit shard constrains peer-selected CIDs and their reuse.
#[doc(hidden)]
pub trait PeerRoute: Sealed + Copy {
    const CONNECTION_ID_LEN: usize;

    fn issue(self, entropy: [u8; ENTROPY_LEN]) -> cid::Id;

    fn matches(self, cid: &cid::Id) -> bool;

    /// Retained across peer CID replacement; `None` leaves peer IDs opaque.
    fn shard(self) -> Option<Shard>;

    #[doc(hidden)]
    fn from_shard(shard: Shard) -> Option<Self>;
}

pub(crate) fn matches_peer(shard: Option<Shard>, cid: cid::Ref<'_>) -> bool {
    shard.is_none_or(|expected| Shard::from_bytes(cid.as_ref()) == Some(expected))
}

/// A local endpoint whose CIDs carry only the full entropy payload.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct Plain;

impl Sealed for Plain {}

impl LocalRoute for Plain {
    const CONNECTION_ID_LEN: usize = ENTROPY_LEN;

    fn issue(&self, entropy: [u8; ENTROPY_LEN]) -> cid::Id {
        cid::Id::from_array(entropy)
    }
}

impl PeerRoute for Plain {
    const CONNECTION_ID_LEN: usize = ENTROPY_LEN;

    fn issue(self, entropy: [u8; ENTROPY_LEN]) -> cid::Id {
        cid::Id::from_array(entropy)
    }

    fn matches(self, cid: &cid::Id) -> bool {
        cid.len() == ENTROPY_LEN
    }

    fn shard(self) -> Option<Shard> {
        None
    }

    fn from_shard(shard: Shard) -> Option<Self> {
        (shard.index() == 0).then_some(Self)
    }
}

impl PeerRoute for Shard {
    const CONNECTION_ID_LEN: usize = CONNECTION_ID_LEN;

    fn issue(self, entropy: [u8; ENTROPY_LEN]) -> cid::Id {
        let mut bytes = [0_u8; CONNECTION_ID_LEN];
        bytes[0] = self.index();
        bytes[1..].copy_from_slice(&entropy);
        cid::Id::from_array(bytes)
    }

    fn matches(self, cid: &cid::Id) -> bool {
        matches_peer(Some(self), cid.as_ref_id())
    }

    fn shard(self) -> Option<Shard> {
        Some(self)
    }

    fn from_shard(shard: Shard) -> Option<Self> {
        Some(shard)
    }
}

/// Local endpoint auth recovered only by consuming its affine binding.
#[derive(Eq, PartialEq)]
pub struct Routed {
    shard: Shard,
}

impl Sealed for Routed {}

impl LocalRoute for Routed {
    const CONNECTION_ID_LEN: usize = CONNECTION_ID_LEN;

    fn issue(&self, entropy: [u8; ENTROPY_LEN]) -> cid::Id {
        self.shard.issue(entropy)
    }
}

/// One affine socket paired with the only QUIC shard that its selector admits.
pub struct Binding {
    socket: datagram::Lease,
    shard: Shard,
}

impl Binding {
    pub const fn shard(&self) -> Shard {
        self.shard
    }

    pub(crate) fn into_parts(self) -> (datagram::Lease, Routed) {
        (self.socket, Routed { shard: self.shard })
    }
}

/// A completely installed QUIC routing group.
pub struct Group {
    native: datagram::Group,
}

impl Group {
    pub fn bind(addr: net::SocketAddr, count: Count) -> Result<Self, datagram::Error> {
        use dope_sys::io::socket::route::Plan;

        Ok(Self {
            native: datagram::Group::bind(addr, Plan::new(count.0, SELECTOR))?,
        })
    }

    pub fn split(self) -> impl ExactSizeIterator<Item = Binding> {
        self.native.into_entries().map(|(index, socket)| {
            let shard = Shard::from(index);
            Binding { socket, shard }
        })
    }
}

const _: () = {
    assert!(CONNECTION_ID_LEN <= cid::Id::MAX_LEN);
    assert!(mem::size_of::<Count>() == mem::size_of::<u16>());
    assert!(mem::size_of::<Result<Count, count::Error>>() == 2 * mem::size_of::<u16>());
    assert!(mem::size_of::<Shard>() == 1);
    assert!(mem::size_of::<Plain>() == 0);
    assert!(mem::size_of::<Routed>() == 1);
    assert!(!mem::needs_drop::<Routed>());
    assert!(mem::size_of::<Binding>() == 2 * mem::size_of::<datagram::Lease>());
};
