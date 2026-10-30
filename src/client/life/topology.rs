use std::net;

use o3::mem::rc;

use crate::{client::auth, runtime::routing};

pub(in crate::client) struct Peer<A, R> {
    pub(in crate::client) addr: net::SocketAddr,
    pub(in crate::client) auth: A,
    pub(in crate::client) route: R,
}

pub(in crate::client) enum Topology<A, R: routing::PeerRoute> {
    Flat(Box<[Peer<A, R>]>),
    Dense {
        paths: Box<[net::SocketAddr]>,
        auth: A,
        shards: routing::Count,
        capacity: usize,
    },
}

impl<A, R: routing::PeerRoute> Topology<A, R> {
    pub(in crate::client) fn dense(
        paths: Vec<net::SocketAddr>,
        auth: A,
        shards: routing::Count,
    ) -> Option<Self> {
        if paths.is_empty() {
            return None;
        }
        let capacity = shards.dense_len(paths.len())?;
        let last = routing::Shard::from_index((shards.get() - 1) as u8);
        R::from_shard(last)?;
        Some(Self::Dense {
            paths: paths.into_boxed_slice(),
            auth,
            shards,
            capacity,
        })
    }

    pub(in crate::client) fn len(&self) -> usize {
        match self {
            Self::Flat(peers) => peers.len(),
            Self::Dense { capacity, .. } => *capacity,
        }
    }

    pub(super) fn peer(&self, index: usize) -> Option<Peer<Result<A, rc::Error>, R>>
    where
        A: auth::Mode,
    {
        match self {
            Self::Flat(peers) => peers.get(index).map(|peer| Peer {
                addr: peer.addr,
                auth: peer.auth.try_clone(),
                route: peer.route,
            }),
            Self::Dense {
                paths,
                auth,
                shards,
                capacity: _,
            } => {
                let (shard, path) = shards.resolve(paths.len(), index)?;
                Some(Peer {
                    addr: *paths.get(path)?,
                    auth: auth.try_clone(),
                    route: R::from_shard(shard)?,
                })
            }
        }
    }

    pub(super) fn address(&self, index: usize) -> Option<net::SocketAddr> {
        match self {
            Self::Flat(peers) => peers.get(index).map(|peer| peer.addr),
            Self::Dense { paths, shards, .. } => {
                let (_, path) = shards.resolve(paths.len(), index)?;
                paths.get(path).copied()
            }
        }
    }

    pub(super) fn route(&self, index: usize) -> Option<R> {
        match self {
            Self::Flat(peers) => peers.get(index).map(|peer| peer.route),
            Self::Dense { paths, shards, .. } => {
                let (shard, _) = shards.resolve(paths.len(), index)?;
                R::from_shard(shard)
            }
        }
    }
}
