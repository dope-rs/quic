use crate::common::e2e::life::identity;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Witness {
    Length { actual: usize, maximum: usize },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Topology {
    Transports {
        actual: u16,
        maximum: usize,
    },
    Shards {
        actual: u16,
        maximum: usize,
    },
    Routes {
        actual: usize,
        maximum: usize,
    },
    Route {
        index: usize,
        actual: identity::RouteId,
    },
    Transport {
        route: identity::RouteId,
        actual: identity::TransportId,
        count: u16,
    },
    Shard {
        route: identity::RouteId,
        actual: identity::ShardId,
        count: u16,
    },
    UnownedTransport {
        index: usize,
    },
    UnmappedShard {
        index: usize,
    },
}
