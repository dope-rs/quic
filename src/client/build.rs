use o3::{
    alloc,
    depot::{capacity, queue::indexed::planes},
};
use std::net;
use std::num;

use dope::core::driver;

use crate::client;
use crate::client::auth;
use crate::client::dialer;
use crate::client::life;
use crate::client::protocol;
use crate::conn::id;
use crate::conn::life::options;
use crate::conn::life::tls::clients;
use crate::errors;
use crate::runtime::endpoint;
use crate::runtime::endpoint::owner;
use crate::runtime::mux;
use crate::runtime::mux::auth::{Mode, Owned};
use crate::runtime::receive;
use crate::runtime::routing;
use endpoint::client::Plan;
use life::topology;

/// Exact failure while validating or binding a client topology.
#[derive(Debug)]
pub enum Error {
    Storage(planes::Error<capacity::Limit<{ mux::MAX_CONNECTIONS }>>),
    Reverse(alloc::Error),
    Connection(errors::Connect),
    EmptyTopology,
    EventBudget,
    RetryBudget,
    EndpointCount {
        capacity: capacity::Limit<{ mux::MAX_CONNECTIONS }>,
        endpoints: usize,
    },
    Endpoint(endpoint::BindError),
}

pub(super) struct WorkLimits {
    pub(super) events: num::NonZero<usize>,
    pub(super) retries: num::NonZero<usize>,
}

impl WorkLimits {
    fn new(events: usize, retries: usize) -> Result<Self, Error> {
        let events = num::NonZero::<usize>::new(events).ok_or(Error::EventBudget)?;
        if events.get() > mux::MAX_OUTGOING_CAPACITY {
            return Err(Error::EventBudget);
        }
        let retries = num::NonZero::<usize>::new(retries).ok_or(Error::RetryBudget)?;
        if retries.get() > mux::MAX_OUTGOING_CAPACITY {
            return Err(Error::RetryBudget);
        }
        Ok(Self { events, retries })
    }
}

pub struct Builder<P, A, B, C, R: routing::PeerRoute = routing::Plain> {
    topology: topology::Topology<A, R>,
    config_provider: C,
    protocol: P,
    backoff: B,
    config: client::Config,
}

impl<P, B> Builder<P, auth::Owned, B, client::StaticConfig, routing::Plain> {
    pub fn owned(
        specs: Vec<client::EndpointSpec>,
        opts: options::Options,
        protocol: P,
        backoff: B,
        config: client::Config,
    ) -> Result<Self, Error> {
        Ok(Self::owned_with(
            specs,
            client::StaticConfig(opts),
            protocol,
            backoff,
            config,
        ))
    }
}

impl<P, B, C> Builder<P, auth::Owned, B, C, routing::Plain> {
    pub fn owned_with(
        specs: Vec<client::EndpointSpec>,
        configs: C,
        protocol: P,
        backoff: B,
        config: client::Config,
    ) -> Self {
        let peers = specs
            .into_iter()
            .map(|endpoint| topology::Peer {
                addr: endpoint.addr,
                auth: auth::Owned::new(endpoint.authority),
                route: routing::Plain,
            })
            .collect::<Vec<_>>();
        Self {
            topology: topology::Topology::Flat(peers.into_boxed_slice()),
            config_provider: configs,
            protocol,
            backoff,
            config,
        }
    }
}

impl<'tls, P, B> Builder<P, auth::Pooled<'tls>, B, client::StaticConfig, routing::Plain> {
    pub fn pooled(
        specs: Vec<client::PooledSpec<'tls>>,
        opts: options::Options,
        protocol: P,
        backoff: B,
        config: client::Config,
    ) -> Result<Self, Error> {
        Ok(Self::pooled_with(
            specs,
            client::StaticConfig(opts),
            protocol,
            backoff,
            config,
        ))
    }

    /// Builds a plain client topology with one shared TLS auth and one
    /// resident copy of each remote address. Mutable endpoint lifecycle state
    /// is allocated separately from this immutable identity table.
    pub fn pooled_dense(
        paths: Vec<net::SocketAddr>,
        pool: &'tls clients::Pool,
        opts: options::Options,
        protocol: P,
        backoff: B,
        config: client::Config,
    ) -> Result<Self, Error> {
        let topology =
            topology::Topology::dense(paths, auth::Pooled::new(pool), routing::Count::MIN)
                .ok_or(Error::EmptyTopology)?;
        Ok(Self {
            topology,
            config_provider: client::StaticConfig(opts),
            protocol,
            backoff,
            config,
        })
    }
}

impl<'tls, P, B> Builder<P, auth::Pooled<'tls>, B, client::StaticConfig, routing::Shard> {
    pub fn pooled_dense(
        paths: Vec<net::SocketAddr>,
        pool: &'tls clients::Pool,
        shards: routing::Count,
        opts: options::Options,
        protocol: P,
        backoff: B,
        config: client::Config,
    ) -> Result<Self, Error> {
        let topology = topology::Topology::dense(paths, auth::Pooled::new(pool), shards)
            .ok_or(Error::EmptyTopology)?;
        Ok(Self {
            topology,
            config_provider: client::StaticConfig(opts),
            protocol,
            backoff,
            config,
        })
    }
}

impl<'tls, P, B, C> Builder<P, auth::Pooled<'tls>, B, C, routing::Plain> {
    pub fn pooled_with(
        specs: Vec<client::PooledSpec<'tls>>,
        configs: C,
        protocol: P,
        backoff: B,
        config: client::Config,
    ) -> Self {
        let peers = specs
            .into_iter()
            .map(|endpoint| topology::Peer {
                addr: endpoint.addr,
                auth: auth::Pooled::new(endpoint.pool),
                route: routing::Plain,
            })
            .collect::<Vec<_>>();
        Self {
            topology: topology::Topology::Flat(peers.into_boxed_slice()),
            config_provider: configs,
            protocol,
            backoff,
            config,
        }
    }
}

impl<P, A, B, C, R: routing::PeerRoute> Builder<P, A, B, C, R> {
    pub fn bind<'pool, 'd, const ID: u8>(
        self,
        endpoint: Plan<ID, impl receive::Policy<Buffer<'d> = P::Receive>>,
        driver: &mut driver::Context<'_, 'd>,
    ) -> Result<client::Dialer<'pool, 'd, ID, P, B, A, C, R>, Error>
    where
        P: protocol::Protocol<'d>,
        B: client::Backoff,
        A: auth::Mode,
        A::Binding: owner::Binding<'d, ID>,
        <A::Binding as owner::Binding<'d, ID>>::Mode: Mode<
                ID,
                LocalRoute = routing::Plain,
                Random = <Owned<routing::Plain, id::Driver<'d>> as Mode<ID>>::Random,
            >,
        C: client::ConfigSource,
    {
        let work = WorkLimits::new(self.config.event_budget, self.config.retry_budget)?;
        let capacity = endpoint.capacity();
        if capacity.get() != self.topology.len() {
            return Err(Error::EndpointCount {
                capacity,
                endpoints: self.topology.len(),
            });
        }
        let state = driver.driver_ref().clock().try_attach(|now| {
            life::Lifecycle::try_new(self.topology, self.backoff, capacity, now)
        })?;
        let bridge = client::Bridge::new(self.protocol, state);
        let inner = endpoint
            .bind::<_, A::Binding>(bridge, driver)
            .map_err(Error::Endpoint)?;
        Ok(client::Dialer {
            inner: dialer::Engine::new(inner, self.config_provider),
            limits: work,
        })
    }
}
