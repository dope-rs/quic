use std::marker;

use o3::buffer;

use crate::{
    conn,
    runtime::{
        mux,
        routing::{self, registry},
    },
    stream,
    wire::packet::cid,
};
use conn::id;
use mux::{auth, router};
use router::routing::issuer;

const CAPACITY: usize = conn::MAX_ACTIVE_CONNECTION_IDS + 1;

pub(in crate::runtime) struct Route {
    value: cid::Id,
    hash: u64,
}

impl Route {
    pub(in crate::runtime) const fn value(&self) -> cid::Id {
        self.value
    }

    pub(in crate::runtime) const fn hash(&self) -> u64 {
        self.hash
    }
}

pub(in crate::runtime::mux) struct Source<
    'storage,
    'id,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
> {
    owner: registry::Directory<'storage, 'id, C, DOMAIN, B, D, T>,
}

pub(in crate::runtime::mux) enum Lookup<
    'storage,
    'id,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
> {
    Routed(registry::Hit<'storage, 'id, C, DOMAIN, B, D, T>),
    Vacant(Vacant<'storage, 'id, C, DOMAIN, B, D, T>),
}

pub(in crate::runtime::mux) struct Vacant<
    'storage,
    'id,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
> {
    source: Source<'storage, 'id, C, DOMAIN, B, D, T>,
    alias: Route,
}

pub(in crate::runtime::mux) struct Prepared<
    'storage,
    'id,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
> {
    source: Source<'storage, 'id, C, DOMAIN, B, D, T>,
    local: Route,
    alias: Option<Route>,
}

pub(in crate::runtime) struct Routes<'id> {
    local: Route,
    alias: Option<Route>,
    root: marker::PhantomData<fn(&'id ()) -> &'id ()>,
}

impl Routes<'_> {
    pub(in crate::runtime) const fn local(&self) -> (cid::Id, u64) {
        (self.local.value, self.local.hash)
    }

    pub(in crate::runtime) fn alias(&self) -> Option<(cid::Id, u64)> {
        self.alias.as_ref().map(|route| (route.value, route.hash))
    }
}

impl<'storage, 'id, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    Source<'storage, 'id, C, DOMAIN, B, D, T>
{
    pub(in crate::runtime::mux) fn new(
        owner: registry::Directory<'storage, 'id, C, DOMAIN, B, D, T>,
    ) -> Self {
        Self { owner }
    }

    pub(in crate::runtime::mux) fn find(
        self,
        value: &[u8],
    ) -> Result<registry::Hit<'storage, 'id, C, DOMAIN, B, D, T>, Self> {
        let hash = self.owner.hash(value);
        self.owner
            .lookup(value, hash)
            .map_err(|owner| Self { owner })
    }

    pub(in crate::runtime::mux) fn lookup(
        self,
        value: cid::Ref<'_>,
    ) -> Lookup<'storage, 'id, C, DOMAIN, B, D, T> {
        let hash = self.owner.hash(value.into_slice());
        match self.owner.lookup(value.into_slice(), hash) {
            Ok(hit) => Lookup::Routed(hit),
            Err(owner) => Lookup::Vacant(Vacant {
                source: Self { owner },
                alias: Route {
                    value: value.into_owned(),
                    hash,
                },
            }),
        }
    }

    pub(in crate::runtime::mux) fn reserve<R: routing::LocalRoute, G: issuer::Source>(
        mut self,
        route: &R,
        issuer: &mut G,
    ) -> Option<Prepared<'storage, 'id, C, DOMAIN, B, D, T>> {
        let local = self.next(route, issuer, None)?;
        Some(Prepared {
            source: self,
            local,
            alias: None,
        })
    }

    fn next<R: routing::LocalRoute, G: issuer::Source>(
        &mut self,
        route: &R,
        issuer: &mut G,
        excluded: Option<&[u8]>,
    ) -> Option<Route> {
        next(route, issuer, self.owner.len(), excluded, |value| {
            let hash = self.owner.hash(value);
            (!self.owner.contains(value, hash)).then_some(hash)
        })
    }
}

impl<'storage, 'id, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    Vacant<'storage, 'id, C, DOMAIN, B, D, T>
{
    pub(in crate::runtime::mux) const fn value(&self) -> cid::Id {
        self.alias.value
    }

    pub(in crate::runtime::mux) fn is_full(&self) -> bool {
        let (active, limit) = self.source.owner.capacity();
        active >= limit.get()
    }

    pub(in crate::runtime::mux) fn new_away<R: routing::LocalRoute, G: issuer::Source>(
        &mut self,
        route: &R,
        issuer: &mut G,
    ) -> Option<cid::Id> {
        self.source
            .next(route, issuer, Some(self.alias.value.as_slice()))
            .map(|route| route.value)
    }

    pub(in crate::runtime::mux) fn reserve_away<R: routing::LocalRoute, G: issuer::Source>(
        mut self,
        route: &R,
        issuer: &mut G,
    ) -> Option<Prepared<'storage, 'id, C, DOMAIN, B, D, T>> {
        let local = self
            .source
            .next(route, issuer, Some(self.alias.value.as_slice()))?;
        Some(Prepared {
            source: self.source,
            local,
            alias: Some(self.alias),
        })
    }
}

impl<'storage, 'id, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
    Prepared<'storage, 'id, C, DOMAIN, B, D, T>
{
    pub(in crate::runtime::mux) const fn value(&self) -> cid::Id {
        self.local.value
    }

    pub(in crate::runtime::mux) fn claim<I: Copy>(
        self,
        domain: id::Domain<I, DOMAIN>,
    ) -> Option<registry::Reservation<'storage, 'id, C, I, DOMAIN, B, D, T>> {
        let Self {
            source,
            local,
            alias,
        } = self;
        source.owner.claim(
            domain,
            Routes {
                local,
                alias,
                root: marker::PhantomData,
            },
        )
    }
}

pub(in crate::runtime::mux::router) fn sync<
    'loan,
    'storage,
    'id,
    A: auth::Mode<DOMAIN>,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
>(
    mut routing: registry::Drain<'loan, 'storage, 'id, C, DOMAIN, B, A::Send, A::Session>,
    binding: &mut router::Binding<A, DOMAIN>,
) {
    let router::Binding { route, issuer, .. } = binding;
    while let Some(issue) = routing.next() {
        let next = next(route, issuer, issue.len(), None, |value| {
            let hash = issue.hash(value);
            (!issue.contains(value, hash)).then_some(hash)
        });
        let Some(next) = next else {
            issue.defer();
            break;
        };
        routing = issue.assign(next);
    }
}

fn next<R: routing::LocalRoute, G: issuer::Source>(
    route: &R,
    issuer: &mut G,
    active: usize,
    excluded: Option<&[u8]>,
    mut vacant: impl FnMut(&[u8]) -> Option<u64>,
) -> Option<Route> {
    let mut left = active * CAPACITY + 1 + usize::from(excluded.is_some());
    while left != 0 {
        left -= 1;
        let value = route.issue(issuer.entropy()?);
        if excluded.is_some_and(|excluded| value.as_slice() == excluded) {
            continue;
        }
        if let Some(hash) = vacant(value.as_slice()) {
            return Some(Route { value, hash });
        }
    }
    None
}

const _: () = {
    assert!(mux::MAX_CONNECTIONS <= (usize::MAX - 2) / CAPACITY);
};
