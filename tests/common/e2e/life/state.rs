use crate::common::e2e::life;
use life::identity;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Route {
    spec: life::RouteSpec,
    binding: Binding,
    connection: Connection,
    cid: identity::CidEpoch,
    delivery: Delivery,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Binding {
    epoch: identity::BindingEpoch,
    path: identity::PathEpoch,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Connection {
    client: identity::Generation,
    server: identity::Generation,
    witness: life::Witness,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Delivery {
    accepted: u64,
    delivered: u64,
    live: bool,
}

impl Route {
    pub(in crate::common::e2e::life) const EMPTY: Self = Self {
        spec: life::RouteSpec::new(
            identity::RouteId::new(0),
            identity::TransportId::new(0),
            identity::ShardId::new(0),
        ),
        binding: Binding::new(
            identity::BindingEpoch::INITIAL,
            identity::PathEpoch::INITIAL,
        ),
        connection: Connection::new(
            identity::Generation::INITIAL,
            identity::Generation::INITIAL,
            life::Witness::EMPTY,
        ),
        cid: identity::CidEpoch::INITIAL,
        delivery: Delivery::new(0, 0, false),
    };

    pub const fn new(
        spec: life::RouteSpec,
        binding: Binding,
        conn: Connection,
        cid: identity::CidEpoch,
        delivery: Delivery,
    ) -> Self {
        Self {
            spec,
            binding,
            connection: conn,
            cid,
            delivery,
        }
    }

    pub const fn spec(self) -> life::RouteSpec {
        self.spec
    }

    pub const fn binding(self) -> Binding {
        self.binding
    }

    pub const fn connection(self) -> Connection {
        self.connection
    }

    pub const fn cid(self) -> identity::CidEpoch {
        self.cid
    }

    pub const fn delivery(self) -> Delivery {
        self.delivery
    }
}

impl Binding {
    pub const fn new(epoch: identity::BindingEpoch, path: identity::PathEpoch) -> Self {
        Self { epoch, path }
    }

    pub const fn epoch(self) -> identity::BindingEpoch {
        self.epoch
    }

    pub const fn path(self) -> identity::PathEpoch {
        self.path
    }
}

impl Connection {
    pub const fn new(
        client: identity::Generation,
        server: identity::Generation,
        witness: life::Witness,
    ) -> Self {
        Self {
            client,
            server,
            witness,
        }
    }

    pub const fn client(self) -> identity::Generation {
        self.client
    }

    pub const fn server(self) -> identity::Generation {
        self.server
    }

    pub const fn witness(self) -> life::Witness {
        self.witness
    }
}

impl Delivery {
    pub const fn new(accepted: u64, complete: u64, live: bool) -> Self {
        Self {
            accepted,
            delivered: complete,
            live,
        }
    }

    pub const fn accepted(self) -> u64 {
        self.accepted
    }

    pub const fn delivered(self) -> u64 {
        self.delivered
    }

    pub const fn is_live(self) -> bool {
        self.live
    }
}

const _: () = {
    assert!(std::mem::size_of::<Binding>() == 8);
    assert!(std::mem::size_of::<Connection>() == 32);
    assert!(std::mem::size_of::<Delivery>() == 24);
    assert!(std::mem::size_of::<Route>() == 80);
    assert!(!std::mem::needs_drop::<Route>());
};
