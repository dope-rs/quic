use crate::common::e2e::life::driver::Ticket;
use crate::common::runtime;
use crate::common::suite::cid::{Count, Error, INITIAL};
use crate::common::suite::peers::tls;
use dope_quic::conn::id::Handle;
use dope_quic::conn::life::tls::clients;
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::runtime::mux::builder::Plan;
use dope_quic::runtime::mux::router;
use std::mem::replace;
use std::num::NonZero;
use std::time::Duration;
use std::{net::SocketAddr, pin::Pin, time::Instant};

use crate::common::e2e::life::identity::{
    BindingEpoch, CidEpoch, Generation, PathEpoch, RouteId, ShardId, TransportId,
};
use crate::common::e2e::life::state::{Binding, Connection, Delivery, Route};
use crate::common::e2e::life::{self, Action, RouteSpec, Witness};
use dope_quic::errors::Code;
use dope_quic::proto::cid::{Rotation, Schedule};

pub const ROUTES: [RouteSpec; 1] = [RouteSpec::new(
    RouteId::new(0),
    TransportId::new(0),
    ShardId::new(0),
)];

pub struct Wire {
    server: Peer,
    client: Peer,
    pub(super) route: Route,
    active: Option<[u8; 8]>,
    pub(super) steps: Steps,
    authority: clients::Authority,
    rotation: Schedule,
}

struct Peer {
    router: router::Router<Count>,
    address: SocketAddr,
    handle: Handle,
}

pub(super) struct Steps {
    pub(super) pending: Option<(Ticket, life::ValidStep)>,
    pub(super) next: u64,
    now: Instant,
}

impl Wire {
    pub fn counts(&self) -> (usize, usize) {
        (
            self.server.router.active_conns(),
            self.client.router.active_conns(),
        )
    }

    pub fn new() -> Result<Self, Error> {
        let (key, config) = Count::try_keys().map_err(Error::Runtime)?;
        let auth = tls::client(key)
            .map_err(runtime::Error::Tls)
            .map_err(Error::Runtime)?;
        let plan = Plan::try_new(2, 4096, 16 << 20).map_err(Error::Limits)?;
        let mut server = Count::server(config, plan).map_err(Error::Runtime)?;
        let plan = Plan::try_new(1, 4096, 16 << 20).map_err(Error::Limits)?;
        let mut client = Builder::client(Count::default())
            .limits(plan)
            .build()
            .map_err(Error::Build)?;
        let peer = SocketAddr::from(([10, 0, 0, 2], 443));
        let local = SocketAddr::from(([10, 0, 0, 1], 50_000));
        let started = Instant::now();
        let options = Count::options().map_err(Error::Runtime)?;
        let outbound = Pin::new(&mut client)
            .observe(started, |mut turn| {
                turn.protocol()
                    .connect(peer, &auth, options, INITIAL.to_vec())
            })
            .map_err(Error::Initial)?;
        for turn in 0..16 {
            let now = started
                .checked_add(Duration::from_millis(turn * 10))
                .ok_or(Error::Runtime(runtime::Error::Deadline(started)))?;
            Count::relay_at(&mut client, &mut server, local, now).map_err(Error::Runtime)?;
            Count::relay_at(&mut server, &mut client, peer, now).map_err(Error::Runtime)?;
            if client.handler().established == 1 && server.handler().established == 1 {
                break;
            }
        }
        if client.handler().established != 1 || server.handler().established != 1 {
            return Err(Error::Setup {
                client: client.handler().established,
                server: server.handler().established,
            });
        }
        let Some(inbound) = server.handler().last_handle else {
            return Err(Error::Handle {
                established: server.handler().established,
            });
        };
        let count = NonZero::<u16>::MIN.saturating_add(1);
        let period = NonZero::<u64>::MIN.saturating_add(999_999);
        let plan = Rotation::from_nanos(period, count);
        let rotation = Pin::new(&mut server).observe(started, |turn| turn.plan_cid(plan));
        let witness = Witness::try_new(&INITIAL).map_err(Error::Witness)?;
        Ok(Self {
            server: Peer {
                router: server,
                address: peer,
                handle: inbound,
            },
            client: Peer {
                router: client,
                address: local,
                handle: outbound,
            },
            route: Route::new(
                ROUTES[0],
                Binding::new(BindingEpoch::INITIAL, PathEpoch::INITIAL),
                Connection::new(Generation::INITIAL, Generation::INITIAL, witness),
                CidEpoch::INITIAL,
                Delivery::new(0, 0, true),
            ),
            active: None,
            steps: Steps {
                pending: None,
                next: 0,
                now: started
                    .checked_add(Duration::from_millis(150))
                    .ok_or(Error::Runtime(runtime::Error::Deadline(started)))?,
            },
            authority: auth,
            rotation,
        })
    }

    fn now(&mut self) -> Result<Instant, Error> {
        self.steps.now = self
            .steps
            .now
            .checked_add(Duration::from_millis(10))
            .ok_or(Error::Runtime(runtime::Error::Deadline(self.steps.now)))?;
        Ok(self.steps.now)
    }

    fn set(&mut self, binding: Binding, conn: Connection, cid: CidEpoch, delivery: Delivery) {
        self.route = Route::new(self.route.spec(), binding, conn, cid, delivery);
    }

    fn probe(&mut self, sequence: u32) -> Result<(), Error> {
        let before = self.server.router.handler().datagrams;
        let now = self.now()?;
        Pin::new(&mut self.client.router)
            .observe(now, |mut turn| {
                turn.protocol()
                    .try_datagram(self.client.handle, sequence.to_be_bytes().to_vec())
            })
            .map_err(Error::ProbeSend)?;
        for _ in 0..16 {
            let now = self.now()?;
            let wires = Count::relay_at(
                &mut self.client.router,
                &mut self.server.router,
                self.client.address,
                now,
            )
            .map_err(Error::Runtime)?;
            if let Some(cid) = wires.iter().find_map(|wire| Count::short_cid(wire)) {
                self.active = Some(cid);
            }
            Count::relay_at(
                &mut self.server.router,
                &mut self.client.router,
                self.server.address,
                now,
            )
            .map_err(Error::Runtime)?;
            if self.server.router.handler().datagrams == before + 1 {
                let accepted = self.route.delivery().accepted() + 1;
                self.set(
                    self.route.binding(),
                    self.route.connection(),
                    self.route.cid(),
                    Delivery::new(accepted, accepted, true),
                );
                return Ok(());
            }
        }
        Err(Error::Delivery {
            expected: before + 1,
            actual: self.server.router.handler().datagrams,
        })
    }

    fn rotate(&mut self) -> Result<(), Error> {
        let Some(conn) = self.server.router.conn(self.server.handle) else {
            return Err(Error::Connection {
                handle: self.server.handle,
            });
        };
        let Some(retiring) = conn
            .view()
            .path()
            .local_cids()
            .entries()
            .map(|entry| entry.0)
            .min()
        else {
            return Err(Error::Cid {
                handle: self.server.handle,
            });
        };
        let now = self.now()?;
        let progress = Pin::new(&mut self.server.router)
            .observe(now, |mut turn| turn.maintain_cid(&mut self.rotation));
        if progress.visited() != 1 || progress.started() != 1 || !progress.is_complete() {
            return Err(Error::Sweep {
                visited: progress.visited(),
                started: progress.started(),
                complete: progress.is_complete(),
            });
        }
        let Some(previous) = self.active else {
            return Err(Error::ProbeCid);
        };
        let mut next = None;
        let mut emitted = false;
        let mut retired = false;
        for _ in 0..16 {
            let now = self.now()?;
            emitted |= !Count::relay_at(
                &mut self.server.router,
                &mut self.client.router,
                self.server.address,
                now,
            )
            .map_err(Error::Runtime)?
            .is_empty();
            let wires = Count::relay_at(
                &mut self.client.router,
                &mut self.server.router,
                self.client.address,
                now,
            )
            .map_err(Error::Runtime)?;
            next = next.or_else(|| Count::changed_cid(&wires, previous));
            let Some(conn) = self.server.router.conn(self.server.handle) else {
                return Err(Error::Connection {
                    handle: self.server.handle,
                });
            };
            retired = conn
                .view()
                .path()
                .local_cids()
                .entries()
                .all(|entry| entry.0 != retiring);
            if emitted && next.is_some() && retired {
                self.active = next;
                self.set(
                    self.route.binding(),
                    self.route.connection(),
                    CidEpoch::new(self.route.cid().get() + 1),
                    self.route.delivery(),
                );
                return Ok(());
            }
        }
        Err(Error::Rotation {
            emitted,
            changed: next.is_some(),
            retired,
        })
    }

    fn rebind(&mut self, epoch: BindingEpoch, sequence: u32) -> Result<(), Error> {
        self.client.address.set_port(self.client.address.port() + 1);
        let before = self.server.router.handler().datagrams;
        let now = self.now()?;
        Pin::new(&mut self.client.router)
            .observe(now, |mut turn| {
                turn.protocol()
                    .try_datagram(self.client.handle, sequence.to_be_bytes().to_vec())
            })
            .map_err(Error::PathSend)?;
        let mut peer = None;
        for _ in 0..32 {
            let now = self.now()?;
            let wires = Count::relay_at(
                &mut self.client.router,
                &mut self.server.router,
                self.client.address,
                now,
            )
            .map_err(Error::Runtime)?;
            if let Some(cid) = wires.iter().find_map(|wire| Count::short_cid(wire)) {
                self.active = Some(cid);
            }
            Count::relay_at(
                &mut self.server.router,
                &mut self.client.router,
                self.server.address,
                now,
            )
            .map_err(Error::Runtime)?;
            peer = self
                .server
                .router
                .conn(self.server.handle)
                .and_then(|conn| conn.view().path().peer_address());
            if self.server.router.handler().datagrams == before + 1
                && peer == Some(self.client.address)
            {
                let accepted = self.route.delivery().accepted() + 1;
                self.set(
                    Binding::new(epoch, PathEpoch::new(self.route.binding().path().get() + 1)),
                    self.route.connection(),
                    self.route.cid(),
                    Delivery::new(accepted, accepted, true),
                );
                return Ok(());
            }
        }
        Err(Error::Path {
            expected: self.client.address,
            actual: peer,
            sent: before + 1,
            received: self.server.router.handler().datagrams,
        })
    }

    fn cycle(&mut self) -> Result<(), Error> {
        let conn = self.route.connection();
        let next = Generation::new(conn.client().get() + 1);
        let Ok(cycle) = u8::try_from(next.get()) else {
            return Err(Error::Generation { actual: next.get() });
        };
        let cid = [cycle; 8];
        let mut client = Builder::client(Count::default())
            .build()
            .map_err(Error::Build)?;
        let now = self.now()?;
        let options = Count::options().map_err(Error::Runtime)?;
        let handle = Pin::new(&mut client)
            .observe(now, |mut turn| {
                turn.protocol()
                    .connect(self.server.address, &self.authority, options, cid.to_vec())
            })
            .map_err(Error::Connect)?;
        let before = self.server.router.handler().established;
        for _ in 0..16 {
            let now = self.now()?;
            Count::relay_at(
                &mut client,
                &mut self.server.router,
                self.client.address,
                now,
            )
            .map_err(Error::Runtime)?;
            Count::relay_at(
                &mut self.server.router,
                &mut client,
                self.server.address,
                now,
            )
            .map_err(Error::Runtime)?;
            if client.handler().established == 1
                && self.server.router.handler().established == before + 1
            {
                break;
            }
        }
        if client.handler().established != 1
            || self.server.router.handler().established != before + 1
        {
            return Err(Error::Replacement {
                client: client.handler().established,
                server: self.server.router.handler().established,
                expected: before + 1,
            });
        }
        if self.server.router.active_conns() != 2 || self.client.router.active_conns() != 1 {
            return Err(Error::Overlap {
                server: self.server.router.active_conns(),
                client: self.client.router.active_conns(),
            });
        }

        let Some(inbound) = self.server.router.handler().last_handle else {
            return Err(Error::Handle {
                established: self.server.router.handler().established,
            });
        };
        let old = self.client.handle;
        let mut retiring = replace(&mut self.client.router, client);
        self.client.handle = handle;
        self.server.handle = inbound;

        let now = self.now()?;
        Pin::new(&mut retiring)
            .observe(now, |mut turn| {
                turn.protocol().with_conn(old, |mut scope| {
                    scope.lifecycle().close(Code::ZERO, Vec::new());
                })
            })
            .map_err(Error::Retire)?;
        for _ in 0..16 {
            let now = self.now()?;
            Count::relay_at(
                &mut retiring,
                &mut self.server.router,
                self.client.address,
                now,
            )
            .map_err(Error::Runtime)?;
            Count::relay_at(
                &mut self.server.router,
                &mut retiring,
                self.server.address,
                now,
            )
            .map_err(Error::Runtime)?;
            if retiring.active_conns() == 0 && self.server.router.active_conns() == 1 {
                break;
            }
        }
        if retiring.active_conns() != 0 || self.server.router.active_conns() != 1 {
            return Err(Error::Drain {
                retiring: retiring.active_conns(),
                server: self.server.router.active_conns(),
            });
        }
        self.active = None;
        let witness = Witness::try_new(&cid).map_err(Error::Witness)?;
        self.set(
            self.route.binding(),
            Connection::new(next, next, witness),
            self.route.cid(),
            self.route.delivery(),
        );
        Ok(())
    }

    fn target(&self, target: life::Target) -> Result<(), Error> {
        let spec = self.route.spec();
        let owned = match target {
            life::Target::All => true,
            life::Target::Transport(id) => id == spec.transport(),
            life::Target::Route(id) => id == spec.route(),
        };
        if !owned {
            return Err(Error::Target {
                target,
                route: spec.route(),
                transport: spec.transport(),
            });
        }
        Ok(())
    }

    pub(super) fn execute(&mut self, valid: life::ValidStep) -> Result<(), Error> {
        match valid.action() {
            Action::Probe { target, sequence } => {
                self.target(target)?;
                self.probe(sequence)
            }
            Action::RotateLocalCids { target } => {
                self.target(target)?;
                self.rotate()
            }
            Action::RebindTransports {
                target,
                epoch,
                probe_sequence: sequence,
            } => {
                self.target(target)?;
                self.rebind(epoch, sequence)
            }
            Action::CycleConnections { target } => {
                self.target(target)?;
                self.cycle()
            }
            Action::Drain { target } => {
                self.target(target)?;
                Err(Error::Action(valid.step()))
            }
        }
    }
}
