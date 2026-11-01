use crate::common::peer;
use dope::core::driver::life::creation::Attempt;
use dope::core::driver::life::{domain, recovery};
use dope::core::io::{
    Reclaimed,
    datagram::payload::{self, Len},
};
use dope::core::platform::wake;
use dope::runtime::executor::{create, drive, session};
use dope_quic::conn::life::options::{Options, builder::Invalid};
use dope_quic::conn::life::tls::clients;
use dope_quic::conn::life::tls::servers;
use dope_quic::errors;
use dope_quic::runtime::endpoint::config;
use dope_quic::runtime::endpoint::config::Config;
use dope_test::harness::scenario::TIMEOUT;
use o3::buffer::write::consume;
use proto::cid::Rotation;
use settings::claim::Needs;
use settings::errors::Claim;

use std::cell::RefCell;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZero;
use std::rc::Rc;
use std::time::Duration;

use crate::common::receive::retained::{Capture, Connect, Fault, Pooled, Proof, Reading};
use crate::common::suite::peers::tls;
use dope::core::driver::{schedule::clock, settings};
use dope::runtime::{control, executor::Executor, shutdown};
use dope_quic::conn::life::accept;
use dope_quic::proto::{self, param};
use dope_quic::runtime::endpoint::{
    self, client,
    owner::{self, pool},
    server,
};
use dope_quic::runtime::{receive, routing::Plain};
use dope_quic::stream::RecvBuffer;
use dope_quic::wire::packet;
use packet::cid;

const CID: [u8; 8] = [0x31; 8];
pub const SERVER_ROUTE: u8 = 0;
pub const CLIENT_ROUTE: u8 = 1;

pub const ENDPOINT: Config = Config {
    max_conns: 1,
    outgoing_capacity: 16,
    outgoing_bytes_capacity: 1 << 16,
    packet_buffer_slots: 16,
    packet_buffer_bytes: 2048,
    cid_rotation: Rotation::disabled(),
};

#[derive(Debug)]
pub enum Setup {
    Parameters(param::Error),
    Options(Invalid),
    Shutdown(wake::CreateError),
    Register(domain::Register),
    Plan(endpoint::PlanError),
    Config(config::Error),
    Claim(Claim),
    Payload(payload::Error),
    Identity(dope_tls::Error),
    Tls(dope_tls::Error),
    Connect(errors::Connect),
    Id(consume::Error),
}

#[derive(Debug)]
pub enum Stage<'report> {
    Deadline(clock::Range<Duration>),
    Bind(endpoint::BindError),
    Session(session::Error<'report, Result<(), drive::Error>>),
    Drive(drive::Error),
}

pub enum Error<'owner, 'report> {
    Create(create::Error<'owner>),
    Domain(domain::Error<'owner, Infallible, Result<(), Stage<'report>>, shutdown::Source>),
    Stage(Stage<'report>),
    Setup(Setup),
    Observers(Rc<RefCell<Proof>>),
}

fn driver_config(res: impl settings::Resource) -> Result<settings::Config, Setup> {
    Needs::from_tree(&res)
        .map_err(Setup::Claim)?
        .apply_exact(Config::driver(settings::Datagram::new(
            settings::Ring::try_round(64).map_err(Setup::Claim)?,
            Len::try_from(ENDPOINT.packet_buffer_bytes).map_err(Setup::Payload)?,
        )))
        .map_err(Setup::Claim)
}

#[pin_project::pin_project]
#[derive(dope::Application)]
#[dispatcher(driver = 'd)]
#[coordinate]
struct App<'d> {
    #[pin]
    #[manifold]
    server: endpoint::Endpoint<'d, SERVER_ROUTE, Capture<'d, SERVER_ROUTE>, RecvBuffer<'d>>,
    #[pin]
    #[manifold(control)]
    client: endpoint::Endpoint<'d, CLIENT_ROUTE, Capture<'d, CLIENT_ROUTE>, RecvBuffer<'d>>,
    #[dispatcher(schedule)]
    timeout: clock::Deadline<'d>,
}

impl<'d> App<'d> {
    fn coordinate(mut this: app_coord::Fields<'_, 'd>) -> control::Flow {
        if this.timeout.is_due(this.step.now()) {
            this.client.view().timeout();
            return control::Flow::Idle;
        }
        if let Some(connect) = this.client.view().take_connect()
            && let Err(cause) = this.client.at(this.step.clock()).connect(
                connect.peer,
                &connect.authority,
                connect.params,
                CID.to_vec(),
            )
        {
            this.client.view().fail(Fault::Connect(cause));
            return control::Flow::Idle;
        }
        if let Some((handle, payload)) = this.client.view().take_send() {
            let result = {
                let mut client = this.client.at(this.step.clock());
                client
                    .try_datagram(handle, payload)
                    .and_then(|()| client.try_datagram(handle, b"owner lifetime barrier".to_vec()))
            };
            if let Err(cause) = result {
                this.client.view().fail(Fault::Datagram(cause));
            }
        }
        control::Flow::Idle
    }
}

#[pin_project::pin_project]
#[derive(dope::Application)]
#[dispatcher(driver = 'd)]
#[coordinate]
struct PooledApp<'d, 'tls> {
    #[pin]
    #[manifold]
    server: endpoint::Endpoint<
        'd,
        SERVER_ROUTE,
        Capture<'d, SERVER_ROUTE, Pooled<'tls>>,
        RecvBuffer<'d>,
        endpoint::Idle,
        owner::Pooled<'tls>,
    >,
    #[pin]
    #[manifold(control)]
    client: endpoint::Endpoint<
        'd,
        CLIENT_ROUTE,
        Capture<'d, CLIENT_ROUTE, Pooled<'tls>>,
        RecvBuffer<'d>,
        endpoint::Idle,
        owner::Pooled<'tls>,
    >,
    #[dispatcher(schedule)]
    timeout: clock::Deadline<'d>,
}

impl<'d, 'tls> PooledApp<'d, 'tls> {
    fn coordinate(mut this: pooled_app_coord::Fields<'_, 'd, 'tls>) -> control::Flow {
        if this.timeout.is_due(this.step.now()) {
            this.client.view().timeout();
            return control::Flow::Idle;
        }
        if let Some(connect) = this.client.view().take_connect()
            && let Err(cause) = this.client.at(this.step.clock()).pool_connect(
                connect.peer,
                connect.pool,
                connect.params,
                CID.to_vec(),
            )
        {
            this.client.view().fail(Fault::Connect(cause));
            return control::Flow::Idle;
        }
        if let Some((handle, payload)) = this.client.view().take_send() {
            let result = {
                let mut client = this.client.at(this.step.clock());
                client.try_datagram(handle, payload).and_then(|()| {
                    client.try_datagram(handle, b"pooled owner lifetime barrier".to_vec())
                })
            };
            if let Err(cause) = result {
                this.client.view().fail(Fault::Datagram(cause));
            }
        }
        control::Flow::Idle
    }
}

pub fn mode<T>(
    payload: Vec<u8>,
    stream: bool,
    fail: bool,
    recover: impl recovery::Recover,
    finish: impl for<'owner, 'report> FnOnce(
        Result<(Proof, Vec<Reclaimed>), Error<'owner, 'report>>,
    ) -> T,
) -> Result<T, Setup> {
    let (signing, key) = peer::raw(0x52).map_err(Setup::Identity)?;
    let auth = tls::client(key).map_err(Setup::Tls)?;
    let tls = signing.server().map_err(Setup::Tls)?;
    let params = param::Set::builder()
        .idle_ms(30_000)
        .datagram(Some(2048))
        .initial_data(4096)
        .stream_uni(2048)
        .uni_count(2)
        .try_build()
        .map_err(Setup::Parameters)?;
    let (source, stop) = shutdown::Pair::new().map_err(Setup::Shutdown)?.split();
    let proof = Rc::new(RefCell::new(Proof {
        read: Reading {
            stream,
            len: fail.then_some(payload.len()),
            ..Reading::default()
        },
        payload: Some(payload),
        stop: Some(stop),
        ..Proof::default()
    }));
    let bind = SocketAddr::from(([127, 0, 0, 1], 0));
    let srv_plan = server::Plan::<SERVER_ROUTE, receive::Adaptive>::new(
        bind,
        tls,
        Options::try_from(params.clone()).map_err(Setup::Options)?,
        ENDPOINT,
    )
    .map_err(Setup::Plan)?;
    let cli_plan = client::Plan::<CLIENT_ROUTE, receive::Adaptive>::new(bind, ENDPOINT)
        .map_err(Setup::Config)?;
    let config = driver_config((srv_plan.as_ref(), cli_plan.as_ref()))?;
    let mut create = Attempt::new();
    let runtime = match Executor::new(&mut create, config) {
        Ok(runtime) => runtime,
        Err(cause) => return Ok(finish(Err(Error::Create(cause)))),
    }
    .shutdown(source)
    .map_err(Setup::Register)?;
    let mut reports = Vec::new();
    let mut report = session::Completion::new();
    Ok(runtime.run(|runtime| {
        let result = runtime.enter_with(
            |mut session| {
                let (server, client, timeout) = {
                    let mut driver = session.driver();
                    let timeout = driver
                        .driver_ref()
                        .clock()
                        .now()
                        .try_add(Duration::from_secs(2))
                        .map_err(Stage::Deadline)?;
                    let server = srv_plan
                        .bind(Capture::new(false, Rc::clone(&proof), None), &mut driver)
                        .map_err(Stage::Bind)?;
                    let addr = server.local_addr();
                    let client = cli_plan
                        .bind(
                            Capture::new(
                                true,
                                Rc::clone(&proof),
                                Some(Connect {
                                    peer: addr,
                                    authority: auth,
                                    params,
                                }),
                            ),
                            &mut driver,
                        )
                        .map_err(Stage::Bind)?;
                    (server, client, timeout)
                };
                session
                    .with_quiesce(
                        &mut report,
                        App {
                            server,
                            client,
                            timeout,
                        },
                        TIMEOUT,
                        |app| app.run_for(TIMEOUT).map(|_| ()),
                    )
                    .map_err(Stage::Session)?
                    .map_err(Stage::Drive)
            },
            recovery::Policy::new(|event| reports.push(event), recover),
        );
        let result = match result {
            Err(cause) => Err(Error::Domain(cause)),
            Ok(Err(cause)) => Err(Error::Stage(cause)),
            Ok(Ok(())) => Rc::try_unwrap(proof)
                .map(|proof| (proof.into_inner(), reports))
                .map_err(Error::Observers),
        };
        finish(result)
    }))
}

pub fn pooled<T>(
    payload: Vec<u8>,
    recover: impl recovery::Recover,
    finish: impl for<'owner, 'report> FnOnce(
        Result<(Proof, Vec<Reclaimed>, [bool; 2]), Error<'owner, 'report>>,
    ) -> T,
) -> Result<T, Setup> {
    let (signing, key) = peer::raw(0x63).map_err(Setup::Identity)?;
    let tls = signing.server().map_err(Setup::Tls)?;
    let params = param::Set::builder()
        .idle_ms(30_000)
        .datagram(Some(2048))
        .try_build()
        .map_err(Setup::Parameters)?;
    let options = Options::try_from(params.clone()).map_err(Setup::Options)?;
    let auth = accept::Authority::new(tls, options).map_err(Setup::Connect)?;
    let srv_pool = servers::Pool::new(auth, NonZero::<usize>::MIN);
    let cli_pool = clients::Pool::new(tls::client(key).map_err(Setup::Tls)?, NonZero::<usize>::MIN);
    let (source, stop) = shutdown::Pair::new().map_err(Setup::Shutdown)?.split();
    let proof = Rc::new(RefCell::new(Proof {
        payload: Some(payload),
        stop: Some(stop),
        ..Proof::default()
    }));
    let srv_plan =
        endpoint::Plan::<SERVER_ROUTE, receive::Adaptive>::new(ENDPOINT).map_err(Setup::Config)?;
    let bind = SocketAddr::from(([127, 0, 0, 1], 0));
    let cli_plan = client::Plan::<CLIENT_ROUTE, receive::Adaptive>::new(bind, ENDPOINT)
        .map_err(Setup::Config)?;
    let binding = pool::Binding::new(&srv_pool);
    let config = driver_config((&srv_plan, cli_plan.as_ref()))?;
    let mut create = Attempt::new();
    let runtime = match Executor::new(&mut create, config) {
        Ok(runtime) => runtime,
        Err(cause) => return Ok(finish(Err(Error::Create(cause)))),
    }
    .shutdown(source)
    .map_err(Setup::Register)?;
    let mut reports = Vec::new();
    let mut report = session::Completion::new();
    Ok(runtime.run(|runtime| {
        let result = runtime.enter_with(
            |mut session| {
                let (server, client, timeout) = {
                    let mut driver = session.driver();
                    let timeout = driver
                        .driver_ref()
                        .clock()
                        .now()
                        .try_add(Duration::from_secs(2))
                        .map_err(Stage::Deadline)?;
                    let server = binding
                        .bind(
                            bind,
                            Capture::new(false, Rc::clone(&proof), None),
                            srv_plan,
                            &mut driver,
                        )
                        .map_err(Stage::Bind)?;
                    let addr = server.local_addr();
                    let client = cli_plan
                        .bind(
                            Capture::new(
                                true,
                                Rc::clone(&proof),
                                Some(Pooled {
                                    peer: addr,
                                    pool: &cli_pool,
                                    params: params.clone(),
                                }),
                            ),
                            &mut driver,
                        )
                        .map_err(Stage::Bind)?;
                    (server, client, timeout)
                };
                session
                    .with_quiesce(
                        &mut report,
                        PooledApp {
                            server,
                            client,
                            timeout,
                        },
                        TIMEOUT,
                        |app| app.run_for(TIMEOUT).map(|_| ()),
                    )
                    .map_err(Stage::Session)?
                    .map_err(Stage::Drive)
            },
            recovery::Policy::new(|event| reports.push(event), recover),
        );
        let result = match result {
            Err(cause) => Err(Error::Domain(cause)),
            Ok(Err(cause)) => Err(Error::Stage(cause)),
            Ok(Ok(())) => match (|| {
                let cli_opts = Options::try_from(params).map_err(Setup::Options)?;
                let id = cid::Id::try_from(CID.as_slice()).map_err(Setup::Id)?;
                let cli_tls = cli_pool
                    .connect::<CLIENT_ROUTE>(id, id, cli_opts, Plain)
                    .map_err(Setup::Connect)?;
                let srv_tls = srv_pool
                    .accept(accept::Ids::initial(id, id, id))
                    .map_err(Setup::Connect)?;
                Ok((proof, reports, cli_tls, srv_tls))
            })() {
                Err(cause) => Err(Error::Setup(cause)),
                Ok((proof, reports, cli_tls, srv_tls)) => {
                    let opening = [
                        cli_tls.view().lifecycle().is_opening(),
                        srv_tls.view().lifecycle().is_opening(),
                    ];
                    match Rc::try_unwrap(proof) {
                        Ok(proof) => Ok((proof.into_inner(), reports, opening)),
                        Err(proof) => Err(Error::Observers(proof)),
                    }
                }
            },
        };
        finish(result)
    }))
}
