use crate::common::peer;
use capture::Capture;
use capture::Connect;
use capture::Events;
use capture::{Network, Observed};
use common::recovery;
use common::suite::peers::tls;
use dope::core::driver::life::creation::Attempt;
use dope::core::driver::life::recovery::{Policy, Recovery};
use dope::core::driver::route::Id;
use dope::core::driver::settings;
use dope::core::{driver::settings::claim::Needs, io::datagram::payload::Len};
use dope::runtime::executor::Executor;
use dope::runtime::executor::session;
use dope::runtime::shutdown;
use dope_quic::conn::life::options::Options;
use dope_quic::proto::param;
use dope_quic::runtime::endpoint::client;
use dope_quic::runtime::endpoint::config::Config;
use dope_quic::runtime::endpoint::server;
use dope_quic::runtime::mux::app::Watch;
use dope_quic::runtime::receive;
use dope_test::harness::scenario::TIMEOUT;
use dope_test::quic::{Lane, Oracle};
use load::Load;
use load::{Fairness, Packets};
use std::cell::Cell;
use std::convert::Infallible;
use std::mem;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

pub mod common;
use common::runtime::loopback::{
    APPLICATION_PAYLOAD, App, CLIENT_ROUTE, ENDPOINT, SATURATED_DATAGRAMS, SERVER_ROUTE, capture,
    load,
};

#[test]
fn saturated_progress() {
    for lane in [Lane::Plain, Lane::Gso] {
        let (active, [server, client]) = {
            let want_gso = lane.is_gso();
            let (signing, key) = peer::raw(0x39).expect("raw identity");
            let identity = signing.server().expect("server TLS");
            let params = param::Set::builder()
                .idle_ms(30_000)
                .datagram(Some(65_535))
                .try_build()
                .expect("fixture transport parameters");
            let options = Options::try_from(params.clone())
                .expect("fixture connection options must be valid");
            let srv_net = Observed::default();
            let cli_net = Observed::default();
            let (source, stop) = shutdown::Pair::new()
                .expect("shutdown pair capacity must be available")
                .split();
            let stop = Rc::new(Cell::new(Some(stop)));
            let gso = Rc::new(Cell::new((!want_gso).then_some(false)));
            let srv_plan = server::Plan::<SERVER_ROUTE, receive::Copied>::new(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback wildcard server address must parse"),
                identity,
                options,
                ENDPOINT,
            )
            .expect("loopback server resources must form an endpoint plan");
            let cli_plan = client::Plan::<CLIENT_ROUTE>::new(
                "127.0.0.1:0"
                    .parse::<SocketAddr>()
                    .expect("loopback wildcard client address must parse"),
                ENDPOINT,
            )
            .expect("loopback client resources must form an endpoint plan");
            let claims = (srv_plan.as_ref(), cli_plan.as_ref());
            let base = Config::driver(settings::Datagram::new(
                settings::Ring::try_round(128).expect("fixture receive ring"),
                Len::try_from(2048).expect("fixture packet size"),
            ));
            let config = Needs::from_tree(&claims)
                .expect("server and client resource claims must compose")
                .apply_to(base)
                .expect("composed endpoint claims must fit the driver baseline");
            let mut create = Attempt::new();
            let built = Executor::new(&mut create, config);
            assert!(
                built.is_ok(),
                "{:?}",
                built.as_ref().err().map(|error| error.kind())
            );
            let exec = built
                .ok()
                .expect("executor")
                .shutdown(source)
                .expect("executor must accept its sole shutdown source");
            let (srv_out, cli_out) = {
                let mut reports = Vec::new();
                let output = exec.run(|exec| {
                    let result = exec.enter_with(
                        |mut session| {
                            let srv_log = Rc::new(Events::default());
                            let cli_log = Rc::new(Events::default());
                            let elapsed = Rc::new(Cell::new(false));
                            let fair = Rc::new(Fairness::saturated().expect("saturated scenario"));
                            let ingress = Rc::new(Cell::new(0));
                            let (server, client, timeout) = {
                                let mut driver = session.driver();
                                let timeout = driver
                                    .driver_ref()
                                    .clock()
                                    .now()
                                    .try_add(Duration::from_secs(2))
                                    .expect("fixture deadline range");
                                let server = srv_plan
                                    .bind_with::<Watch, _, _, _, _>(&mut driver, |_| {
                                        Ok::<_, Infallible>((
                                            Capture {
                                                events: Rc::clone(&srv_log),
                                                stop: Rc::clone(&stop),
                                                connect: None,
                                                timed_out: Rc::clone(&elapsed),
                                                fairness: Rc::clone(&fair),
                                                gso_active: Rc::clone(&gso),
                                                network: Network {
                                                    observed: srv_net.clone(),
                                                    ingress: Rc::clone(&ingress),
                                                },
                                            },
                                            Load {
                                                fairness: Rc::clone(&fair),
                                                credit: true,
                                                pending: None,
                                            },
                                        ))
                                    })
                                    .expect("server plan must bind its capture and load driver");
                                let srv_addr = server.local_addr();
                                let client = cli_plan
                                    .bind(
                                        Capture {
                                            events: Rc::clone(&cli_log),
                                            stop: Rc::clone(&stop),
                                            connect: Some(Connect {
                                                peer: srv_addr,
                                                authority: tls::client(key).expect("client TLS authority"),
                                                params,
                                            }),
                                            timed_out: Rc::clone(&elapsed),
                                            fairness: Rc::clone(&fair),
                                            gso_active: Rc::clone(&gso),
                                            network: Network {
                                                observed: cli_net.clone(),
                                                ingress: Rc::clone(&ingress),
                                            },
                                        },
                                        &mut driver,
                                    )
                                    .expect("client plan must bind its capture");
                                (server, client, timeout)
                            };

                            let mut report = session::Completion::new();
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
                                .expect("session completion")
                                .expect("application completion");

                            let srv_done = srv_net
                                .finish()
                                .expect("every server output owner must be settled");
                            let cli_done = cli_net
                                .finish()
                                .expect("every client output owner must be settled");
                            let srv_up = srv_log.established.take();
                            let cli_up = cli_log.established.take();
                            assert!(
                                !elapsed.get(),
                                "loopback deadline elapsed after {} handshakes, {} admissions, {} deliveries, \
                                 and {} ingress packets; server sent {}/{}/{} operations/datagrams/bytes \
                                 and client sent {}/{}/{}",
                                srv_up.len() + cli_up.len(),
                                fair.admitted.get(),
                                fair.received.get(),
                                ingress.get(),
                                srv_done.operations(),
                                srv_done.datagrams(),
                                srv_done.bytes(),
                                cli_done.operations(),
                                cli_done.datagrams(),
                                cli_done.bytes(),
                            );
                            assert_eq!(srv_up.len() + cli_up.len(), 2);
                            assert_eq!(srv_up.len(), 1);
                            assert_eq!(cli_up.len(), 1);
                            assert!(!srv_log.certificates.get());
                            assert!(!cli_log.certificates.get());
                            assert!(srv_log.packet.take().is_none());
                            assert!(cli_log.packet.take().is_none());
                            assert_eq!(fair.admitted.get(), SATURATED_DATAGRAMS);
                            assert_eq!(fair.received.get(), SATURATED_DATAGRAMS);
                            assert!(!fair.stale.get(), "stale handle must not select a connection");
                            let failures = fair.failures.take();
                            assert!(
                                failures.is_empty(),
                                "bounded saturated sends must not fail terminally: {failures:?}",
                            );
                            assert_ne!(ingress.get(), 0, "kernel UDP ingress was not observed");
                            let first = fair
                                .first_received_at
                                .get()
                                .expect("client must observe saturated endpoint output");
                            assert!(
                                first < SATURATED_DATAGRAMS,
                                "application drained before transport and output progressed"
                            );
                            let oracle = mem::replace(
                                &mut *fair.packets.oracle.borrow_mut(),
                                Oracle::new(Packets::scenario().expect("saturated scenario")),
                            );
                            assert!(oracle.is_complete(), "all saturated payloads must arrive");
                            let done = oracle
                                .finish()
                                .expect("every saturated payload must be delivered");
                            assert_eq!(done.delivered(), SATURATED_DATAGRAMS);
                            assert_eq!(done.bytes(), SATURATED_DATAGRAMS * APPLICATION_PAYLOAD);
                            (srv_done, cli_done)
                        },
                        Policy::new(
                            |event| reports.push(event),
                            |failure: Recovery<'_, '_>| -> Infallible {
                                panic!("native recovery: {:?}", failure.cause())
                            },
                        ),
                    );
                    assert!(
                        result.is_ok(),
                        "{:?}",
                        result.as_ref().err().map(|error| error.cause())
                    );
                    result.ok().expect("domain completion")
                });
                recovery::Teardown::new([Id::fixed::<SERVER_ROUTE>(), Id::fixed::<CLIENT_ROUTE>()])
                    .verify(reports)
                    .expect("both endpoint receive operations must retire exactly once");
                output
            };
            (gso.get() == Some(true), [srv_out, cli_out])
        };
        if !lane.is_gso() {
            assert!(!active);
        }
        for net in [server, client] {
            assert_eq!(net.failed_ops(), 0);
            assert_eq!(net.shutdowns(), 0);
        }
        let saved = server.saved_ops();
        if active {
            assert!(server.gso_ops() != 0);
            assert!(saved != 0);
            assert!(server.max_batch() > 1);
            assert!(server.operations() < server.datagrams());
        } else {
            assert_eq!(server.gso_ops(), 0);
            assert_eq!(saved, 0);
        }
    }
}
