pub mod common;

use common::{
    peer, recovery,
    runtime::loopback::{
        App, CLIENT_ROUTE, ENDPOINT, SERVER_ROUTE,
        capture::{Capture, Connect, Events, Failure, Network, Observed},
        load::{Fairness, Load},
    },
    suite::peers::tls,
};
use dope::{
    core::{
        driver::{
            life::{
                creation::Attempt,
                recovery::{Policy, Recovery},
            },
            route::Id,
            settings::{self, claim::Needs},
        },
        io::datagram::payload::Len,
    },
    runtime::{
        executor::{Executor, session},
        shutdown,
    },
};
use dope_quic::{
    conn::{life::options::Options, output::transmit},
    proto::param,
    runtime::{
        endpoint::{client, config::Config, server},
        mux::app::Watch,
        receive,
    },
};
use dope_test::harness::scenario::TIMEOUT;
use o3::depot::capacity;
use std::{cell::Cell, convert::Infallible, net::SocketAddr, rc::Rc, time::Duration};

#[test]
fn retains_scalar_failure() {
    let (signing, key) = peer::raw(0x39).expect("raw identity");
    let params = param::Set::builder()
        .idle_ms(30_000)
        .datagram(Some(65_535))
        .try_build()
        .expect("transport parameters");
    let options = Options::try_from(params.clone())
        .expect("connection options")
        .into_builder()
        .journals(|limits| limits.crypto::<1>())
        .try_build()
        .expect("one CRYPTO journal slot");
    let bind = SocketAddr::from(([127, 0, 0, 1], 0));
    let server = server::Plan::<SERVER_ROUTE, receive::Copied>::new(
        bind,
        signing.server().expect("server TLS"),
        options,
        ENDPOINT,
    )
    .expect("server plan");
    let client = client::Plan::<CLIENT_ROUTE>::new(bind, ENDPOINT).expect("client plan");
    let claims = (server.as_ref(), client.as_ref());
    let config = Needs::from_tree(&claims)
        .expect("endpoint claims")
        .apply_to(Config::driver(settings::Datagram::new(
            settings::Ring::try_round(128).expect("receive ring"),
            Len::try_from(2048).expect("packet size"),
        )))
        .expect("driver configuration");
    let (source, stop) = shutdown::Pair::new().expect("shutdown pair").split();
    let stop = Rc::new(Cell::new(Some(stop)));
    let mut create = Attempt::new();
    let executor = Executor::new(&mut create, config);
    executor
        .as_ref()
        .map_err(|error| error.kind())
        .expect("native driver");
    let executor = executor
        .ok()
        .expect("driver admission")
        .shutdown(source)
        .expect("shutdown source");
    let mut reports = Vec::new();
    executor.run(|executor| {
        let result = executor.enter_with(
            |mut session| {
                let srv = Rc::new(Events::default());
                let cli = Rc::new(Events::default());
                let srv_net = Observed::default();
                let cli_net = Observed::default();
                let elapsed = Rc::new(Cell::new(false));
                let fairness = Rc::new(Fairness::saturated().expect("fixture scenario"));
                let gso = Rc::new(Cell::new(Some(false)));
                let ingress = Rc::new(Cell::new(0));
                let (server, client, timeout) = {
                    let mut driver = session.driver();
                    let timeout = driver
                        .driver_ref()
                        .clock()
                        .now()
                        .try_add(Duration::from_secs(2))
                        .expect("fixture deadline");
                    let server = server
                        .bind_with::<Watch, _, _, _, _>(&mut driver, |_| {
                            Ok::<_, Infallible>((
                                Capture {
                                    events: Rc::clone(&srv),
                                    stop: Rc::clone(&stop),
                                    connect: None,
                                    timed_out: Rc::clone(&elapsed),
                                    fairness: Rc::clone(&fairness),
                                    gso_active: Rc::clone(&gso),
                                    network: Network {
                                        observed: srv_net.clone(),
                                        ingress: Rc::clone(&ingress),
                                    },
                                },
                                Load {
                                    fairness: Rc::clone(&fairness),
                                    credit: false,
                                    pending: None,
                                },
                            ))
                        })
                        .expect("bound server");
                    let client = client
                        .bind(
                            Capture {
                                events: Rc::clone(&cli),
                                stop: Rc::clone(&stop),
                                connect: Some(Connect {
                                    peer: server.local_addr(),
                                    authority: tls::client(key).expect("client TLS"),
                                    params,
                                }),
                                timed_out: Rc::clone(&elapsed),
                                fairness: Rc::clone(&fairness),
                                gso_active: Rc::clone(&gso),
                                network: Network {
                                    observed: cli_net.clone(),
                                    ingress: Rc::clone(&ingress),
                                },
                            },
                            &mut driver,
                        )
                        .expect("bound client");
                    (server, client, timeout)
                };
                let mut done = session::Completion::new();
                session
                    .with_quiesce(
                        &mut done,
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
                assert!(!elapsed.get(), "transmit failure must close before timeout");
                let events = srv.transmit.take();
                assert_eq!(events.len(), 1, "one original transmit failure");
                let (error, before) = events.into_iter().next().expect("transmit event");
                let (handle, cause) = error.into_parts();
                let expected = transmit::Error::Admission(transmit::Admission::Crypto {
                    needed: 1,
                    reason: capacity::Reason::Full,
                });
                assert_eq!(cause, expected);
                assert_eq!(before, 0, "failure must precede scalar removal");
                assert_eq!(srv.closed.take(), [handle]);
                assert!(cli.transmit.take().is_empty());
                let failure = srv_net.finish().expect_err("server transmit failure");
                assert!(
                    matches!(&failure, Failure::Transmit(cause) if cause == &expected),
                    "{failure:?}"
                );
                cli_net.finish().expect("client output owners settled");
                let failures = fairness.failures.take();
                assert!(
                    failures.is_empty(),
                    "fixture or shutdown failure: {failures:?}"
                );
            },
            Policy::new(
                |event| reports.push(event),
                |failure: Recovery<'_, '_>| -> Infallible {
                    panic!("native recovery: {:?}", failure.cause())
                },
            ),
        );
        result
            .as_ref()
            .map_err(|error| error.cause())
            .expect("driver retirement");
    });
    recovery::Teardown::new([Id::fixed::<SERVER_ROUTE>(), Id::fixed::<CLIENT_ROUTE>()])
        .verify(reports)
        .expect("endpoint receive owners retire exactly once");
}
