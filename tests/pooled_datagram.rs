use crate::common::peer;
use common::suite::peers::tls;
use dope::core::driver::life::recovery::{Policy, Recovery};
use std::convert::Infallible;
pub mod common;
use common::recovery;
use common::runtime::pooled::{
    App, CLIENT_ROUTE, Capture, Connect, Errors, PAYLOAD, SERVER_ROUTE, State, endpoint,
};
use dope::core::driver::life::creation::Attempt;
use dope::core::driver::{route::Id, settings};
use dope::core::io::datagram::payload::Len;
use dope::runtime::executor::session;
use dope::runtime::{executor::Executor, shutdown};
use dope_quic::proto::{datagram::Arena, param};
use dope_quic::runtime::endpoint::{client, config::Config, server};
use dope_quic::runtime::receive;
use dope_test::harness::scenario::TIMEOUT;
use settings::claim::Needs;
use std::{cell::Cell, net::SocketAddr, rc::Rc, time::Duration};

#[test]
fn slot_returns() {
    let (signing, key) = peer::raw(0x39).expect("raw identity");
    let identity = signing.server().expect("server TLS");
    let params = param::Set::builder()
        .idle_ms(30_000)
        .datagram(Some(65_535))
        .try_build()
        .expect("fixture transport parameters");
    let arena = Arena::try_new(1, 1200).expect("packet arena");
    let large = Arena::try_new(1, 8192).expect("large packet arena");
    let received = Rc::new(Cell::new(false));
    let (source, stop) = shutdown::Pair::new().expect("shutdown pair").split();
    let stop = Rc::new(Cell::new(Some(stop)));
    let srv_plan = server::Plan::<SERVER_ROUTE, receive::Copied>::from_params(
        "127.0.0.1:0".parse::<SocketAddr>().expect("server bind"),
        identity,
        params.clone(),
        endpoint(),
    )
    .expect("server plan");
    let cli_plan = client::Plan::<CLIENT_ROUTE>::new(
        "127.0.0.1:0".parse::<SocketAddr>().expect("client bind"),
        Config {
            outgoing_bytes_capacity: 4096,
            ..endpoint()
        },
    )
    .expect("client plan");
    let claims = (srv_plan.as_ref(), cli_plan.as_ref());
    let baseline = Config::driver(
        settings::Datagram::try_new(
            settings::Ring::try_round(32).expect("fixture receive ring"),
            Len::try_from(2048).expect("fixture packet size"),
        )
        .expect("fixture datagram receive layout"),
    );
    let config = Needs::from_tree(&claims)
        .expect("compose endpoint claims")
        .apply_to(baseline)
        .expect("realize endpoint driver config");
    let mut create = Attempt::new();
    let built = Executor::new(&mut create, config);
    assert!(
        built.is_ok(),
        "{:?}",
        built.as_ref().err().map(|error| error.kind())
    );
    let executor = built
        .ok()
        .expect("executor")
        .with_storage((arena, large))
        .shutdown(source)
        .expect("shutdown source");

    let free = {
        let mut reports = Vec::new();
        let output = executor.run(|executor| {
            let result = executor.enter_with(
                |mut session| {
                    let (arena, large) = session.storage();
                    let mut packet = large
                        .try_acquire(PAYLOAD.len())
                        .expect("oversized resident owner");
                    packet.payload_mut().copy_from_slice(PAYLOAD);
                    let srv_up = Rc::new(Cell::new(None));
                    let cli_up = Rc::new(Cell::new(None));
                    let errors = Rc::new(Errors::default());
                    let (server, client, connect, timeout) = {
                        let mut driver = session.driver();
                        let timeout = driver
                            .driver_ref()
                            .clock()
                            .now()
                            .try_add(Duration::from_secs(2))
                            .expect("fixture deadline range");
                        let server = srv_plan
                            .bind(
                                Capture {
                                    established: srv_up,
                                    errors: Rc::clone(&errors),
                                    received: Rc::clone(&received),
                                    stop: Rc::clone(&stop),
                                },
                                &mut driver,
                            )
                            .expect("server");
                        let connect = Connect {
                            peer: server.local_addr(),
                            authority: tls::client(key).expect("client TLS authority"),
                            params: params.clone(),
                        };
                        let client = cli_plan
                            .bind(
                                Capture {
                                    established: cli_up,
                                    errors: Rc::clone(&errors),
                                    received: Rc::clone(&received),
                                    stop: Rc::clone(&stop),
                                },
                                &mut driver,
                            )
                            .expect("client");
                        (server, client, connect, timeout)
                    };
                    let mut report = session::Completion::new();
                    session
                        .with_quiesce(
                            &mut report,
                            App {
                                server,
                                client,
                                state: State {
                                    arena,
                                    connect: Some(connect),
                                    packet: Some(packet),
                                    errors: Rc::clone(&errors),
                                    sent: false,
                                },
                                timeout,
                            },
                            TIMEOUT,
                            |app| app.run_for(TIMEOUT).map(|_| ()),
                        )
                        .expect("session completion")
                        .expect("application completion");
                    let packets = errors.packets.take();
                    let failures = errors.failures.take();
                    assert!(packets.is_empty());
                    assert!(!errors.certificates.get());
                    assert!(failures.is_empty(), "{failures:?}");
                    assert_eq!(errors.resident.get(), Some((8192, 4096)));
                    assert_eq!(large.available(), 1);
                    arena.available()
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

    assert!(received.get());
    assert_eq!(free, 1);
}
