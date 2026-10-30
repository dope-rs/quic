use crate::common::peer;
use dope::core::driver::life::creation::Attempt;
use dope::core::driver::life::recovery::{Policy, Recovery};
use dope::runtime::executor::session;
use std::convert::Infallible;
pub mod common;
use crate::common::recovery;
use crate::common::suite::peers::tls;
use dope::core::driver::route::Id;
use dope_quic::conn::life::{options::Options, tls::clients};
use dope_quic::runtime::endpoint::config;
use dope_test::harness::scenario::TIMEOUT;
use std::cell::Cell;
use std::num::NonZero;
use std::rc::Rc;
use std::time::Duration;

use dope::runtime::{executor::Executor, shutdown};
use dope_quic::client::{self, EndpointSpec, PooledSpec, SlotId, build};
use dope_quic::errors;
use dope_quic::proto::{cid, param};
use dope_quic::runtime::endpoint::{client::Plan, server};
use dope_quic::runtime::receive;

use crate::common::retry::{
    BIND, CLIENT_ROUTE, Causal, Close, Context, ENDPOINT, Events, Pooled, SERVER_ROUTE,
    traces::{Backoff, CausalConfig, CauseBackoff, Config, History, Immediate, Observed},
};

#[test]
fn immediate_reuses_slot() {
    let (signing, pubkey) = peer::raw(0x39).expect("fixture raw public key must construct");
    let cert = signing
        .server()
        .expect("fixture server configuration must construct");
    let params = param::Set::builder()
        .idle_ms(30_000)
        .datagram(Some(65_535))
        .try_build()
        .expect("fixture transport parameters");
    let trace = History::default();
    let (source, stop) = shutdown::Pair::new()
        .expect("shutdown trigger pair has capacity")
        .split();
    let serve = server::Plan::<SERVER_ROUTE, receive::Copied>::from_params(
        BIND,
        cert,
        params.clone(),
        ENDPOINT,
    )
    .expect("server endpoint capacities are valid");
    let dial =
        Plan::<CLIENT_ROUTE>::new(BIND, ENDPOINT).expect("client endpoint capacities are valid");
    let claims = (serve.as_ref(), dial.as_ref());
    let mut create = Attempt::new();
    let built = Executor::new(
        &mut create,
        Events::settings(64, claims).expect("endpoint claims"),
    );
    assert!(
        built.is_ok(),
        "{:?}",
        built.as_ref().err().map(|error| error.kind())
    );
    let executor = built
        .ok()
        .expect("executor")
        .shutdown(source)
        .expect("shutdown source is installed once");
    {
        let mut reports = Vec::new();
        executor.run(|executor| {
            let result = executor.enter_with(
                |mut session| {
                    let events = Events::new(stop);
                    let streams = events.streams.clone();
                    let errors = events.errors.clone();
                    let connects = events.attempts.connects.clone();
                    let exact = events.attempts.exact_checked.clone();
                    let elapsed = events.timed_out.clone();
                    let address = events.address.clone();
                    let done = events.finish.done.clone();
                    let (server, client, timeout) = {
                        let mut driver = session.driver();
                        let timeout = driver
                            .driver_ref()
                            .clock()
                            .now()
                            .try_add(Duration::from_secs(2))
                            .expect("fixture deadline range");
                        let server = serve
                            .bind(Close(errors.clone()), &mut driver)
                            .expect("server plan binds to the session driver");
                        let client = build::Builder::owned_with(
                            vec![EndpointSpec {
                                addr: server.local_addr(),
                                authority: tls::client(pubkey).expect("client TLS authority"),
                            }],
                            CausalConfig {
                                trace: &trace,
                                params: params.clone(),
                            },
                            events,
                            CauseBackoff(&trace),
                            client::Config {
                                event_budget: 64,
                                retry_budget: 64,
                            },
                        )
                        .bind(dial, &mut driver)
                        .expect("client plan binds to the session driver");
                        (server, client, timeout)
                    };
                    assert!(client.smoothed_rtt(SlotId::from_index(0)).is_none());
                    assert!(client.path_stats(SlotId::from_index(0)).is_none());
                    assert!(client.path_stats(SlotId::from_index(1)).is_none());
                    let mut report = session::Completion::new();
                    session
                        .with_quiesce(
                            &mut report,
                            Causal {
                                server,
                                client,
                                timeout,
                            },
                            TIMEOUT,
                            |app| app.run_for(TIMEOUT).map(|_| ()),
                        )
                        .expect("session completion")
                        .expect("application completion");
                    let invalid = trace.errors.take();
                    assert!(invalid.is_empty(), "{invalid:?}");
                    assert!(!elapsed.get(), "reconnect deadline elapsed");
                    assert_eq!(connects.get(), 3, "shutdown restarted the client");
                    assert!(exact.get(), "stale exact attempt was not rejected");
                    assert!(!address.get().is_null(), "protocol was never pinned");
                    assert!(streams.get().is_none(), "unexpected stream");
                    assert!(errors.packets.take().is_empty());
                    let certs = errors.certificates.take();
                    assert!(certs.is_empty(), "{certs:?}");
                    for message in errors.connections.take() {
                        eprintln!("{message}");
                    }
                    let faults = errors.violations.take();
                    assert!(faults.is_empty(), "{faults:?}");
                    let done = done.take();
                    assert!(matches!(done.as_slice(), [Ok(())]), "{done:?}");
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
        });
        recovery::Teardown::new([Id::fixed::<SERVER_ROUTE>(), Id::fixed::<CLIENT_ROUTE>()])
            .verify(reports)
            .expect("exact endpoint receive retirement");
    };
    let attempts = trace.attempts.take();
    let retries = trace.retries.take();
    assert!(
        attempts.len() >= 3,
        "three live attempts were not configured"
    );
    assert!(
        retries.len() >= 2,
        "live closes were not scheduled for retry"
    );
    for index in 0..2 {
        let current = attempts[index];
        let retry = retries[index];
        let next = attempts[index + 1];
        assert_eq!(current.ordinal, 1);
        assert!(retry.cause == client::RetryCause::ConnectionClosed);
        assert!(retry.previous == current.id);
        assert_eq!(retry.previous_ordinal, current.ordinal);
        assert!(retry.next == next.id);
        assert_eq!(retry.next_ordinal, 1);
        assert_eq!(next.ordinal, 1);
        assert_eq!(next.id.generation(), current.id.generation() + 1);
    }
}

#[test]
fn borrowed_attempt_context() {
    let (_, pubkey) = peer::raw(0x3a).expect("fixture raw public key must construct");
    let trace = Observed::default();
    let (source, stop) = shutdown::Pair::new()
        .expect("shutdown trigger pair has capacity")
        .split();
    let limits = config::Config {
        max_conns: 1,
        outgoing_capacity: 8,
        outgoing_bytes_capacity: 16 * 1024,
        packet_buffer_slots: 8,
        packet_buffer_bytes: 2048,
        cid_rotation: cid::Rotation::disabled(),
    };
    let dial =
        Plan::<CLIENT_ROUTE>::new(BIND, limits).expect("bounded client endpoint config is valid");
    let mut create = Attempt::new();
    let built = Executor::new(
        &mut create,
        Events::settings(8, dial.as_ref()).expect("endpoint claims"),
    );
    assert!(
        built.is_ok(),
        "{:?}",
        built.as_ref().err().map(|error| error.kind())
    );
    let executor = built
        .ok()
        .expect("executor")
        .shutdown(source)
        .expect("shutdown source is installed once");
    {
        let mut reports = Vec::new();
        executor.run(|executor| {
            let result = executor.enter_with(
                |mut session| {
                    let events = Events::new(stop);
                    let streams = events.streams.clone();
                    let errors = events.errors.clone();
                    let elapsed = events.timed_out.clone();
                    let done = events.finish.done.clone();
                    let (client, timeout) = {
                        let mut driver = session.driver();
                        let timeout = driver
                            .driver_ref()
                            .clock()
                            .now()
                            .try_add(Duration::from_millis(20))
                            .expect("fixture deadline range");
                        let client = build::Builder::owned_with(
                            vec![EndpointSpec {
                                addr: "127.0.0.1:9"
                                    .parse()
                                    .expect("discard UDP endpoint address is valid"),
                                authority: tls::client(pubkey).expect("client TLS authority"),
                            }],
                            Config(&trace),
                            events,
                            Backoff(&trace),
                            client::Config {
                                event_budget: 8,
                                retry_budget: 8,
                            },
                        )
                        .bind(dial, &mut driver)
                        .expect("client plan binds to the session driver");
                        (client, timeout)
                    };
                    let mut report = session::Completion::new();
                    session
                        .with_quiesce(&mut report, Context { client, timeout }, TIMEOUT, |app| {
                            app.run_for(TIMEOUT).map(|_| ())
                        })
                        .expect("session completion")
                        .expect("application completion");
                    assert!(elapsed.get(), "attempt-context deadline did not run");
                    assert!(streams.get().is_none(), "unexpected stream");
                    assert!(errors.packets.take().is_empty());
                    let certs = errors.certificates.take();
                    assert!(certs.is_empty(), "{certs:?}");
                    for message in errors.connections.take() {
                        eprintln!("{message}");
                    }
                    let faults = errors.violations.take();
                    assert!(faults.is_empty(), "{faults:?}");
                    let done = done.take();
                    assert!(matches!(done.as_slice(), [Ok(())]), "{done:?}");
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
        });
        recovery::Teardown::new([Id::fixed::<CLIENT_ROUTE>()])
            .verify(reports)
            .expect("exact endpoint receive retirement");
    };
    let attempts = trace.history.attempts.take();
    let retries = trace.history.retries.take();
    assert_eq!(attempts.len(), 1);
    assert_eq!(retries.len(), 1);
    let attempt = attempts[0];
    let retry = retries[0];
    assert!(attempt.id.slot() == SlotId::from_index(0));
    assert_eq!(attempt.id.generation(), 1);
    assert_eq!(attempt.ordinal, 1);
    assert!(trace.observed_start.get());
    assert!(retry.cause == client::RetryCause::AttemptFailed);
    assert!(retry.previous == attempt.id);
    assert_eq!(retry.previous_ordinal, attempt.ordinal);
    assert_eq!(retry.next.generation(), retry.previous.generation() + 1);
    assert_eq!(retry.next_ordinal, retry.previous_ordinal + 1);
}

#[test]
fn pool_recycles() {
    let (signing, pubkey) = peer::raw(0x4a).expect("fixture raw public key must construct");
    let cert = signing
        .server()
        .expect("fixture server configuration must construct");
    let params = param::Set::builder()
        .idle_ms(30_000)
        .datagram(Some(65_535))
        .try_build()
        .expect("fixture transport parameters");
    let pool = clients::Pool::new(
        tls::client(pubkey).expect("client TLS authority"),
        NonZero::<usize>::MIN,
    );
    let (source, stop) = shutdown::Pair::new()
        .expect("shutdown trigger pair has capacity")
        .split();
    let serve = server::Plan::<SERVER_ROUTE, receive::Copied>::from_params(
        BIND,
        cert,
        params.clone(),
        ENDPOINT,
    )
    .expect("server endpoint capacities are valid");
    let dial =
        Plan::<CLIENT_ROUTE>::new(BIND, ENDPOINT).expect("client endpoint capacities are valid");
    let claims = (serve.as_ref(), dial.as_ref());
    let mut create = Attempt::new();
    let built = Executor::new(
        &mut create,
        Events::settings(64, claims).expect("endpoint claims"),
    );
    assert!(
        built.is_ok(),
        "{:?}",
        built.as_ref().err().map(|error| error.kind())
    );
    let executor = built
        .ok()
        .expect("executor")
        .shutdown(source)
        .expect("shutdown source is installed once");
    {
        let mut reports = Vec::new();
        executor.run(|executor| {
            let result = executor.enter_with(
                |mut session| {
                    let events = Events::new(stop);
                    let streams = events.streams.clone();
                    let errors = events.errors.clone();
                    let connects = events.attempts.connects.clone();
                    let elapsed = events.timed_out.clone();
                    let address = events.address.clone();
                    let failures = Rc::new(Cell::new(Vec::new()));
                    let done = events.finish.done.clone();
                    let backoff = Immediate::default();
                    let (server, client, timeout) = {
                        let mut driver = session.driver();
                        let timeout = driver
                            .driver_ref()
                            .clock()
                            .now()
                            .try_add(Duration::from_secs(2))
                            .expect("fixture deadline range");
                        let server = serve
                            .bind(Close(errors.clone()), &mut driver)
                            .expect("server plan binds to the session driver");
                        let options =
                            Options::try_from(params).expect("fixture connection options");
                        let client = build::Builder::pooled(
                            vec![PooledSpec {
                                addr: server.local_addr(),
                                pool: &pool,
                            }],
                            options,
                            events,
                            backoff.clone(),
                            client::Config {
                                event_budget: 64,
                                retry_budget: 64,
                            },
                        )
                        .expect("pooled client construction accepts one matching pool")
                        .bind(dial, &mut driver)
                        .expect("pooled client plan binds to the session driver");
                        (server, client, timeout)
                    };
                    let mut report = session::Completion::new();
                    session
                        .with_quiesce(
                            &mut report,
                            Pooled {
                                server,
                                client,
                                failures: Rc::clone(&failures),
                                timeout,
                            },
                            TIMEOUT,
                            |app| app.run_for(TIMEOUT).map(|_| ()),
                        )
                        .expect("session completion")
                        .expect("application completion");
                    assert!(!elapsed.get(), "pooled reconnect deadline elapsed");
                    assert_eq!(connects.get(), 3, "one-slot TLS pool did not recycle");
                    for failure in failures.take().iter() {
                        assert!(
                            matches!(
                                failure,
                                errors::SendFailure::Closed(data) if data.as_slice() == [0x42]
                            ),
                            "immediate peer close must retain the rejected datagram",
                        );
                    }
                    assert!(!address.get().is_null(), "pooled protocol was never pinned");
                    assert!(streams.get().is_none(), "unexpected stream");
                    assert!(errors.packets.take().is_empty());
                    let certs = errors.certificates.take();
                    assert!(certs.is_empty(), "{certs:?}");
                    for message in errors.connections.take() {
                        eprintln!("{message}");
                    }
                    let faults = errors.violations.take();
                    assert!(faults.is_empty(), "{faults:?}");
                    assert!(backoff.0.get().is_none(), "{:?}", backoff.0.get());
                    let done = done.take();
                    assert!(matches!(done.as_slice(), [Ok(())]), "{done:?}");
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
        });
        recovery::Teardown::new([Id::fixed::<SERVER_ROUTE>(), Id::fixed::<CLIENT_ROUTE>()])
            .verify(reports)
            .expect("exact endpoint receive retirement");
    };
}
