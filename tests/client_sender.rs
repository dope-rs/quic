use crate::common::peer;
use common::suite::peers::tls;
pub mod common;

use common::recovery::Teardown;
use common::retry::{
    ENDPOINT, Events, Finish,
    sender::{App, Phase},
    traces::Immediate,
    writable::{Callback, Connected, Peer},
};
use dope::core::driver::{
    life::{creation::Attempt, recovery},
    route::Id,
};
use dope::runtime::{
    executor::{Executor, session},
    shutdown,
};
use dope_quic::client::{self, EndpointSpec, build};
use dope_quic::conn::life::options::Options;
use dope_quic::proto::{datagram::Arena, param};
use dope_quic::runtime::endpoint::{client::Plan, config::Config};
use dope_test::harness::scenario::TIMEOUT;
use std::{cell::Cell, convert::Infallible, num::NonZero, rc::Rc, time::Duration};

#[test]
fn reuses_sender_vacancy() {
    let (signing, pubkey) = peer::raw(0x6e).expect("raw identity");
    let auth = tls::client(pubkey).expect("client TLS authority");
    let params = param::Set::builder()
        .idle_ms(30_000)
        .datagram(Some(1200))
        .try_build()
        .expect("datagram parameters");
    let peer = Peer::with_limit(
        signing.server().expect("server TLS"),
        Options::try_from(params.clone()).expect("peer options"),
        NonZero::new(2).expect("two connections"),
    )
    .expect("peer");
    let options = Options::try_from(params).expect("client options");
    let addr = peer.addr().expect("peer address");
    let observed = peer.observations();
    let dial = Plan::<1>::new(
        "127.0.0.1:0".parse().expect("client address"),
        Config {
            max_conns: 2,
            ..ENDPOINT
        },
    )
    .expect("two client connections");
    let (source, stop) = shutdown::Pair::new().expect("shutdown pair").split();
    let mut create = Attempt::new();
    let executor = Executor::new(
        &mut create,
        Events::settings(8, dial.as_ref()).expect("settings"),
    );
    assert!(
        executor.is_ok(),
        "executor: {:?}",
        executor.as_ref().err().map(|cause| cause.kind())
    );
    let executor = executor
        .ok()
        .expect("executor admission")
        .with_storage(Arena::try_new(1, 1200).expect("one packet owner"))
        .shutdown(source)
        .expect("shutdown source");
    let done = Rc::new(Cell::new(Vec::new()));
    let retry = Immediate::default();
    let mut reports = Vec::new();
    let free = executor.run(|executor| {
        let result = executor.enter_with(
            |mut session| {
                let arena = session.storage();
                let (client, next, timeout) = {
                    let mut driver = session.driver();
                    let now = driver.driver_ref().clock().now();
                    let timeout = now.try_add(Duration::from_secs(2)).expect("deadline");
                    let client = build::Builder::owned(
                        vec![
                            EndpointSpec {
                                addr,
                                authority: auth.try_clone().expect("authority reference"),
                            },
                            EndpointSpec {
                                addr,
                                authority: auth,
                            },
                        ],
                        options,
                        Connected::new(|event: Result<client::SlotId, Callback<'_>>| {
                            event.expect("only connected events");
                        }),
                        retry.clone(),
                        client::Config {
                            event_budget: 1,
                            retry_budget: 1,
                        },
                    )
                    .expect("client builder")
                    .bind(dial, &mut driver)
                    .expect("client endpoint");
                    (client, now.into(), timeout)
                };
                let mut finish = session::Completion::new();
                let error = Rc::new(Cell::new(None));
                session
                    .with_app(
                        &mut finish,
                        App {
                            client,
                            peer,
                            arena,
                            phase: Phase::Pending(None),
                            finish: Finish {
                                stop: Some(stop),
                                done: Rc::clone(&done),
                            },
                            error: Rc::clone(&error),
                            timeout,
                            next,
                        },
                        |app| app.run_for(TIMEOUT).map(|_| ()),
                    )
                    .expect("session finish")
                    .expect("application finish");
                let error = error.take();
                assert!(error.is_none(), "sender progress failed");
                arena.available()
            },
            recovery::Policy::new(
                |event| reports.push(event),
                |failure: recovery::Recovery<'_, '_>| -> Infallible {
                    panic!("native recovery: {:?}", failure.cause())
                },
            ),
        );
        assert!(
            result.is_ok(),
            "domain: {:?}",
            result.as_ref().err().map(|cause| cause.cause())
        );
        result.ok().expect("domain completion")
    });
    Teardown::new([Id::fixed::<1>()])
        .verify(reports)
        .expect("endpoint retirement");
    assert!(
        matches!(done.take().as_slice(), [Ok(())]),
        "one successful shutdown"
    );
    assert!(retry.0.get().is_none(), "invalid retry transition");
    let observed = observed.borrow();
    assert_eq!(observed.certificates, 0);
    assert!(
        observed
            .owners
            .iter()
            .all(|(stored, event)| stored == event)
    );
    assert_eq!(free, 1);
}
