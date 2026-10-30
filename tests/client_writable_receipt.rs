use crate::common::peer;
use common::suite::peers::tls;
pub mod common;

use common::recovery;
use common::retry::writable::Callback;
use common::retry::{
    ENDPOINT, Events, Finish,
    traces::Immediate,
    writable::{App, Connected, Observed, Peer, Stage},
};
use dope::core::driver::life::recovery::{Policy, Recovery};
use dope::core::driver::{life::creation::Attempt, route::Id};
use dope::runtime::{
    executor::{Executor, session},
    shutdown,
};
use dope_quic::client::{self, EndpointSpec, SlotId, build};
use dope_quic::conn::life::options::Options;
use dope_quic::proto::{datagram::Arena, param};
use dope_quic::runtime::endpoint::client::Plan;
use dope_quic::runtime::mux::handler::hook::writable::Receipt;
use dope_test::harness::scenario::TIMEOUT;
use std::cell::{Cell, RefCell};
use std::convert::Infallible;
use std::{rc::Rc, time::Duration};

#[test]
fn retains_stage_receipt() {
    let (signing, pubkey) = peer::raw(0x6c).expect("raw identity");
    let params = param::Set::builder()
        .idle_ms(30_000)
        .datagram(Some(1200))
        .try_build()
        .expect("datagram parameters");
    let peer = Peer::new(
        signing.server().expect("server TLS"),
        Options::try_from(params.clone()).expect("peer options"),
    )
    .expect("peer setup");
    let options = Options::try_from(params).expect("client options");
    let address = peer.addr().expect("peer address");
    let peers = peer.observations();
    let dial = Plan::<1>::new("127.0.0.1:0".parse().expect("client address"), ENDPOINT)
        .expect("client plan");
    let (source, stop) = shutdown::Pair::new().expect("shutdown pair").split();
    let mut create = Attempt::new();
    let executor = Executor::new(
        &mut create,
        Events::settings(8, dial.as_ref()).expect("driver settings"),
    );
    assert!(
        executor.is_ok(),
        "executor: {:?}",
        executor.as_ref().err().map(|cause| cause.kind())
    );
    let executor = executor
        .ok()
        .expect("executor admission")
        .with_storage(Arena::try_new(2, 1200).expect("packet owners"))
        .shutdown(source)
        .expect("shutdown source");
    let done = Rc::new(Cell::new(Vec::new()));
    let retry = Immediate::default();
    let mut reports = Vec::new();
    let free = executor.run(|executor| {
        let result = executor.enter_with(
            |mut session| {
                let arena = session.storage();
                let observed = Rc::new(RefCell::new(Observed::default()));
                let (client, next, timeout) = {
                    let mut driver = session.driver();
                    let now = driver.driver_ref().clock().now();
                    let timeout = now.try_add(Duration::from_secs(2)).expect("deadline");
                    let client = build::Builder::owned(
                        vec![EndpointSpec {
                            addr: address,
                            authority: tls::client(pubkey).expect("client TLS authority"),
                        }],
                        options,
                        Connected::new(|event: Result<SlotId, Callback<'_>>| {
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
                session
                    .with_quiesce(
                        &mut finish,
                        App {
                            client,
                            peer,
                            arena,
                            stage: Stage::Connect,
                            finish: Finish {
                                stop: Some(stop),
                                done: Rc::clone(&done),
                            },
                            observed: Rc::clone(&observed),
                            timeout,
                            next,
                        },
                        TIMEOUT,
                        |app| app.run_for(TIMEOUT).map(|_| ()),
                    )
                    .expect("session finish")
                    .expect("application finish");
                let observed = observed.borrow();
                assert!(observed.error.is_none(), "writable progress failed");
                assert!(
                    observed
                        .owners
                        .iter()
                        .all(|(returned, original)| returned == original)
                );
                assert!(observed.payloads.iter().all(|payload| payload == &[2; 32]));
                assert_eq!(observed.available, [0]);
                assert_eq!(observed.ready, [Receipt::Ready]);
                assert_eq!(observed.idle, [Receipt::Idle; 3]);
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
            "domain: {:?}",
            result.as_ref().err().map(|cause| cause.cause())
        );
        result.ok().expect("domain completion")
    });
    assert!(retry.0.get().is_none());
    let peers = peers.borrow();
    assert_eq!(peers.certificates, 0);
    assert!(
        peers
            .owners
            .iter()
            .all(|(stored, current)| stored == current)
    );
    recovery::Teardown::new([Id::fixed::<1>()])
        .verify(reports)
        .expect("endpoint retirement");
    let done = done.take();
    assert!(matches!(done.as_slice(), [Ok(())]), "{done:?}");
    assert_eq!(free, 2);
}
