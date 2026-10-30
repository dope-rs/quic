use crate::common::peer;
use common::suite::peers::tls;
pub mod common;

use common::receive::client::{App, PREFIX, Peer, RESET, Received, STOPPED, SUFFIX, State};
use common::recovery;
use common::retry::writable::Callback;
use common::retry::{ENDPOINT, Events, Finish, traces::Immediate};
use dope::core::driver::life::recovery::{Policy, Recovery};
use dope::core::driver::{life::creation::Attempt, route::Id};
use dope::runtime::{
    executor::{Executor, session},
    shutdown,
};
use dope_quic::client::{self, EndpointSpec, SlotId, build};
use dope_quic::conn::life::options::Options;
use dope_quic::conn::stream::Event;
use dope_quic::proto::param;
use dope_quic::runtime::endpoint::client::Plan;
use dope_quic::runtime::receive;
use dope_test::harness::scenario::TIMEOUT;
use std::cell::{Cell, RefCell};
use std::convert::Infallible;
use std::{rc::Rc, time::Duration};

#[test]
fn resumes_buffered_owners() {
    let (signing, pubkey) = peer::raw(0x6b).expect("raw identity");
    let params = param::Set::builder()
        .idle_ms(30_000)
        .initial_data(14)
        .local_bidi(14)
        .remote_bidi(14)
        .bidi_count(3)
        .try_build()
        .expect("transport parameters");
    let peer = Peer::new(
        signing.server().expect("server TLS"),
        Options::try_from(params.clone()).expect("peer options"),
    )
    .expect("peer setup");
    let options = Options::try_from(params).expect("connection options");
    let address = peer.inner.addr().expect("peer address");
    let peers = peer.inner.observations();
    let dial =
        Plan::<1, receive::Adaptive>::new("127.0.0.1:0".parse().expect("client address"), ENDPOINT)
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
        .shutdown(source)
        .expect("shutdown source");
    let received = Rc::new(RefCell::new(State::default()));
    let done = Rc::new(Cell::new(Vec::new()));
    let retry = Immediate::default();
    let mut reports = Vec::new();
    executor.run(|executor| {
        let result = executor.enter_with(
            |mut session| {
                let (client, next, timeout) = {
                    let mut driver = session.driver();
                    let now = driver.driver_ref().clock().now();
                    let timeout = now.try_add(Duration::from_secs(5)).expect("test deadline");
                    let client = build::Builder::owned(
                        vec![EndpointSpec {
                            addr: address,
                            authority: tls::client(pubkey).expect("client TLS authority"),
                        }],
                        options,
                        Received {
                            state: Rc::clone(&received),
                            observe: |event: Result<SlotId, Callback<'_>>| {
                                event.expect("only connected events");
                            },
                            active: None,
                        },
                        retry.clone(),
                        client::Config {
                            event_budget: 8,
                            retry_budget: 8,
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
                            received: Rc::clone(&received),
                            finish: Finish {
                                stop: Some(stop),
                                done: Rc::clone(&done),
                            },
                            timeout,
                            next,
                        },
                        TIMEOUT,
                        |app| app.run_for(TIMEOUT).map(|_| ()),
                    )
                    .expect("session finish")
                    .expect("application finish");
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
        result.ok().expect("domain completion");
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
        .expect("receive retirement");
    let done = done.take();
    assert!(matches!(done.as_slice(), [Ok(())]), "{done:?}");
    let received = received.borrow();
    assert!(received.error.is_none(), "{:?}", received.error);
    assert!(received.connects.iter().all(Option::is_none));
    assert!(
        received
            .owners
            .iter()
            .all(|(active, current)| *active == Some(*current))
    );
    assert_eq!(
        received.bytes,
        [
            PREFIX.to_vec(),
            SUFFIX.to_vec(),
            PREFIX.to_vec(),
            SUFFIX.to_vec()
        ]
    );
    assert_eq!(received.connects.len(), 2);
    assert!(received.stale_checked);
    assert_eq!(received.ends.len(), 4);
    for (index, pair) in received.ends.as_chunks::<2>().0.iter().enumerate() {
        let attempt = pair[0].0;
        assert_eq!(attempt.slot(), SlotId::from_index(0));
        assert_eq!(attempt.generation(), index as u32 + 1);
        assert_eq!(pair[0].1.get(), 1);
        assert!(pair[0].2);
        assert_eq!(pair[0].3, (index + 1) * 2);
        assert_eq!(pair[1].0, attempt);
        assert_eq!(pair[1].1.get(), 5);
        assert!(!pair[1].2);
        assert_eq!(pair[1].3, pair[0].3);
    }
    assert_eq!(received.terminals.len(), 4);
    for (index, pair) in received.terminals.as_chunks::<2>().0.iter().enumerate() {
        let attempt = pair[0].0;
        assert_eq!(attempt.slot(), SlotId::from_index(0));
        assert_eq!(attempt.generation(), index as u32 + 1);
        assert_eq!(pair[1].0, attempt);
        assert!(pair.iter().any(|(_, event)| matches!(
            event,
            Event::Reset { id, error_code } if id.get() == 9 && *error_code == RESET[index]
        )));
        assert!(pair.iter().any(|(_, event)| matches!(
            event,
            Event::Stopped { id, error_code } if id.get() == 9 && *error_code == STOPPED[index]
        )));
    }
}
