use crate::common::peer;
pub mod common;

use aws_lc_rs::aead;
use common::recovery;
use common::retry::{ENDPOINT, Events, Finish, queue, writable::Peer};
use common::runtime::loopback::capture::Connect;
use common::suite::peers::tls;
use dope::core::driver::life::recovery::{Policy, Recovery};
use dope::core::driver::{life::creation::Attempt, route::Id};
use dope::runtime::{
    executor::{Executor, session},
    shutdown,
};
use dope_quic::conn::life::options::Options;
use dope_quic::proto::{datagram::Arena, param};
use dope_quic::runtime::endpoint::{client::Plan, config::Config};
use dope_quic::runtime::mux::handler::net::Outcome;
use dope_test::harness::scenario::TIMEOUT;
use std::convert::Infallible;
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    time::Duration,
};

#[test]
fn retains_rejected_owner() {
    let (signing, pubkey) = peer::raw(0x6d).expect("peer signing key");
    let params = param::Set::builder()
        .idle_ms(30_000)
        .udp_max(1200)
        .datagram(Some(1200))
        .try_build()
        .expect("datagram parameters");
    let peer = Peer::new(
        signing.server().expect("peer TLS configuration"),
        Options::try_from(params.clone()).expect("peer options"),
    )
    .expect("peer setup");
    let peers = peer.observations();
    let connect = Connect {
        peer: peer.addr().expect("peer address"),
        authority: tls::client(pubkey).expect("client TLS authority"),
        params: &params,
    };
    let dial = Plan::<1>::new(
        "127.0.0.1:0".parse().expect("client address"),
        Config {
            outgoing_capacity: 1,
            ..ENDPOINT
        },
    )
    .expect("single native queue entry");
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
        .with_storage(Arena::try_new(2, 1200).expect("two packet owners"))
        .shutdown(source)
        .expect("shutdown source");
    let fired = Rc::new(Cell::new(Vec::new()));
    let notes = RefCell::new(Vec::new());
    let mut reports = Vec::new();
    let free = executor.run(|executor| {
        let result = executor.enter_with(
            |mut session| {
                let arena = session.storage();
                let error = Rc::new(Cell::new(None));
                let state = Rc::new(queue::State::new(|event: queue::Observed<'_>| {
                    use queue::Observed;
                    match event {
                        Observed::Certificate(cause) => {
                            notes.borrow_mut().push(format!("certificate: {cause:?}"))
                        }
                        Observed::Packet(cause) => {
                            notes.borrow_mut().push(format!("packet: {cause:?}"))
                        }
                        Observed::Receive(cause) => notes
                            .borrow_mut()
                            .push(format!("native receive: {cause:?}")),
                        Observed::Rejected(cause) => {
                            notes.borrow_mut().push(format!("native output: {cause:?}"))
                        }
                        Observed::Transmit(cause) => {
                            notes.borrow_mut().push(format!("transmit: {cause:?}"))
                        }
                        Observed::Blocked => notes
                            .borrow_mut()
                            .push(String::from("full native queue accepted a second owner")),
                        Observed::ReplacedOwner(prior) => assert!(!prior),
                        Observed::ReplacedFlight(prior) => assert!(!prior),
                        Observed::Active(active) => {
                            assert!(active.is_some(), "settlement without acceptance")
                        }
                        Observed::Settled {
                            outcome,
                            wire,
                            pointer,
                        } => {
                            assert!(
                                matches!(outcome, Outcome::Sent(_)),
                                "non-Sent settlement; notes: {:?}",
                                notes.borrow(),
                            );
                            let start = wire
                                .len()
                                .checked_sub(aead::AES_128_GCM.tag_len() + 32)
                                .expect("protected payload length");
                            assert_eq!(wire[start..].as_ptr(), pointer);
                        }
                        Observed::Quota { before, after } => assert_eq!((before, after), (1, 0)),
                        Observed::Park {
                            submitted: sent,
                            writable,
                            second,
                        } => {
                            assert!(!sent, "first owner cannot reach native submission yet");
                            assert_eq!(writable, 0);
                            if let Some(accepted) = second {
                                assert!(!accepted);
                            }
                        }
                        Observed::Receipt(count) => {
                            assert_eq!(count, 1, "native rejection arms one receipt")
                        }
                        Observed::Delivered {
                            first,
                            second,
                            available: free,
                        } => {
                            assert_eq!(first, [1; 32]);
                            assert_eq!(second, [2; 32]);
                            assert_eq!(free, 2);
                        }
                    }
                }));
                let (endpoint, next, timeout) = {
                    let mut driver = session.driver();
                    let now = driver.driver_ref().clock().now();
                    let timeout = now.try_add(Duration::from_secs(2)).expect("deadline");
                    let endpoint = dial
                        .bind(queue::Events(Rc::clone(&state)), &mut driver)
                        .expect("client endpoint");
                    (endpoint, now.into(), timeout)
                };
                let mut finish = session::Completion::new();
                let result = session.with_quiesce(
                    &mut finish,
                    queue::App {
                        client: queue::Queued { endpoint, state },
                        peer,
                        pending: queue::Pending::Connect(connect),
                        arena,
                        finish: Finish {
                            stop: Some(stop),
                            done: Rc::clone(&fired),
                        },
                        error: Rc::clone(&error),
                        timeout,
                        next,
                    },
                    TIMEOUT,
                    |app| app.run_for(TIMEOUT).map(|_| ()),
                );
                let error = error.take();
                assert!(
                    result.is_ok() && error.is_none() && notes.borrow().is_empty(),
                    "session: {result:?}; queue failed: {}; notes: {:?}",
                    error.is_some(),
                    notes.borrow(),
                );
                result.expect("session finish").expect("application finish");
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
    recovery::Teardown::new([Id::fixed::<1>()])
        .verify(reports)
        .expect("endpoint retirement");
    let fired = fired.take();
    assert!(matches!(fired.as_slice(), [Ok(())]), "{fired:?}");
    let peers = peers.borrow();
    assert_eq!(peers.certificates, 0);
    assert!(
        peers
            .owners
            .iter()
            .all(|(stored, current)| stored == current)
    );
    assert_eq!(free, 2);
}
