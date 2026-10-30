use dope::core::driver::life::recovery::{Policy, Recovery};
use std::convert::Infallible;
pub mod common;

use std::{
    net::{Ipv4Addr, UdpSocket},
    rc::Rc,
    time::Duration,
};

use dope::core::driver::{life::creation::Attempt, route::KeyTag, settings};
use dope::manifold::network::datagram::plan::{Config, Plan};
use dope::manifold::network::datagram::send;
use dope::runtime::executor::{Executor, session::Completion};
use dope_quic::{
    runtime::endpoint::{self, Payload},
    wire::packet::long::retry::Suffix,
};
use dope_test::{fibers, harness::signals::Gate};
use o3::buffer::write::Sink as _;

use common::runtime::suffix::{App, Observed, Sender};
use settings::claim::Needs;

#[test]
fn returns_allocation() {
    let mut storage = Vec::with_capacity(64);
    storage.extend_from_slice(b"pseudo-prefix");
    let pointer = storage.as_ptr();
    let bytes = storage.capacity();
    let mut suffix = Suffix::new(storage, b'r').expect("suffix");
    suffix.append().write_slice(b"etry-wire").expect("wire");
    {
        let mut tail = suffix.append();
        tail.write_slice(b"discard").expect("discard");
        tail.rollback();
    }
    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("receive timeout");
    let plan = Plan::<KeyTag<0>>::new(Config::new(1, bytes, 1).expect("send bounds"));
    let config = {
        use endpoint::config::Config;
        Needs::from_tree(&plan)
            .expect("claim")
            .apply_to(Config::driver(settings::Datagram::fixed::<16, 2048>()))
            .expect("driver config")
    };
    let settled = Gate::new();
    let observed = Rc::new(Observed::default());
    let mut create = Attempt::new();
    let mut finish = Completion::new();
    let built = Executor::new(&mut create, config);
    assert!(
        built.is_ok(),
        "{:?}",
        built.as_ref().err().map(|error| error.kind())
    );
    built.ok().expect("executor").run(|exec| {
        let result = exec.enter_with(
            |mut session| {
                let endpoint = {
                    let mut driver = session.driver();
                    plan.prepare(&mut driver)
                        .expect("prepare")
                        .bind(
                            (Ipv4Addr::LOCALHOST, 0).into(),
                            Sender {
                                addr: receiver.local_addr().expect("address"),
                                pending: Some(Payload::Retry(suffix)),
                                observed: observed.clone(),
                                settled: settled.clone(),
                            },
                            &mut driver,
                        )
                        .expect("bind")
                };
                assert!(
                    session
                        .with_quiesce(
                            &mut finish,
                            App { endpoint },
                            Duration::from_secs(2),
                            |mut app| {
                                assert_eq!(
                                    fibers::TEST
                                        .try_wait(&mut app, &settled, 1)
                                        .expect("settlement progress"),
                                    fibers::Wait::Reached,
                                );
                            }
                        )
                        .is_ok()
                );
            },
            Policy::new(
                |_| {},
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
    let received = observed.received.take();
    let rejected = observed.rejected.take();
    let mut settled = observed.settlements.take();
    assert!(received.is_empty(), "unexpected receive");
    assert!(rejected.is_none(), "suffix admission");
    assert!(matches!(
        settled.as_slice(),
        [(send::Outcome::Sent(_), Ok(_))]
    ));
    let mut received = [0; 64];
    let (len, _) = receiver.recv_from(&mut received).expect("receive suffix");
    assert_eq!(&received[..len], b"retry-wire");
    let (_, storage) = settled.pop().expect("settlement");
    let storage = storage.expect("settled allocation");
    assert_eq!(storage.as_ptr(), pointer);
    assert_eq!(storage.capacity(), bytes);
    assert_eq!(storage, b"pseudo-prefixretry-wire");
}
