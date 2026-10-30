pub mod common;

use common::{
    peer,
    runtime::embedded::{Capture, Retry, address},
    suite::peers::tls,
};
use dope::core::driver::{
    life::{
        creation::Attempt,
        recovery::{Policy, Recovery},
    },
    settings::{self, claim::Needs},
    storage,
};
use dope::core::io::Reclaimed;
use dope::runtime::{
    executor::{Executor, session},
    shutdown,
};
use dope_quic::conn::life::options::Options;
use dope_quic::runtime::embedded::{self, client, link::Link, plan, server};
use dope_test::harness::scenario::TIMEOUT;
use std::{cell::RefCell, convert::Infallible, rc::Rc};

#[test]
fn restores_flight() {
    let (key, pin) = peer::raw(0x37).expect("peer identity");
    let auth = tls::client(pin).expect("client authority");
    let plan = plan::Plan::try_new(embedded::Config {
        max_connections: 1,
        outgoing_capacity: 2,
        outgoing_bytes_capacity: 2400,
        link_capacity: 2,
        max_flight_resident_bytes: 2048,
    })
    .expect("bounded endpoint plan");
    let client = client::Plan::<7>::new(plan);
    let server = server::Plan::<8>::new(
        key.server().expect("server identity"),
        Options::default(),
        plan,
    )
    .expect("server plan");
    let wrong = plan.link::<31, 7, 8>(address(7), address(9));
    let right = plan.link::<32, 7, 8>(address(7), address(8));
    let cfg = Needs::from_tree(&(&client, &server, &wrong, &right))
        .expect("endpoint and link claims")
        .apply_to(settings::Config::default())
        .expect("driver configuration");
    let (source, stop) = shutdown::Pair::new().expect("shutdown pair").split();
    let mut create = Attempt::new();
    let exec = Executor::new(&mut create, cfg);
    assert!(exec.is_ok(), "{:?}", exec.as_ref().err().map(|e| e.kind()));
    let mut reports = Vec::new();
    exec.ok()
        .expect("executor admission")
        .shutdown(source)
        .expect("shutdown source")
        .with_plan(storage::Scope::new((
            wrong.try_arena().expect("wrong-peer link arena"),
            right.try_arena().expect("correct-peer link arena"),
        )))
        .run(|exec| {
            let result = exec.scope(
                |mut session| {
                    let (wrong, right) = *session.storage();
                    let (client, server, wrong, right) = {
                        let mut driver = session.driver();
                        (
                            client
                                .bind(Capture::default(), &mut driver)
                                .expect("client binding"),
                            server
                                .bind(Capture::default(), &mut driver)
                                .expect("server binding"),
                            Link::try_new(wrong, &mut driver).expect("wrong link binding"),
                            Link::try_new(right, &mut driver).expect("right link binding"),
                        )
                    };
                    let seen = Rc::new(RefCell::new(None));
                    let mut done = session::Completion::new();
                    session
                        .with_app(
                            &mut done,
                            Retry {
                                client,
                                server,
                                wrong,
                                right,
                                auth,
                                seen: Rc::clone(&seen),
                                stop: Some(stop),
                            },
                            |app| app.run_for(TIMEOUT).map(|_| ()),
                        )
                        .expect("embedded teardown")
                        .expect("embedded execution");
                    let record = seen.borrow_mut().take().expect("one attempted relay");
                    record.opened.expect("initial connection admission");
                    for result in [record.first, record.again] {
                        assert!(
                            matches!(result, Err(embedded::Error::WrongPeer { actual, expected })
                            if actual == address(8) && expected == address(9))
                        );
                    }
                    assert!(matches!(record.sent, Ok(1)));
                    assert!(matches!(record.empty, Ok(0)));
                    assert_eq!(record.count, 1);
                    assert!(!record.failed);
                    assert!(record.stopped.is_ok());
                },
                Policy::new(
                    |event| reports.push(event),
                    |error: Recovery<'_, '_>| -> Infallible {
                        panic!("native recovery: {:?}", error.cause())
                    },
                ),
            );
            assert!(
                result.is_ok(),
                "{:?}",
                result.as_ref().err().map(|e| e.cause())
            );
            result.ok().expect("domain completion")
        });
    assert!(
        matches!(reports.as_slice(), [] | [Reclaimed::Shutdown]),
        "{reports:?}"
    );
}
