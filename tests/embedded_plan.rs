use dope::core::driver::life::recovery::{Policy, Recovery};
use std::convert::Infallible;
pub mod common;
use common::runtime::embedded::{Links, address, config, driver, link};
use dope::core::driver::life::creation::Attempt;
use dope::core::driver::{route, settings, storage};
use dope::core::io::Reclaimed;
use dope::runtime::executor::session;
use dope::runtime::{executor::Executor, shutdown};
use dope_quic::runtime::embedded::{self, client, link::Link, plan};
use dope_test::alloc::Tracker;
use dope_test::harness::scenario::TIMEOUT;
use settings::claim::Needs;
use std::{cell::Cell, mem, num::NonZero, rc::Rc};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn plan_owns_boundaries() {
    let (plan, allocs) = Tracker::count(|| plan::Plan::try_new(config()));
    let plan = (plan).expect("valid embedded plan");
    assert_eq!(allocs, 0);
    let client = client::Plan::<7>::new(plan);
    let link = plan.link::<9, 7, 8>(address(7), address(8));
    let needs = Needs::from_tree(&client).expect("client resources form valid requirements");
    assert!(matches!(
        needs.include(settings::claim::Claim::new(
            settings::Routes::singleton::<route::KeyTag<7>>()
        )),
        Err(settings::errors::Claim::DuplicateRoute(id)) if id == route::Id::fixed::<7>()
    ));
    assert_eq!(
        link.capacity(),
        std::num::NonZero::new(3).expect("nonzero link capacity")
    );
    assert_eq!(link.flight_limit(), 2048);
    assert_eq!(link.local(), address(7));
    assert_eq!(link.peer(), address(8));
    let cfg = needs
        .apply_to(settings::Config::default())
        .expect("client requirements fit the default driver config");
    assert!(cfg.domains() == settings::Domain::ZERO);
    assert!(driver(&link).expect("link claims").domains() == settings::Domain::ONE);
}

#[test]
fn separates_allocation() {
    let mut reports = Vec::new();

    let plan = link::<11>().expect("link plan");
    let (arena, allocs) = Tracker::count(|| plan.try_arena().expect("prepare exact arena"));
    assert_eq!(allocs, 1);
    let mut create = Attempt::new();
    let built = Executor::new(&mut create, driver(&plan).expect("link claims"));
    assert!(
        built.is_ok(),
        "{:?}",
        built.as_ref().err().map(|error| error.kind())
    );
    built
        .ok()
        .expect("executor")
        .with_plan(storage::Scope::new(arena))
        .run(|executor| {
            let result = executor.scope(
                |mut session| {
                    let root = *session.storage();
                    let mut driver = session.driver();
                    let (link, allocs) = Tracker::count(|| {
                        Link::try_new(root, &mut driver).expect("validated link plan binds")
                    });
                    assert_eq!(allocs, 0);
                    assert_eq!(
                        mem::size_of::<embedded::link::Control<'static, 'static, 11, 7, 8>>(),
                        mem::size_of::<usize>()
                    );
                    assert_eq!(
                        link.capacity(),
                        std::num::NonZero::new(3).expect("nonzero link capacity")
                    );
                    assert_eq!(link.flight_limit(), 2048);
                    assert_eq!(link.local(), address(7));
                    assert_eq!(link.peer(), address(8));
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

    assert!(
        reports.is_empty(),
        "unexpected embedded completion: {reports:?}"
    );
}

#[test]
fn dispatcher_owns_links() {
    let mut reports = Vec::new();
    let fired = Rc::new(Cell::new(Vec::new()));

    let plan = plan::Plan::try_new(config()).expect("valid embedded plan");
    let forward = plan.link::<21, 7, 8>(address(7), address(8));
    let reverse = plan.link::<22, 8, 7>(address(8), address(7));
    let cfg = Needs::from_tree(&(&forward, &reverse))
        .expect("both link resources form valid requirements")
        .apply_to(settings::Config::default())
        .expect("both link requirements fit the default driver config");
    let (source, trigger) = shutdown::Pair::new()
        .expect("shutdown pair is available")
        .split();
    let mut create = Attempt::new();
    let built = Executor::new(&mut create, cfg);
    assert!(
        built.is_ok(),
        "{:?}",
        built.as_ref().err().map(|error| error.kind())
    );
    built
        .ok()
        .expect("executor")
        .shutdown(source)
        .expect("executor accepts the shutdown source")
        .with_plan(storage::Scope::new((
            forward.try_arena().expect("prepare forward arena"),
            reverse.try_arena().expect("prepare reverse arena"),
        )))
        .run(|executor| {
            let result = executor.scope(
                |mut session| {
                    let (forward, reverse) = *session.storage();
                    let (forward, reverse) = {
                        let mut driver = session.driver();
                        (
                            Link::try_new(forward, &mut driver).expect("forward link plan binds"),
                            Link::try_new(reverse, &mut driver).expect("reverse link plan binds"),
                        )
                    };
                    let mut report = session::Completion::new();
                    session
                        .with_app(
                            &mut report,
                            Links {
                                forward,
                                reverse,
                                trigger: Some(trigger),
                                fired: Rc::clone(&fired),
                            },
                            |app| app.run_for(TIMEOUT).map(|_| ()),
                        )
                        .expect("embedded link teardown")
                        .expect("embedded link runtime");
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

    assert!(matches!(fired.take().as_slice(), [Ok(())]));
    assert!(
        matches!(reports.as_slice(), [] | [Reclaimed::Shutdown]),
        "unexpected embedded completion: {reports:?}"
    );
}

#[test]
fn alloc_failure_preserves() {
    let plan = link::<12>().expect("link plan");
    let result = Tracker::fail_after(0, || plan.try_arena());
    assert!(matches!(result, Err(o3::alloc::Error::Exhausted)));
    let arena = plan
        .try_arena()
        .expect("failed allocation leaves the plan reusable");
    assert_eq!(arena.capacity(), plan.capacity());
}

#[test]
fn ready_failure_reclaims() {
    let mut reports = Vec::new();

    let plan = link::<13>().expect("link plan");
    let cfg = driver(&plan)
        .expect("link claims")
        .set_schedule(settings::Schedule::fixed::<0, 0>());
    let mut create = Attempt::new();
    let built = Executor::new(&mut create, cfg);
    assert!(
        built.is_ok(),
        "{:?}",
        built.as_ref().err().map(|error| error.kind())
    );
    built
        .ok()
        .expect("executor")
        .with_plan(storage::Scope::new(
            plan.try_arena().expect("prepare arena"),
        ))
        .run(|executor| {
            let result = executor.scope(
                |mut session| {
                    let root = *session.storage();
                    let mut driver = session.driver();
                    for _ in 0..2 {
                        let (result, activity) =
                            Tracker::activity(|| Link::try_new(root, &mut driver));
                        assert!(matches!(result, Err(embedded::link::bind::Error::Ready(_))));
                        assert_eq!(activity.allocations, 0);
                        assert_eq!(activity.deallocations, 0);
                    }
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

    assert!(
        reports.is_empty(),
        "unexpected embedded completion: {reports:?}"
    );
}

#[test]
fn resident_fail_reclaims() {
    let mut reports = Vec::new();

    let plan = link::<14>().expect("link plan");
    let cfg = driver(&plan)
        .expect("link claims")
        .with_domains(settings::Domain::ZERO)
        .set_schedule(settings::Schedule::fixed::<1, 0>());
    let mut create = Attempt::new();
    let built = Executor::new(&mut create, cfg);
    assert!(
        built.is_ok(),
        "{:?}",
        built.as_ref().err().map(|error| error.kind())
    );
    built
        .ok()
        .expect("executor")
        .with_plan(storage::Scope::new(
            plan.try_arena().expect("prepare arena"),
        ))
        .run(|executor| {
            let result = executor.scope(
                |mut session| {
                    let root = *session.storage();
                    let mut driver = session.driver();
                    for _ in 0..2 {
                        let (result, activity) =
                            Tracker::activity(|| Link::try_new(root, &mut driver));
                        assert!(matches!(
                            result,
                            Err(embedded::link::bind::Error::Resident(_))
                        ));
                        assert_eq!(activity.allocations, 0);
                        assert_eq!(activity.deallocations, 0);
                    }
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

    assert!(
        reports.is_empty(),
        "unexpected embedded completion: {reports:?}"
    );
}

#[test]
fn invalid_plan_is_inert() {
    let base = config();
    for (config, expected) in [
        (
            embedded::Config {
                link_capacity: 0,
                ..base
            },
            plan::Error::LinkCapacity {
                actual: 0,
                maximum: u32::MAX as usize,
            },
        ),
        (
            embedded::Config {
                link_capacity: 1,
                ..base
            },
            plan::Error::LinkRange {
                actual: NonZero::<u32>::MIN,
                minimum: 2,
                maximum: 32,
            },
        ),
        (
            embedded::Config {
                link_capacity: base.outgoing_capacity + 1,
                ..base
            },
            plan::Error::LinkRange {
                actual: NonZero::new(33).expect("nonzero link capacity"),
                minimum: 2,
                maximum: 32,
            },
        ),
        (
            embedded::Config {
                max_flight_resident_bytes: 0,
                ..base
            },
            plan::Error::Flight { actual: 0 },
        ),
    ] {
        let (result, allocs) = Tracker::count(|| plan::Plan::try_new(config));
        assert_eq!(allocs, 0);
        assert_eq!(result.err(), Some(expected));
    }
}
