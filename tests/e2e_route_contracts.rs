pub mod common;
use crate::common::e2e::life::{
    self,
    contract::{self, Field},
    driver::Driver as _,
    identity::{BindingEpoch, CidEpoch, Generation, PathEpoch, RouteId, TransportId},
    state::{Binding, Connection, Delivery, Route},
};
use common::e2e::routes::{Idle, Model, SPECS};
use std::num;

#[test]
fn preserves_route_state() {
    let steps = [
        life::Step::new(
            0,
            life::Action::Probe {
                target: life::Target::Route(RouteId::new(0)),
                sequence: 0,
            },
        ),
        life::Step::new(
            1,
            life::Action::RotateLocalCids {
                target: life::Target::Transport(TransportId::new(0)),
            },
        ),
        life::Step::new(
            2,
            life::Action::RebindTransports {
                target: life::Target::Transport(TransportId::new(1)),
                epoch: BindingEpoch::new(1),
                probe_sequence: 0,
            },
        ),
        life::Step::new(
            3,
            life::Action::CycleConnections {
                target: life::Target::All,
            },
        ),
        life::Step::new(
            4,
            life::Action::Probe {
                target: life::Target::Route(RouteId::new(2)),
                sequence: 1,
            },
        ),
        life::Step::new(
            5,
            life::Action::Drain {
                target: life::Target::All,
            },
        ),
    ];
    let scenario = life::Scenario::new(
        life::Topology::try_new(2, 2, &SPECS).expect("all transports and shards are mapped"),
        &steps,
        num::NonZero::<u16>::new(2).expect("two polls are nonzero"),
    );
    let mut model = Model::default();
    assert!(matches!(
        scenario.replay(&mut model),
        life::Execution::Complete
    ));
    let [r0, r1, r2, r3] =
        [0, 1, 2, 3].map(|id| model.snapshot(RouteId::new(id)).expect("fixture route"));
    assert_eq!(r0.delivery().delivered(), 1);
    assert_eq!(r2.delivery().delivered(), 2);
    assert_eq!(r0.connection().client().get(), 1);
    assert_eq!(r3.connection().server().get(), 1);
    assert_eq!(r0.cid().get(), 1);
    assert_eq!(r2.cid().get(), 0);
    assert_eq!(r1.binding().path().get(), 0);
    assert_eq!(r3.binding().path().get(), 1);
}

#[test]
fn rejects_unsent_delivery() {
    let mut model = Model::default();
    model.routes[0] = Route::new(
        SPECS[0],
        Binding::new(BindingEpoch::INITIAL, PathEpoch::INITIAL),
        Connection::new(
            Generation::INITIAL,
            Generation::INITIAL,
            life::Witness::from([0, 0]),
        ),
        CidEpoch::INITIAL,
        Delivery::new(0, 1, true),
    );
    let scenario = life::Scenario::new(
        life::Topology::try_new(2, 2, &SPECS).expect("all transports and shards are mapped"),
        &[],
        num::NonZero::<u16>::MIN,
    );
    assert!(matches!(
        scenario.replay(&mut model),
        life::Execution::Failed(contract::Error::UnsentDelivery {
            route,
            accepted: 0,
            delivered: 1,
        }) if route == RouteId::new(0)
    ));
}

#[test]
fn rejects_false_receipt() {
    let steps = [life::Step::new(
        0,
        life::Action::RotateLocalCids {
            target: life::Target::Transport(TransportId::new(0)),
        },
    )];
    let scenario = life::Scenario::new(
        life::Topology::try_new(2, 2, &SPECS).expect("all transports and shards are mapped"),
        &steps,
        num::NonZero::<u16>::MIN,
    );
    let mut model = Idle {
        model: Model::default(),
        pending: None,
    };
    assert!(matches!(
        scenario.replay(&mut model),
        life::Execution::Failed(contract::Error::ActionNotApplied { step, route })
            if step == steps[0] && route == RouteId::new(0)
    ));
}

#[test]
fn rejects_probe_count() {
    let steps = [life::Step::new(
        0,
        life::Action::Probe {
            target: life::Target::Route(RouteId::new(0)),
            sequence: 0,
        },
    )];
    let scenario = life::Scenario::new(
        life::Topology::try_new(2, 2, &SPECS).expect("all transports and shards are mapped"),
        &steps,
        num::NonZero::<u16>::MIN,
    );
    let mut model = Idle {
        model: Model::default(),
        pending: None,
    };
    assert!(matches!(
        scenario.replay(&mut model),
        life::Execution::Failed(contract::Error::ProbeCount {
            step,
            route,
            before: 0,
            after: 0,
        }) if step == steps[0] && route == RouteId::new(0)
    ));
}

#[test]
fn rejects_step_ordinal() {
    let steps = [life::Step::new(
        1,
        life::Action::Probe {
            target: life::Target::Route(RouteId::new(0)),
            sequence: 0,
        },
    )];
    let scenario = life::Scenario::new(
        life::Topology::try_new(2, 2, &SPECS).expect("all transports and shards are mapped"),
        &steps,
        num::NonZero::<u16>::MIN,
    );
    let mut model = Model::default();
    assert!(matches!(
        scenario.replay(&mut model),
        life::Execution::Failed(contract::Error::WrongOrdinal {
            expected: 0,
            observed: 1,
        })
    ));
}

#[test]
fn rejects_foreign_route() {
    let steps = [life::Step::new(
        0,
        life::Action::RotateLocalCids {
            target: life::Target::Transport(TransportId::new(0)),
        },
    )];
    let scenario = life::Scenario::new(
        life::Topology::try_new(2, 2, &SPECS).expect("all transports and shards are mapped"),
        &steps,
        num::NonZero::<u16>::new(2).expect("two polls are nonzero"),
    );
    let mut model = Model::leaky();
    assert!(matches!(
        scenario.replay(&mut model),
        life::Execution::Failed(contract::Error::UnexpectedMutation {
            step,
            route,
            field: Field::CidEpoch,
        }) if step == steps[0] && route == RouteId::new(2)
    ));
}
