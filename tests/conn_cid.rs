pub mod common;
use crate::common::e2e::life::{self, driver::Driver, identity::RouteId};
use common::suite::cid::contract::{ROUTES, Wire};
use dope_quic::proto::cid::Schedule;
use dope_quic::runtime::mux::protocol::rotation::Batch;
use std::{
    mem::{needs_drop, size_of},
    num::NonZero,
};
#[test]
fn replays_lifecycle() {
    assert_eq!(size_of::<Batch>(), 2 * size_of::<usize>());
    assert!(!needs_drop::<Batch>());
    assert!(size_of::<Schedule>() <= 4 * size_of::<usize>());
    assert!(!needs_drop::<Schedule>());
    let topology = life::Topology::try_new(1, 1, &ROUTES)
        .expect("the fixture maps its sole transport and shard");
    let scenario =
        life::Scenario::new(topology, &life::CANONICAL_ACTIVE_STEPS, NonZero::<u16>::MIN);
    let mut driver = Wire::new().expect("the fixed lifecycle fixture must construct");
    let result = scenario.replay(&mut driver);
    assert!(
        matches!(result, life::Execution::Complete),
        "the canonical lifecycle trace must complete"
    );
    let delivery = driver
        .snapshot(RouteId::new(0))
        .expect("known route")
        .delivery();
    assert_eq!(delivery.accepted(), 4);
    assert_eq!(delivery.delivered(), 4);
    assert!(delivery.is_live());
    assert_eq!(driver.counts(), (1, 1));
}
