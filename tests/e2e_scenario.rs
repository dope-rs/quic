use dope_test::quic::{Datagram, Lane, Observation, Oracle, Violation};

#[test]
fn delivers_once() {
    let scenario = Datagram::try_new(2, 3, 32).expect("the scenario dimensions are valid");
    let mut oracle = Oracle::new(scenario);
    for flow in 0..2 {
        for sequence in 0..3 {
            assert!(matches!(
                oracle.observe(
                    &scenario
                        .try_payload(flow, sequence)
                        .expect("each enumerated identity must encode"),
                ),
                Ok(Observation {
                    flow: actual_flow,
                    sequence: actual_sequence,
                }) if actual_flow == flow && actual_sequence == sequence
            ));
        }
    }
    assert_eq!(oracle.delivered(), scenario.total());
    assert!(matches!(
        oracle.observe(
            &scenario
                .try_payload(0, 0)
                .expect("the first scenario identity must encode"),
        ),
        Err(Violation::Duplicate {
            flow: 0,
            sequence: 0,
        })
    ));
    let done = oracle
        .finish()
        .expect("every scenario identity was delivered");
    assert_eq!(done.delivered(), scenario.total());
    assert_eq!(done.bytes(), scenario.total() * 32);
    assert!(!Lane::Plain.is_gso());
    assert!(Lane::Gso.is_gso());
}
