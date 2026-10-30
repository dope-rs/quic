pub mod common;

use common::suite::peers::packet::{Pair, bytes};
use dope_quic::conn::Epoch;
use std::time::{Duration, Instant};

#[test]
fn recycles_retirements() {
    let mut now = Instant::now();
    let mut certs = Vec::new();
    let pair = Pair::try_new(1, now, |error| certs.push(format!("{error:?}")));
    assert!(certs.is_empty(), "{certs:?}");
    let mut pair = pair.expect("independent peer handshake");

    pair.receive(&bytes::notice(2, 2).expect("CID notice"), now)
        .expect("replace and retire the received initial CID");
    let retired = pair.retired(now).expect("authenticated retirement output");
    assert_eq!(retired, [0]);
    assert_eq!(pair.server.view().recovery().unacked(Epoch::Application), 0);

    now += Duration::from_millis(1);
    pair.receive(&bytes::notice(1, 0).expect("delayed CID notice"), now)
        .expect("a first late CID below the retirement floor is retired");
    assert_eq!(pair.retired(now).expect("delayed CID output"), [1]);

    for sequence in 3..=66 {
        now += Duration::from_millis(1);
        pair.receive(
            &bytes::notice(sequence, sequence).expect("next CID notice"),
            now,
        )
        .expect("fresh CID rotation");
        assert_eq!(
            pair.retired(now).expect("acknowledged rotation"),
            [u64::from(sequence - 1)]
        );
    }
    assert_eq!(pair.server.view().recovery().unacked(Epoch::Application), 0);

    for sequence in 1..=65 {
        now += Duration::from_millis(1);
        pair.receive(
            &bytes::notice(sequence, 0).expect("replayed CID notice"),
            now,
        )
        .expect("an obsolete CID remains retired");
        let retired = pair.retired(now).expect("replayed retirement output");
        assert!(
            retired.is_empty() || retired == [u64::from(sequence)],
            "{retired:?}"
        );
    }

    now += Duration::from_millis(1);
    pair.receive(&bytes::notice(67, 67).expect("fresh CID notice"), now)
        .expect("retirement capacity remains available");
    assert_eq!(pair.retired(now).expect("fresh retirement"), [66]);
    assert!(pair.server.view().lifecycle().is_ready());
}
