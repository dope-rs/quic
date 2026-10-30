use std::num::NonZero;

use dope_quic::proto::param;

#[test]
fn oversized_keeps_failures() {
    for id in [0x00, 0x0f, 0x10] {
        let mut wire = [0; 23];
        wire[0] = id;
        wire[1] = 21;
        let result = param::Codec::decode(&wire);
        assert!(
            matches!(result, Err(param::Error::Cid { id: actual, cause })
            if actual == u64::from(id)
                && cause.into_parts() == (NonZero::<usize>::MIN.saturating_add(20), 20))
        );
    }
}
