use std::mem::size_of;

use dope_quic::varint::{Error, VarInt};

fn value(raw: u64) -> VarInt {
    VarInt::new(raw).expect("test value lies in the QUIC VarInt domain")
}

#[test]
fn nominal_values_cache_the_minimal_wire_width_without_layout_cost() {
    assert_eq!(size_of::<VarInt>(), size_of::<u64>());
    for (raw, width) in [
        (0, 1),
        (63, 1),
        (64, 2),
        (16_383, 2),
        (16_384, 4),
        (1_073_741_823, 4),
        (1_073_741_824, 8),
        (VarInt::MAX, 8),
    ] {
        assert_eq!(value(raw).get(), raw);
        assert_eq!(value(raw).encoded_len(), width);
    }
    assert_eq!(VarInt::new(VarInt::MAX + 1), None);
    for raw in [0, 63, 64, u8::MAX] {
        assert_eq!(VarInt::from_u8(raw), value(u64::from(raw)));
    }
}

#[test]
fn encode_is_infallible_after_construction_and_decode_canonicalizes_width() {
    for raw in [0, 63, 64, 16_383, 16_384, 1_073_741_823, VarInt::MAX] {
        let expected = value(raw);
        let mut wire = Vec::new();
        expected.encode(&mut wire);
        assert_eq!(wire.len(), expected.encoded_len());
        assert_eq!(VarInt::decode(&wire), Ok((expected, wire.len())));
    }

    assert_eq!(VarInt::decode(&[0x40]), Err(Error::Underflow));
    assert_eq!(VarInt::decode(&[0x40, 0]), Ok((VarInt::ZERO, 2)));
    assert_eq!(VarInt::decode(&[0x40, 0]).unwrap().0.encoded_len(), 1);
}
