use std::mem::size_of;

use dope_quic::wire::{
    Mark, Packed,
    stream::Id,
    varint::{Error, VarInt},
};
use o3::base::num::bounded;
use o3::buffer::write;

#[test]
fn caches_wire_width() {
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
        let value = VarInt::new(raw).expect("bounded value must be accepted");
        assert_eq!(value.get(), raw);
        assert_eq!(value.encoded_len(), width);
    }
    assert!(VarInt::new(VarInt::MAX + 1).is_none());
    for raw in [0, 63, 64, u8::MAX] {
        assert!(Some(VarInt::from_u8(raw)) == VarInt::new(u64::from(raw)));
    }
}

#[test]
fn encodes_stream_count() {
    const MAX: u64 = 1 << 60;
    assert_eq!(size_of::<bounded::U64<0, MAX>>(), size_of::<VarInt>());
    assert!(bounded::U64::<0, MAX>::new(MAX + 1).is_none());
    for raw in [0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824, MAX] {
        let count = bounded::U64::<0, MAX>::new(raw).expect("stream count fits its bound");
        let value = VarInt::from(count);
        assert_eq!(value.get(), raw);
        let mut wire = Vec::new();
        value.encode(&mut wire).expect("wire encoding");
        assert_eq!(wire.len(), usize::from(value.encoded_len()));
        assert!(VarInt::decode(&wire) == Ok((value, wire.len())));
    }
    assert_eq!(
        VarInt::from(bounded::U64::<0, MAX>::clamp(u64::MAX)).get(),
        MAX
    );
}

#[test]
fn canonicalizes_width() {
    for raw in [0, 63, 64, 16_383, 16_384, 1_073_741_823, VarInt::MAX] {
        let expected = VarInt::new(raw).expect("bounded value must be accepted");
        let mut wire = Vec::new();
        expected.encode(&mut wire).expect("wire encoding");
        assert_eq!(wire.len(), usize::from(expected.encoded_len()));
        assert!(VarInt::decode(&wire) == Ok((expected, wire.len())));
    }

    assert!(matches!(
        VarInt::decode(&[0x40]),
        Err(Error::Underflow {
            actual: 1,
            required: 2
        }),
    ));
    assert!(VarInt::decode(&[0x40, 0]) == Ok((VarInt::ZERO, 2)));
    assert_eq!(
        VarInt::decode(&[0x40, 0]).map(|(value, _)| value.encoded_len()),
        Ok(1)
    );
}

#[test]
fn rejects_short_output() {
    let mut bytes = [0xa5; 7];
    let mut output = write::Slice::new(&mut bytes);
    assert!(VarInt::MAX_VALUE.encode(&mut output).is_err());
    assert_eq!(output.finish(), 0);
    assert_eq!(bytes, [0xa5; 7]);
}

#[test]
fn packed_keeps_identity() {
    assert_eq!(size_of::<Option<Packed>>(), size_of::<u64>());
    for raw in [
        0,
        63,
        64,
        16_383,
        16_384,
        1_073_741_823,
        1_073_741_824,
        Id::MAX,
    ] {
        let id = Id::try_from(raw).expect("bounded stream identity must be accepted");
        for mark in [Mark::Clear, Mark::Set] {
            let stored = Packed::new(id, mark);
            assert!(stored.id() == id);
            assert!(stored.mark() == mark);
            assert!(stored.id().kind() == id.kind());
            assert_eq!(stored.id().number(), id.number());
        }
    }
    for value in [Id::MAX + 1, u64::MAX] {
        assert!(Id::try_from(value) == Err(Error::TooLarge { value }));
    }
}

#[test]
fn bounds_packed_wire() {
    for (raw, wire) in [
        (0, &[0][..]),
        (63, &[0x3f][..]),
        (64, &[0x40, 0x40][..]),
        (16_383, &[0x7f, 0xff][..]),
        (16_384, &[0x80, 0, 0x40, 0][..]),
        (1_073_741_823, &[0xbf, 0xff, 0xff, 0xff][..]),
        (1_073_741_824, &[0xc0, 0, 0, 0, 0x40, 0, 0, 0][..]),
        (VarInt::MAX, &[0xff; 8][..]),
    ] {
        let value = VarInt::new(raw).expect("wire vector fits a QUIC integer");
        let packed = value.pack();
        assert_eq!(packed.as_ref(), wire);
        assert!(VarInt::decode(packed.as_ref()) == Ok((value, wire.len())));
    }
}

#[test]
fn retains_rejected_length() {
    for value in [0, 63, 64, 16_383, 16_384, usize::MAX >> 2] {
        let varint = VarInt::try_from(value).expect("bounded payload length fits");
        assert_eq!(varint.get(), value as u64);
    }
    if usize::BITS > 62 {
        let value = usize::MAX;
        let error = VarInt::try_from(value).expect_err("oversized length is rejected");
        assert_eq!(error.value.get(), value);
    }
}
