pub mod common;

use common::suite::peers::packet::params;
use dope_quic::conn::life::options;
use dope_quic::proto::param;
use dope_quic::wire::{packet, varint};
use dope_test::alloc::Tracker;
use o3::depot::array::sorted;
use packet::cid;

#[global_allocator]
static ALLOCATOR: Tracker = Tracker::new();

#[test]
fn decode_has_no_alloc() {
    let expected = param::Set::builder().datagram(Some(65_527)).try_build();
    let expected = (expected).expect("fixture transport parameters");
    let initial = cid::Id::try_from(&[0x11; 20][..]).expect("maximum-length CID");
    let original = cid::Id::try_from(&[0x22; 20][..]).expect("maximum-length CID");
    let retry = cid::Id::try_from(&[0x33; 20][..]).expect("maximum-length CID");
    let token = [0x44; 16];
    let mut wire = Vec::with_capacity(param::Codec::MAX_ENCODED_LEN);
    expected
        .bind_server(&initial, &original, Some(&retry), Some(&token))
        .encode(&mut wire)
        .expect("encode parameters");

    let span = Tracker::begin();
    let decoded = param::Codec::decode(&wire);
    let activity = span.finish();

    let decoded = decoded.expect("valid parameters");
    assert_eq!(decoded.flow().datagram(), Some(65_527));
    assert!(decoded.identity().initial() == Some(&initial));
    assert!(decoded.identity().original() == Some(&original));
    assert!(decoded.identity().retry() == Some(&retry));
    assert_eq!(decoded.identity().reset(), Some(token));
    assert_eq!(activity.allocations, 0);
}

#[test]
fn promote_bind_no_alloc() {
    let local =
        cid::Id::try_from([0x51; 20]).expect("20-byte local CID meets the maximum CID length");
    let original =
        cid::Id::try_from([0x52; 20]).expect("20-byte original CID meets the maximum CID length");
    let retry =
        cid::Id::try_from([0x53; 20]).expect("20-byte retry CID meets the maximum CID length");
    let token = [0x54; 16];
    let mut wire = Vec::with_capacity(param::Codec::MAX_ENCODED_LEN);

    let span = Tracker::begin();
    let params = param::Set::builder()
        .idle_ms(30_000)
        .datagram(Some(65_535))
        .try_build()
        .expect("fixture transport parameters");
    params
        .bind_server(&local, &original, Some(&retry), Some(&token))
        .encode(&mut wire)
        .expect("encode parameters");
    let activity = span.finish();

    assert_eq!(activity.allocations, 0);
}

#[test]
fn options_have_no_alloc() {
    let params = param::Set::default();

    let span = Tracker::begin();
    let options = (options::Options::builder()
        .transport(|path| path.params(params))
        .datagrams(|dgram| dgram.pending(8))
        .try_build())
    .expect("fixture connection options");
    let activity = span.finish();

    assert!(options.params() == &param::Set::default());
    assert_eq!(activity.allocations, 0);
}

#[test]
fn exact_nonreserved_budget() {
    let mut wire = Vec::new();
    let mut id = 1_000;
    for _ in 0..param::Codec::MAX_COUNT {
        while params::is_reserved(id) {
            id += 1;
        }
        params::empty(
            &mut wire,
            varint::VarInt::new(id).expect("bounded parameter ID"),
        )
        .expect("encode empty parameter");
        id += 1;
    }
    assert!(param::Codec::decode(&wire).is_ok());

    while params::is_reserved(id) {
        id += 1;
    }
    params::empty(
        &mut wire,
        varint::VarInt::new(id).expect("bounded parameter ID"),
    )
    .expect("encode empty parameter");
    assert!(
        param::Codec::decode(&wire)
            == Err(param::Error::Id(sorted::Error::Full {
                value: id,
                capacity: param::Codec::MAX_COUNT,
            }))
    );
}

#[test]
fn reserved_keeps_budget() {
    let mut wire = Vec::new();
    for n in 0..=param::Codec::MAX_COUNT {
        params::empty(
            &mut wire,
            varint::VarInt::new(31 * n as u64 + 27).expect("bounded reserved parameter ID"),
        )
        .expect("encode empty parameter");
    }
    assert!(param::Codec::decode(&wire).is_ok());
}

#[test]
fn rejects_duplicate_id() {
    let mut wire = Vec::new();
    params::empty(&mut wire, varint::VarInt::from_u16(1_000)).expect("encode empty parameter");
    params::empty(&mut wire, varint::VarInt::from_u16(1_000)).expect("encode empty parameter");
    assert!(
        param::Codec::decode(&wire)
            == Err(param::Error::Id(sorted::Error::Duplicate {
                value: 1_000,
                existing: 1_000,
            }))
    );
}

#[test]
fn truncated_params_errors() {
    for (wire, actual, required) in [(&[0x40][..], 1, 2), (&[0x1b][..], 0, 1)] {
        assert!(
            param::Codec::decode(wire)
                == Err(param::Error::VarInt(varint::Error::Underflow {
                    actual,
                    required,
                }))
        );
    }
    assert!(
        param::Codec::decode(&[0x1b, 0, 0x20, 2, 0])
            == Err(param::Error::Underflow {
                offset: 4,
                required: 2,
                remaining: 1,
            })
    );
}

#[test]
fn stream_count_bounds() {
    let limit = 1_u64 << 60;
    for (id, counts) in [(0x08, (limit, 0)), (0x09, (0, limit))] {
        let mut wire = [id, 8, 0xd0, 0, 0, 0, 0, 0, 0, 0];
        let decoded = param::Codec::decode(&wire).expect("maximum stream count");
        assert_eq!(
            (decoded.flow().bidi_count(), decoded.flow().uni_count()),
            counts
        );
        wire[9] = 1;
        assert!(
            param::Codec::decode(&wire)
                == Err(param::Error::OutOfRange {
                    id: u64::from(id),
                    value: limit + 1,
                    minimum: 0,
                    maximum: limit,
                })
        );
    }
}

#[test]
fn wire_range_error_order() {
    assert!(
        param::Codec::decode(&[0x0a, 1, 21, 0x03, 2, 0x44, 0xaf])
            == Err(param::Error::OutOfRange {
                id: 0x03,
                value: 1199,
                minimum: 1200,
                maximum: varint::VarInt::MAX,
            })
    );
}

#[test]
fn preferred_address_shape() {
    for cid_len in [1, 20] {
        let value = params::preferred(cid_len);
        let mut wire = Vec::new();
        params::push(
            &mut wire,
            varint::VarInt::from_u8(0x0d),
            &value[..41 + usize::from(cid_len)],
        )
        .expect("preferred address parameter");

        let span = Tracker::begin();
        let result = param::Codec::decode(&wire);
        let activity = span.finish();

        assert!(result.is_ok());
        assert_eq!(activity.allocations, 0);
    }
}

#[test]
fn preferred_address_errors() {
    for (cid_len, length, expected) in [
        (
            8,
            24,
            param::Error::Length {
                id: 0x0d,
                actual: 24,
                minimum: 42,
                maximum: 61,
            },
        ),
        (0, 41, param::Error::PreferredCidLength { actual: 0 }),
        (21, 62, param::Error::PreferredCidLength { actual: 21 }),
        (
            20,
            60,
            param::Error::Length {
                id: 0x0d,
                actual: 60,
                minimum: 61,
                maximum: 61,
            },
        ),
        (
            20,
            62,
            param::Error::Length {
                id: 0x0d,
                actual: 62,
                minimum: 61,
                maximum: 61,
            },
        ),
    ] {
        let value = params::preferred(cid_len);
        let mut wire = Vec::new();
        params::push(&mut wire, varint::VarInt::from_u8(0x0d), &value[..length])
            .expect("preferred address parameter");
        assert!(param::Codec::decode(&wire) == Err(expected));
    }
}
