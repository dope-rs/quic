use dope_quic::runtime::routing::{CONNECTION_ID_LEN, Count, ENTROPY_LEN, Shard};

#[test]
fn width_preserves_entropy() {
    assert_eq!(ENTROPY_LEN, 8);
    assert_eq!(CONNECTION_ID_LEN, ENTROPY_LEN + 1);
}

#[test]
fn count_is_bounded() {
    assert!(matches!(Count::try_from(0), Err(error) if error.actual() == 0));
    assert!(Count::try_from(1).expect("one shard is the minimum") == Count::MIN);
    let maximum = Count::try_from(256).expect("256 shards fit one routing byte");
    assert!(maximum.resolve(1, 255) == Some((Shard::from_index(255), 0)));
    assert!(maximum.resolve(1, 256).is_none());
    assert!(matches!(Count::try_from(257), Err(error) if error.actual() == 257));
}
