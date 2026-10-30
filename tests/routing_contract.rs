use dope_quic::runtime::routing::{
    CONNECTION_ID_LEN, Count, ENTROPY_LEN, LocalRoute, PeerRoute, Plain, Shard,
};

#[test]
fn cid_shape() {
    let entropy = [0xA5; ENTROPY_LEN];
    let plain = <Plain as PeerRoute>::issue(Plain, entropy);
    assert_eq!(plain.as_slice(), &entropy);
    assert!(<Plain as PeerRoute>::matches(Plain, &plain));

    let shard = Shard::from_index(37);
    let routed = <Shard as PeerRoute>::issue(shard, entropy);
    assert_eq!(routed.len(), CONNECTION_ID_LEN);
    assert_eq!(routed.as_slice()[0], shard.index());
    assert_eq!(&routed.as_slice()[1..], &entropy);
    assert!(<Shard as PeerRoute>::matches(shard, &routed));
    assert!(!<Shard as PeerRoute>::matches(
        Shard::from_index(38),
        &routed,
    ));
    assert!(!<Plain as PeerRoute>::matches(Plain, &routed));
}

#[test]
fn projection_domain() {
    let entropy = [0x3C; ENTROPY_LEN];
    let plain = <Plain as LocalRoute>::issue(&Plain, entropy);
    assert_eq!(plain.as_slice(), &entropy);

    let shard = Shard::from_index(255);
    assert!(<Shard as PeerRoute>::from_shard(shard) == Some(shard));
    assert!(<Plain as PeerRoute>::from_shard(Shard::from_index(0)) == Some(Plain));
    assert!(<Plain as PeerRoute>::from_shard(Shard::from_index(1)).is_none());

    let shards = Count::try_from(4).expect("four shards are inside the routing domain");
    assert_eq!(shards.dense_len(3), Some(12));
    for index in 0..12 {
        let (shard, path) = shards
            .resolve(3, index)
            .expect("the index is inside the declared dense topology");
        assert_eq!(shards.index(3, shard, path), Some(index));
    }
    assert!(shards.resolve(3, 12).is_none());
    assert_eq!(shards.index(3, Shard::from_index(4), 0), None);

    let shards = Count::try_from(256).expect("all byte-valued shards are inside the domain");
    assert!(shards.resolve(1, 255) == Some((Shard::from_index(255), 0)));
    assert!(shards.resolve(1, 256).is_none());
}
