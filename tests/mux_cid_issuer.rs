pub mod common;
use common::suite::mux::Ignore;
use common::suite::peers::tls;
use dope_quic::conn::life::options::Options;
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::runtime::mux::builder::Plan;
use dope_quic::runtime::routing::Plain;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Instant;

use dope_quic::runtime::routing::{ENTROPY_LEN, Shard};
use dope_quic::wire::packet;
use long::initial;
use packet::long;

#[test]
fn issues_distinct_entropy() {
    let auth = tls::client([7; 32]).expect("client TLS");
    let mut mux = Builder::client(Ignore)
        .limits(Plan::try_new(3, 16, 64 << 10).expect("CID issuer fixture limits are valid"))
        .build()
        .expect("the fixture plan must construct a client mux");
    let now = Instant::now();
    let routes = [
        (SocketAddr::from(([10, 0, 0, 1], 443)), None),
        (
            SocketAddr::from(([10, 0, 0, 2], 443)),
            Some(Shard::from_index(37)),
        ),
        (SocketAddr::from(([10, 0, 0, 3], 443)), None),
    ];
    let mut issued = HashSet::<[u8; ENTROPY_LEN]>::new();

    for (addr, route) in routes {
        let handle = Pin::new(&mut mux)
            .observe(now, |mut turn| match route {
                Some(route) => turn
                    .protocol()
                    .connect_with(addr, &auth, Options::default(), route),
                None => turn
                    .protocol()
                    .connect_with(addr, &auth, Options::default(), Plain),
            })
            .expect("each distinct fixture peer must open a mux connection");
        let original = Pin::new(&mut mux)
            .observe(now, |mut turn| {
                turn.output()
                    .drive()
                    .expect("fresh client connection must admit its Initial");
                for mut outgoing in turn.output().drain() {
                    for segment in outgoing.segments_mut() {
                        if let Ok(header) = initial::Prefix::decode(segment) {
                            return Some(header.dcid.into_slice().to_vec());
                        }
                    }
                }
                None
            })
            .expect("client must emit an Initial packet");
        let path = mux
            .conn(handle)
            .expect("the newly opened handle must resolve to its mux connection")
            .view()
            .path();
        let entropy = match route {
            Some(route) => {
                assert_eq!(original.len(), ENTROPY_LEN + 1);
                assert_eq!(original[0], route.index());
                &original[1..]
            }
            None => {
                assert_eq!(original.len(), ENTROPY_LEN);
                original.as_slice()
            }
        };
        assert!(issued.insert(entropy.try_into().expect("eight bytes of peer CID entropy")));

        let local = path
            .local_cids()
            .values()
            .next()
            .expect("every live fixture path must own a local connection ID");
        assert_eq!(local.len(), ENTROPY_LEN);
        assert!(issued.insert(local.try_into().expect("eight bytes of local CID entropy")));
    }

    assert_eq!(issued.len(), routes.len() * 2);
}
