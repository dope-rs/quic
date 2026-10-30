pub mod common;

use common::suite::mux::install;
use std::{net::SocketAddr, time::Instant};

#[test]
fn same_dcid_reuses_conn() {
    let mut mux = install::alias().expect("install alias");
    let from: SocketAddr = "127.0.0.1:55555"
        .parse()
        .expect("test peer address must be valid");
    let now = Instant::now();

    let dcid = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
    let scid = [0xaa, 0xbb, 0xcc, 0xdd];

    install::alias_admit(&mut mux, from, &dcid, &scid, now).expect("install alias_admit");
    assert_eq!(mux.active_conns(), 1, "first Initial opens one connection");

    install::alias_admit(&mut mux, from, &dcid, &scid, now).expect("install alias_admit");
    assert_eq!(
        mux.active_conns(),
        1,
        "second Initial with the same client DCID must reuse the connection"
    );
}

#[test]
fn dcids_open_conns() {
    let mut mux = install::alias().expect("install alias");
    let from: SocketAddr = "127.0.0.1:55556"
        .parse()
        .expect("test peer address must be valid");
    let now = Instant::now();

    install::alias_admit(&mut mux, from, &[1; 8], &[9, 9], now).expect("install alias_admit");
    install::alias_admit(&mut mux, from, &[2; 8], &[9, 9], now).expect("install alias_admit");
    assert_eq!(
        mux.active_conns(),
        2,
        "distinct client DCIDs are distinct connections"
    );
}
