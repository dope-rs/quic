use std::net::SocketAddr;
use std::time::Instant;

use dope_quic::conn;
use dope_quic::mux::{Handler, Mux};
use dope_quic::packet::{InitialHeader, QUIC_V1};
use dope_quic::transport_params;
use shin::crypto::sig::SigningKey;

#[derive(Default)]
struct NoopHandler;
impl Handler<0> for NoopHandler {
    type Connection = ();

    fn create_connection(
        &mut self,
        _conn: &mut dope_quic::conn::session::Connection,
        _handle: dope_quic::conn::Handle,
    ) {
    }
}

fn make_initial(dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let body = vec![0u8; 120];
    let h = InitialHeader {
        version: QUIC_V1,
        dcid: dcid.to_vec(),
        scid: scid.to_vec(),
        token: vec![],
        packet_number: 0,
        pn_len: 4,
    };
    let (mut wire, _pn_offset) = h.encode_with_pn(body.len()).unwrap();
    wire.extend_from_slice(&body);
    wire
}

fn server_mux() -> Mux<NoopHandler> {
    let signing = SigningKey::from_seed(&[0x11u8; 32]).unwrap();
    let cfg: conn::config::Options = transport_params::Params::default().into();
    dope_quic::mux::setup::Server::accept(NoopHandler, signing, cfg).unwrap()
}

#[test]
fn fragmented_initials_with_same_dcid_route_to_one_conn() {
    let mut mux = server_mux();
    let from: SocketAddr = "127.0.0.1:55555".parse().unwrap();
    let now = Instant::now();

    let dcid = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];
    let scid = [0xaa, 0xbb, 0xcc, 0xdd];

    let _ = mux
        .protocol()
        .recv(from, &mut make_initial(&dcid, &scid), now);
    assert_eq!(mux.active_conns(), 1, "first Initial opens one connection");

    let _ = mux
        .protocol()
        .recv(from, &mut make_initial(&dcid, &scid), now);
    assert_eq!(
        mux.active_conns(),
        1,
        "second Initial with the same client DCID must reuse the connection"
    );
}

#[test]
fn initials_with_distinct_dcids_open_distinct_conns() {
    let mut mux = server_mux();
    let from: SocketAddr = "127.0.0.1:55556".parse().unwrap();
    let now = Instant::now();

    let _ = mux.protocol().recv(
        from,
        &mut make_initial(&[1, 1, 1, 1, 1, 1, 1, 1], &[9, 9]),
        now,
    );
    let _ = mux.protocol().recv(
        from,
        &mut make_initial(&[2, 2, 2, 2, 2, 2, 2, 2], &[9, 9]),
        now,
    );
    assert_eq!(
        mux.active_conns(),
        2,
        "distinct client DCIDs are distinct connections"
    );
}
