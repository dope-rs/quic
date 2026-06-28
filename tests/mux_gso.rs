use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dope_quic::mux::Outgoing;
use dope_quic::{Conn, ConnHandle, Handler, Mux, StreamEvent, transport_params};
use shin::sig::SigningKey;

const CID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

#[derive(Default)]
struct Events {
    established: Vec<ConnHandle>,
    streams: Vec<(ConnHandle, StreamEvent)>,
}

#[derive(Clone, Default)]
struct CapturingHandler {
    events: Rc<RefCell<Events>>,
}

impl Handler for CapturingHandler {
    fn on_established(&mut self, _conn: &mut Conn, h: ConnHandle) {
        self.events.borrow_mut().established.push(h);
    }
    fn on_stream_event(&mut self, _conn: &mut Conn, h: ConnHandle, event: StreamEvent) {
        self.events.borrow_mut().streams.push((h, event));
    }
}

/// Delivers a burst to `dst`, expanding every GSO send back into its segments —
/// exactly what the kernel does on the wire, so reassembly must match a plain
/// per-packet send. Asserts the `UDP_SEGMENT` invariant: equal-size segments
/// with only the trailing one allowed to be shorter.
fn deliver(dst: &mut Mux<CapturingHandler>, src_addr: SocketAddr, burst: Vec<Outgoing>) -> usize {
    let now = Instant::now();
    let mut gso_runs = 0;
    for out in burst {
        match out {
            Outgoing::Plain(_, payload) => {
                dst.on_udp_packet(src_addr, &payload, now).expect("recv");
            }
            Outgoing::Gso(_, payload, seg) => {
                let seg = seg as usize;
                assert!(seg > 0 && payload.len() > seg, "a GSO run holds ≥2 segments");
                assert!(
                    payload.len() % seg == 0 || payload.chunks(seg).next_back().unwrap().len() < seg,
                    "only the trailing segment may be shorter than seg"
                );
                gso_runs += 1;
                for pkt in payload.chunks(seg) {
                    dst.on_udp_packet(src_addr, pkt, now).expect("recv");
                }
            }
        }
    }
    gso_runs
}

#[test]
fn gso_burst_reassembles_to_full_stream() {
    let signing = SigningKey::from_seed(&[7u8; 32]).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();

    let tp = transport_params::Params {
        max_idle_timeout_ms: 30_000,
        initial_max_data: 1 << 20,
        initial_max_stream_data_uni: 1 << 20,
        initial_max_streams_uni: 8,
        ..transport_params::Params::default()
    };

    let server_handler = CapturingHandler::default();
    let server_events = server_handler.events.clone();
    let mut server = Mux::server(server_handler, signing, tp.clone().into());
    server.set_gso(true);

    let client_handler = CapturingHandler::default();
    let client_events = client_handler.events.clone();
    let mut client = Mux::client(client_handler);

    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();

    let mut now = Instant::now();
    let client_handle = client.connect(server_addr, server_pubkey, tp.into(), CID.to_vec(), now);
    deliver(&mut server, client_addr, client.pull_outgoing());
    deliver(&mut client, server_addr, server.pull_outgoing());
    deliver(&mut server, client_addr, client.pull_outgoing());

    let server_handle = server_events.borrow().established[0];

    let body: Vec<u8> = (0..8192u32).map(|i| (i * 31) as u8).collect();
    let stream_id = {
        let conn = server.conn_mut(server_handle).expect("server conn");
        let sid = conn.open_uni_stream().expect("uni stream");
        conn.stream_send(sid, &body);
        conn.stream_send_fin(sid);
        sid
    };

    let mut gso_runs = 0;
    for _ in 0..16 {
        now += Duration::from_millis(20);
        server.flush(server_handle, now);
        gso_runs += deliver(&mut client, server_addr, server.pull_outgoing());
        client.flush(client_handle, now);
        deliver(&mut server, client_addr, client.pull_outgoing());
        if client
            .conn_mut(client_handle)
            .is_some_and(|c| c.stream_recv_eof(stream_id))
        {
            break;
        }
    }

    assert!(gso_runs >= 1, "the paced 8 KiB blast coalesces ≥1 GSO run");
    assert!(
        client_events
            .borrow()
            .streams
            .contains(&(client_handle, StreamEvent::Data { stream_id })),
        "client saw stream data"
    );

    let mut recv = Vec::new();
    let conn = client.conn_mut(client_handle).expect("client conn");
    conn.stream_recv(stream_id, &mut recv);
    assert_eq!(recv, body, "GSO-coalesced burst reassembles byte-exact");
    assert!(conn.stream_recv_eof(stream_id), "fin delivered");
}
