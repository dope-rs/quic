use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dope_quic::conn::{Handle, stream::Event};
use dope_quic::mux::Outgoing;
use dope_quic::{Handler, Mux, conn::session::Connection, transport_params};
use shin::crypto::sig::SigningKey;

const CID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

#[derive(Default)]
struct Events {
    established: Vec<Handle>,
    streams: Vec<(Handle, Event)>,
}

#[derive(Clone, Default)]
struct CapturingHandler {
    events: Rc<RefCell<Events>>,
}

impl Handler<0> for CapturingHandler {
    type Connection = ();

    fn create_connection(&mut self, _conn: &mut Connection, _handle: Handle) {}

    fn established(&mut self, _connection: &mut (), _conn: &mut Connection, h: Handle) {
        self.events.borrow_mut().established.push(h);
    }
    fn stream_event(
        &mut self,
        _connection: &mut (),
        _conn: &mut Connection,
        h: Handle,
        event: Event,
    ) {
        self.events.borrow_mut().streams.push((h, event));
    }
}

fn deliver(dst: &mut Mux<CapturingHandler>, src_addr: SocketAddr, burst: Vec<Outgoing>) -> usize {
    let now = Instant::now();
    let mut gso_runs = 0;
    for out in burst {
        match out {
            Outgoing::Plain(_, mut payload) => {
                dst.protocol()
                    .recv(src_addr, &mut payload, now)
                    .expect("recv");
            }
            Outgoing::Suffix(_, mut payload) => {
                dst.protocol()
                    .recv(src_addr, payload.as_mut_slice(), now)
                    .expect("recv");
            }
            Outgoing::Batch(_, mut payload, segment_size) => {
                for segment in payload.chunks_mut(usize::from(segment_size.get())) {
                    dst.protocol().recv(src_addr, segment, now).unwrap();
                }
                gso_runs += 1;
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
    let mut server = dope_quic::mux::setup::Server::with_outgoing_capacity(
        server_handler,
        signing,
        tp.clone().into(),
        64,
    )
    .unwrap();
    server.configuration().enable_gso().unwrap();

    let client_handler = CapturingHandler::default();
    let client_events = client_handler.events.clone();
    let mut client = dope_quic::mux::setup::Client::new(client_handler)
        .build()
        .unwrap();

    let server_addr: SocketAddr = "10.0.0.2:443".parse().unwrap();
    let client_addr: SocketAddr = "10.0.0.1:50000".parse().unwrap();

    let mut now = Instant::now();
    let client_handle = client
        .protocol()
        .connect(server_addr, server_pubkey, tp.into(), CID.to_vec(), now)
        .unwrap();
    deliver(&mut server, client_addr, client.output().drain().collect());
    deliver(&mut client, server_addr, server.output().drain().collect());
    deliver(&mut server, client_addr, client.output().drain().collect());
    server.output().drive_bounded(now);
    client.output().drive_bounded(now);

    let server_handle = server_events.borrow().established[0];

    let body: Vec<u8> = (0..8192u32).map(|i| (i * 31) as u8).collect();
    let stream_id = {
        let mut conn = server
            .protocol()
            .conn_mut(server_handle)
            .expect("server conn");
        let sid = conn.streams().open_uni().expect("uni stream");
        conn.streams().send(sid, &body).unwrap();
        conn.streams().finish(sid).unwrap();
        sid
    };

    let mut gso_runs = 0;
    for _ in 0..16 {
        now += Duration::from_millis(20);
        server.protocol().flush(server_handle, now);
        assert!(server.output().len() <= server.output().capacity());
        assert!(server.output().bytes() <= server.output().bytes_capacity());
        gso_runs += deliver(&mut client, server_addr, server.output().drain().collect());
        client.protocol().flush(client_handle, now);
        deliver(&mut server, client_addr, client.output().drain().collect());
        if client
            .protocol()
            .conn_mut(client_handle)
            .is_some_and(|c| c.stream_state().recv_eof(stream_id))
        {
            break;
        }
    }

    assert!(gso_runs >= 1, "the paced 8 KiB blast coalesces ≥1 GSO run");
    assert!(
        client_events
            .borrow()
            .streams
            .contains(&(client_handle, Event::Readable { stream_id })),
        "client saw stream data"
    );

    let mut recv = Vec::new();
    let mut conn = client
        .protocol()
        .conn_mut(client_handle)
        .expect("client conn");
    conn.streams().recv(stream_id, &mut recv);
    assert_eq!(recv, body, "GSO-coalesced burst reassembles byte-exact");
    assert!(conn.stream_state().recv_eof(stream_id), "fin delivered");
}
