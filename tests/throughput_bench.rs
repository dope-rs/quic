//! Loopback throughput benches for the QUIC send path (profile without
//! docker/h2load). Requires the `bench` feature for `Conn::bench_prepare_blast`.
//!
//!   cargo test --release --features bench --test throughput_bench -- --ignored --nocapture
//!
//! Env knobs: TP_BODY (response bytes, default 16384), TP_CONC (in-flight
//! streams), TP_SECS (duration), TP_PARK_US (park us), TP_BATCH.
#![cfg(feature = "bench")]

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dope::{Drive, Driver, DriverCfg, DriverConfig};
use dope_quic::{Conn, ConnHandle, Endpoint, Handler, StreamEvent, transport_params};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

const CID: [u8; 8] = [0x42; 8];

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn signing_pair() -> (SigningKey, [u8; 32]) {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let pubkey = *signing.pubkey().unwrap();
    (signing, pubkey)
}

fn bench_tp(max_streams_bidi: u64, max_streams_uni: u64) -> transport_params::Params {
    transport_params::Params {
        max_idle_timeout_ms: 30_000,
        initial_max_data: 1u64 << 34,
        initial_max_stream_data_bidi_local: 1u64 << 30,
        initial_max_stream_data_bidi_remote: 1u64 << 30,
        initial_max_stream_data_uni: 1u64 << 30,
        initial_max_streams_bidi: max_streams_bidi,
        initial_max_streams_uni: max_streams_uni,
        active_connection_id_limit: 4,
        ..Default::default()
    }
}

#[derive(Default)]
struct Events {
    established: Vec<ConnHandle>,
}

#[derive(Clone, Default)]
struct CapturingHandler {
    events: Rc<RefCell<Events>>,
}

impl Handler for CapturingHandler {
    fn on_established(&mut self, _conn: &mut Conn, h: ConnHandle) {
        self.events.borrow_mut().established.push(h);
    }
}

struct ServerHandler {
    body: Rc<Vec<u8>>,
}

impl Handler for ServerHandler {
    fn on_stream_event(&mut self, conn: &mut Conn, _h: ConnHandle, ev: StreamEvent) {
        if let StreamEvent::Finished { stream_id } = ev {
            // bidi client-initiated streams only
            if stream_id & 0x3 == 0 {
                let mut scratch = Vec::new();
                let _ = conn.stream_recv(stream_id, &mut scratch);
                conn.stream_send(stream_id, &self.body);
                conn.stream_send_fin(stream_id);
            }
        }
    }
}

#[derive(Default)]
struct ClientState {
    finished: u64,
}

#[derive(Clone, Default)]
struct ClientHandler {
    state: Rc<RefCell<ClientState>>,
}

impl Handler for ClientHandler {
    fn on_stream_event(&mut self, _conn: &mut Conn, _h: ConnHandle, ev: StreamEvent) {
        if let StreamEvent::Finished { .. } = ev {
            self.state.borrow_mut().finished += 1;
        }
    }
}

// Pure send-path CPU: framing + encryption + bookkeeping, no socket.
#[test]
#[ignore]
fn send_path_cpu() {
    let body_len = env_usize("TP_BODY", 16384);
    let secs = env_usize("TP_SECS", 3) as u64;
    let body = vec![0x61u8; body_len];

    let (signing, server_pubkey) = signing_pair();
    let tp = bench_tp(1_000, 8_000_000);

    let mut server_drv = Driver::new(DriverCfg::for_quic_udp(4096, 2048)).unwrap();
    let srv_handler = CapturingHandler::default();
    let srv_events = srv_handler.events.clone();
    let mut server = std::pin::pin!(
        Endpoint::<0, _>::build_server(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            signing,
            tp.clone(),
            srv_handler,
            &mut server_drv,
        )
        .unwrap()
    );
    let server_addr = server.local_addr();

    let mut client_drv = Driver::new(DriverCfg::for_quic_udp(4096, 2048)).unwrap();
    let mut client = std::pin::pin!(
        Endpoint::<0, _>::build_client(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            CapturingHandler::default(),
            &mut client_drv,
        )
        .unwrap()
    );
    let _ = client
        .as_mut()
        .connect(server_addr, server_pubkey, tp, CID.to_vec());

    let mut ready = false;
    for _ in 0..400 {
        client.as_mut().drive(&mut client_drv);
        let _ = client_drv.park(Duration::from_millis(1));
        server.as_mut().drive(&mut server_drv);
        let _ = server_drv.park(Duration::from_millis(1));
        if !srv_events.borrow().established.is_empty() {
            ready = true;
            break;
        }
    }
    assert!(ready, "handshake did not complete");
    let server_handle = srv_events.borrow().established[0];

    let conn = server
        .as_mut()
        .conn_mut(server_handle)
        .expect("server conn");
    let mut responses: u64 = 0;
    let mut packets: u64 = 0;
    let mut bytes: u64 = 0;
    let start = Instant::now();
    let dur = Duration::from_secs(secs);
    while start.elapsed() < dur {
        for _ in 0..256 {
            conn.bench_prepare_blast();
            let sid = conn.open_uni_stream().expect("uni stream");
            conn.stream_send(sid, &body);
            conn.stream_send_fin(sid);
            let now = Instant::now();
            for pkt in conn.send_packets(now) {
                packets += 1;
                bytes += pkt.len() as u64;
            }
            responses += 1;
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    let rps = responses as f64 / elapsed;
    let mibps = bytes as f64 / elapsed / (1024.0 * 1024.0);
    eprintln!(
        "\nsend_path_cpu: body={}B -> {:.0} resp/s, {:.0} pkt/s, {:.1} MiB/s wire ({} resp)",
        body_len,
        rps,
        packets as f64 / elapsed,
        mibps,
        responses
    );

    let mut batch = dope_quic::conn::PacketBatch::default();
    let mut b_responses: u64 = 0;
    let mut b_packets: u64 = 0;
    let mut b_bytes: u64 = 0;
    let bstart = Instant::now();
    while bstart.elapsed() < dur {
        for _ in 0..256 {
            conn.bench_prepare_blast();
            let sid = conn.open_uni_stream().expect("uni stream");
            conn.stream_send(sid, &body);
            conn.stream_send_fin(sid);
            conn.send_batch(&mut batch, Instant::now());
            b_packets += batch.packets() as u64;
            b_bytes += batch.byte_len() as u64;
            b_responses += 1;
        }
    }
    let b_elapsed = bstart.elapsed().as_secs_f64();
    eprintln!(
        "send_path_build_cpu: body={}B -> {:.0} resp/s, {:.0} pkt/s, {:.1} MiB/s wire ({} resp)",
        body_len,
        b_responses as f64 / b_elapsed,
        b_packets as f64 / b_elapsed,
        b_bytes as f64 / b_elapsed / (1024.0 * 1024.0),
        b_responses
    );
}

// Real-socket one-way blast through the io_uring UDP path: send throughput
// including syscalls.
#[derive(Clone, Default)]
struct DrainHandler {
    rx: Rc<RefCell<u64>>,
    est: Rc<RefCell<Vec<ConnHandle>>>,
}

impl Handler for DrainHandler {
    fn on_established(&mut self, _c: &mut Conn, h: ConnHandle) {
        self.est.borrow_mut().push(h);
    }
    fn on_stream_event(&mut self, conn: &mut Conn, _h: ConnHandle, ev: StreamEvent) {
        if let StreamEvent::Data { stream_id } | StreamEvent::Finished { stream_id } = ev {
            let mut scratch = Vec::new();
            let n = conn.stream_recv(stream_id, &mut scratch);
            *self.rx.borrow_mut() += n as u64;
        }
    }
}

#[test]
#[ignore]
fn send_path_socket() {
    let body_len = env_usize("TP_BODY", 16384);
    let secs = env_usize("TP_SECS", 3) as u64;
    let batch = env_usize("TP_BATCH", 64);
    let body = vec![0x61u8; body_len];

    let (signing, server_pubkey) = signing_pair();
    let tp = bench_tp(1_000, 8_000_000);

    let mut server_drv = Driver::new(DriverCfg::for_quic_udp(8192, 2048)).unwrap();
    let mut server = std::pin::pin!(
        Endpoint::<0, _>::build_server(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            signing,
            tp.clone(),
            DrainHandler::default(),
            &mut server_drv,
        )
        .unwrap()
    );
    let server_addr = server.local_addr();

    let mut client_drv = Driver::new(DriverCfg::for_quic_udp(8192, 2048)).unwrap();
    let cli_handler = DrainHandler::default();
    let rx = cli_handler.rx.clone();
    let mut client = std::pin::pin!(
        Endpoint::<0, _>::build_client(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            cli_handler,
            &mut client_drv,
        )
        .unwrap()
    );
    let client_handle = client
        .as_mut()
        .connect(server_addr, server_pubkey, tp, CID.to_vec());

    let mut server_handle = None;
    for _ in 0..400 {
        client.as_mut().drive(&mut client_drv);
        let _ = client_drv.park(Duration::from_millis(1));
        server.as_mut().drive(&mut server_drv);
        let _ = server_drv.park(Duration::from_millis(1));
        if let Some(h) = server.handler().est.borrow().first().copied() {
            server_handle = Some(h);
            if client
                .as_mut()
                .conn_mut(client_handle)
                .map(|c| c.is_established())
                .unwrap_or(false)
            {
                break;
            }
        }
    }
    let server_handle = server_handle.expect("server established");

    let start = Instant::now();
    let dur = Duration::from_secs(secs);
    let tiny = Duration::from_micros(20);
    while start.elapsed() < dur {
        if let Some(conn) = server.as_mut().conn_mut(server_handle) {
            blast(conn, batch, &body);
        }
        server.as_mut().drive(&mut server_drv);
        let _ = server_drv.park(tiny);
        client.as_mut().drive(&mut client_drv);
        let _ = client_drv.park(tiny);
    }

    let elapsed = start.elapsed().as_secs_f64();
    let got = *rx.borrow();
    eprintln!(
        "\nsend_path_socket: body={}B batch={} -> {:.1} MiB/s recv ({:.0} resp/s eq)",
        body_len,
        batch,
        got as f64 / elapsed / (1024.0 * 1024.0),
        got as f64 / body_len as f64 / elapsed
    );
}

#[test]
#[ignore]
fn quic_request_response_throughput() {
    let body_len = env_usize("TP_BODY", 16384);
    let conc = env_usize("TP_CONC", 64);
    let secs = env_usize("TP_SECS", 2) as u64;
    let park_us = env_usize("TP_PARK_US", 50) as u64;
    let park = Duration::from_micros(park_us);

    let body = Rc::new(vec![0x61u8; body_len]);

    let (signing, server_pubkey) = signing_pair();
    let tp = bench_tp(8_000_000, 16);

    let mut server_drv = Driver::new(DriverCfg::for_quic_udp(4096, 2048)).unwrap();
    let server = ServerHandler { body: body.clone() };
    let mut server = std::pin::pin!(
        Endpoint::<0, _>::build_server(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            signing,
            tp.clone(),
            server,
            &mut server_drv,
        )
        .unwrap()
    );
    let server_addr = server.local_addr();

    let mut client_drv = Driver::new(DriverCfg::for_quic_udp(4096, 2048)).unwrap();
    let client_handler = ClientHandler::default();
    let client_state = client_handler.state.clone();
    let mut client = std::pin::pin!(
        Endpoint::<0, _>::build_client(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            client_handler,
            &mut client_drv,
        )
        .unwrap()
    );

    let client_handle = client
        .as_mut()
        .connect(server_addr, server_pubkey, tp, CID.to_vec());

    // Handshake.
    let mut ready = false;
    for _ in 0..400 {
        client.as_mut().drive(&mut client_drv);
        let _ = client_drv.park(Duration::from_millis(1));
        server.as_mut().drive(&mut server_drv);
        let _ = server_drv.park(Duration::from_millis(1));
        if client
            .as_mut()
            .conn_mut(client_handle)
            .map(|c| c.is_established())
            .unwrap_or(false)
        {
            ready = true;
            break;
        }
    }
    assert!(ready, "handshake did not complete");

    let req = b"GET /static/app.js\r\n";
    let mut opened: u64 = 0;
    let start = Instant::now();
    let dur = Duration::from_secs(secs);

    while start.elapsed() < dur {
        // Refill in-flight streams up to `conc`.
        let finished = client_state.borrow().finished;
        let in_flight = opened - finished;
        if in_flight < conc as u64
            && let Some(conn) = client.as_mut().conn_mut(client_handle)
        {
            for _ in in_flight..conc as u64 {
                let Ok(sid) = conn.open_bidi_stream() else {
                    break;
                };
                conn.stream_send(sid, req);
                conn.stream_send_fin(sid);
                opened += 1;
            }
        }

        client.as_mut().drive(&mut client_drv);
        let _ = client_drv.park(park);
        server.as_mut().drive(&mut server_drv);
        let _ = server_drv.park(park);
    }

    let elapsed = start.elapsed().as_secs_f64();
    let done = client_state.borrow().finished;
    let rps = done as f64 / elapsed;
    let mbps = rps * body_len as f64 / (1024.0 * 1024.0);
    eprintln!(
        "\nthroughput: body={}B conc={} secs={:.2} -> {:.0} resp/s, {:.1} MiB/s ({} done)",
        body_len, conc, elapsed, rps, mbps, done
    );
}

const SERVER_SEED: [u8; 32] = [0x37; 32];

fn pin_core(core: usize) {
    let _ = dope::launcher::Launcher::pin_to_cpu(core as u16);
}

fn tp_2proc() -> transport_params::Params {
    bench_tp(1_000, 8_000_000)
}

fn blast(conn: &mut Conn, batch: usize, body: &[u8]) {
    conn.bench_prepare_blast();
    for _ in 0..batch {
        let Ok(sid) = conn.open_uni_stream() else {
            break;
        };
        conn.stream_send(sid, body);
        conn.stream_send_fin(sid);
    }
}

struct ServerProc(std::process::Child);

impl Drop for ServerProc {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

#[test]
#[ignore]
fn send_path_2proc() {
    if std::env::var("TP_ROLE").as_deref() == Ok("server") {
        run_2proc_server();
    } else {
        run_2proc_client();
    }
}

fn run_2proc_server() {
    pin_core(env_usize("TP_SERVER_CORE", 1));
    let gso = env_usize("TP_GSO", 0) != 0;
    let body_len = env_usize("TP_BODY", 16384);
    let batch = env_usize("TP_BATCH", 64);
    let secs = env_usize("TP_SECS", 3) as u64;
    let body = vec![0x61u8; body_len];

    let signing = SigningKey::from_seed(&SERVER_SEED).unwrap();
    let mut drv = Driver::new(DriverCfg::for_quic_udp(8192, 2048)).unwrap();
    let handler = DrainHandler::default();
    let est = handler.est.clone();
    let mut server = std::pin::pin!(
        Endpoint::<0, _>::build_server(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            signing,
            tp_2proc(),
            handler,
            &mut drv,
        )
        .unwrap()
    );
    server.as_mut().set_gso(gso);
    let port_file = std::env::var("TP_PORT_FILE").unwrap();
    let tmp = format!("{port_file}.tmp");
    std::fs::write(&tmp, server.local_addr().port().to_string()).unwrap();
    std::fs::rename(&tmp, &port_file).unwrap();

    let deadline = Instant::now() + Duration::from_secs(secs + 3);
    let tiny = Duration::from_micros(20);
    while Instant::now() < deadline {
        if let Some(h) = est.borrow().first().copied()
            && let Some(conn) = server.as_mut().conn_mut(h)
        {
            blast(conn, batch, &body);
        }
        server.as_mut().drive(&mut drv);
        let _ = drv.park(tiny);
    }
}

fn run_2proc_client() {
    use std::process::Command;

    pin_core(env_usize("TP_CLIENT_CORE", 0));
    let gso = env_usize("TP_GSO", 0) != 0;
    let body_len = env_usize("TP_BODY", 16384);
    let secs = env_usize("TP_SECS", 3) as u64;

    let port_file = format!(
        "{}/tp_2proc_port_{}",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let _ = std::fs::remove_file(&port_file);
    let exe = std::env::current_exe().unwrap();
    let _child = ServerProc(
        Command::new(exe)
            .args(["send_path_2proc", "--exact", "--ignored"])
            .env("TP_ROLE", "server")
            .env("TP_PORT_FILE", &port_file)
            .spawn()
            .expect("spawn server process"),
    );

    let mut port = 0u16;
    for _ in 0..2000 {
        if let Ok(s) = std::fs::read_to_string(&port_file)
            && let Ok(p) = s.trim().parse::<u16>()
        {
            port = p;
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(port != 0, "server did not report a port");
    let _ = std::fs::remove_file(&port_file);
    let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let server_pubkey = *SigningKey::from_seed(&SERVER_SEED)
        .unwrap()
        .pubkey()
        .unwrap();

    let mut drv = Driver::new(DriverCfg::for_quic_udp(8192, 2048)).unwrap();
    let handler = DrainHandler::default();
    let rx = handler.rx.clone();
    let mut client = std::pin::pin!(
        Endpoint::<0, _>::build_client(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            handler,
            &mut drv,
        )
        .unwrap()
    );
    client.as_mut().set_gso(gso);
    let h = client
        .as_mut()
        .connect(server_addr, server_pubkey, tp_2proc(), CID.to_vec());

    let tiny = Duration::from_micros(20);
    let mut ready = false;
    for _ in 0..2000 {
        client.as_mut().drive(&mut drv);
        let _ = drv.park(tiny);
        if client
            .as_mut()
            .conn_mut(h)
            .map(|c| c.is_established())
            .unwrap_or(false)
        {
            ready = true;
            break;
        }
    }
    assert!(ready, "handshake did not complete");

    *rx.borrow_mut() = 0;
    let start = Instant::now();
    let dur = Duration::from_secs(secs);
    while start.elapsed() < dur {
        client.as_mut().drive(&mut drv);
        let _ = drv.park(tiny);
    }
    let elapsed = start.elapsed().as_secs_f64();
    let got = *rx.borrow();

    eprintln!(
        "\nsend_path_2proc: gso={} body={}B -> {:.1} MiB/s recv ({:.0} resp/s eq)",
        gso as u8,
        body_len,
        got as f64 / elapsed / (1024.0 * 1024.0),
        got as f64 / body_len as f64 / elapsed
    );
}
