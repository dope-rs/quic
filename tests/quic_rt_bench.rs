use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dope::{Drive, Driver, DriverCfg, DriverConfig};
use dope_quic::{Conn, ConnHandle, Endpoint, Handler, transport_params};
use ring::rand::{SecureRandom, SystemRandom};
use shin::sig::SigningKey;

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];
const TICK_PARK: Duration = Duration::from_millis(1);
const N_RT: usize = 100;

#[derive(Default)]
struct Events {
    established: Vec<ConnHandle>,
    datagrams: Vec<(ConnHandle, Vec<u8>)>,
}

#[derive(Clone, Default)]
struct CapturingHandler {
    events: Rc<RefCell<Events>>,
}

impl Handler for CapturingHandler {
    fn on_established(&mut self, _conn: &mut Conn, h: ConnHandle) {
        self.events.borrow_mut().established.push(h);
    }
    fn on_datagram(&mut self, _conn: &mut Conn, h: ConnHandle, data: Vec<u8>) {
        self.events.borrow_mut().datagrams.push((h, data.to_vec()));
    }
}

fn percentile(samples: &mut [Duration], p: f64) -> Duration {
    samples.sort();
    let idx = ((samples.len() as f64) * p / 100.0).floor() as usize;
    samples[idx.min(samples.len() - 1)]
}

#[test]
fn quic_datagram_round_trip_latency() {
    let mut seed = [0u8; 32];
    SystemRandom::new().fill(&mut seed).unwrap();
    let signing = SigningKey::from_seed(&seed).unwrap();
    let server_pubkey = *signing.pubkey().unwrap();

    let tp = transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(65535),
        ..transport_params::Params::default()
    };

    let mut server_drv = Driver::new(DriverCfg::for_quic_udp(64, 2048)).unwrap();
    let server_handler = CapturingHandler::default();
    let server_events = server_handler.events.clone();
    let mut server = std::pin::pin!(
        Endpoint::<0, _>::build_server(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            signing,
            tp.clone(),
            server_handler,
            &mut server_drv,
        )
        .unwrap()
    );
    let server_addr = server.local_addr();

    let mut client_drv = Driver::new(DriverCfg::for_quic_udp(64, 2048)).unwrap();
    let client_handler = CapturingHandler::default();
    let client_events = client_handler.events.clone();
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

    let mut handshake_done = false;
    for _ in 0..200 {
        client.as_mut().drive(&mut client_drv);
        let _ = client_drv.park(TICK_PARK);
        server.as_mut().drive(&mut server_drv);
        let _ = server_drv.park(TICK_PARK);
        if !client_events.borrow().established.is_empty()
            && !server_events.borrow().established.is_empty()
        {
            handshake_done = true;
            break;
        }
    }
    assert!(handshake_done, "handshake did not complete");

    let server_handle = server_events.borrow().established[0];

    let mut samples: Vec<Duration> = Vec::with_capacity(N_RT);
    for i in 0..N_RT {
        let payload = format!("ping-{i:04}").into_bytes();
        let want = payload.clone();

        let server_dg_count_before = server_events.borrow().datagrams.len();
        let client_dg_count_before = client_events.borrow().datagrams.len();

        let t0 = Instant::now();

        client
            .as_mut()
            .send_datagram(client_handle, payload)
            .expect("client send_datagram");

        let mut done = false;
        for _ in 0..200 {
            client.as_mut().drive(&mut client_drv);
            let _ = client_drv.park(TICK_PARK);
            server.as_mut().drive(&mut server_drv);

            let server_evs = server_events.borrow_mut();
            if server_evs.datagrams.len() > server_dg_count_before
                && let Some((_, data)) = server_evs.datagrams.last()
                && data == &want
            {
                let echo = data.clone();
                drop(server_evs);
                server
                    .as_mut()
                    .send_datagram(server_handle, echo)
                    .expect("server echo");
            } else {
                drop(server_evs);
            }
            let _ = server_drv.park(TICK_PARK);
            client.as_mut().drive(&mut client_drv);

            let client_evs = client_events.borrow();
            if client_evs.datagrams.len() > client_dg_count_before
                && let Some((_, data)) = client_evs.datagrams.last()
                && data == &want
            {
                done = true;
                break;
            }
        }
        let t1 = Instant::now();
        assert!(done, "round-trip {i} did not complete");
        samples.push(t1 - t0);
    }

    let mut sorted = samples.clone();
    let p50 = percentile(&mut sorted, 50.0);
    let p90 = percentile(&mut sorted, 90.0);
    let p99 = percentile(&mut sorted, 99.0);
    let min = sorted[0];
    let max = sorted[sorted.len() - 1];
    let avg: Duration = samples.iter().sum::<Duration>() / (samples.len() as u32);

    eprintln!(
        "\nquic-loopback round-trip ({} samples, no chaos):",
        samples.len()
    );
    eprintln!("  min  = {:?}", min);
    eprintln!("  avg  = {:?}", avg);
    eprintln!("  p50  = {:?}", p50);
    eprintln!("  p90  = {:?}", p90);
    eprintln!("  p99  = {:?}", p99);
    eprintln!("  max  = {:?}", max);

    assert!(
        p99 < Duration::from_millis(50),
        "p99 {:?} > 50ms — dope-quic adds suspicious latency on clean loopback",
        p99,
    );
}
