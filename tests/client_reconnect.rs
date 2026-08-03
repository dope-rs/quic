pub mod support;

use std::cell::Cell;
use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::time::{Duration, Instant};

use dope::runtime::dispatcher::Dispatcher;
use dope::runtime::executor::Executor;
use dope::{Completion, DriverContext, driver};
use dope_quic::conn::Handle;
use dope_quic::{
    BackoffPolicy, Client, Connection, Endpoint, EndpointSpec, Handler, Protocol, SlotId, client,
    conn, endpoint, transport_params,
};
use o3::cell;

const ENDPOINT: endpoint::Config = endpoint::Config {
    max_conns: 1,
    outgoing_capacity: 64,
    outgoing_bytes_capacity: 1 << 20,
    packet_buffer_slots: 64,
    packet_buffer_bytes: u16::MAX as u32,
    completion_budget: 64,
    flush_budget: 64,
};

struct CloseImmediately;

impl Handler for CloseImmediately {
    type Connection = ();

    fn create_connection(&mut self, _conn: &mut Connection, _handle: Handle) {}

    fn established(&mut self, _connection: &mut (), conn: &mut Connection, _handle: Handle) {
        conn.close(0, Vec::new());
    }
}

struct Immediate;

impl BackoffPolicy for Immediate {
    fn next_retry_at(&self, _attempt: u32, now: Instant) -> Instant {
        now
    }
}

struct Events {
    connects: Rc<Cell<usize>>,
    connected: bool,
}

impl Protocol for Events {
    fn connect(&mut self, _slot: SlotId) {
        self.connects.set(self.connects.get() + 1);
        self.connected = true;
    }

    fn datagram(&mut self, _slot: SlotId, _data: Vec<u8>) {}

    fn close(&mut self, _slot: SlotId) {
        self.connected = false;
    }
}

#[pin_project::pin_project]
#[derive(dope_gen::Dispatcher)]
#[coordinate]
struct Runtime<'d> {
    #[pin]
    #[manifold]
    server: Endpoint<'d, 0, CloseImmediately>,
    #[pin]
    #[manifold]
    client: Client<'d, 1, Events, Immediate>,
}

impl<'d> Runtime<'d> {
    fn coordinate(self: Pin<&mut Self>, _driver: &mut DriverContext<'_, 'd>) {
        let mut client = self.project().client;
        if client.as_ref().protocol().connected {
            let slot = SlotId::from_index(0);
            let stats = client.as_ref().path_stats(slot).unwrap();
            assert_eq!(client.as_ref().smoothed_rtt(slot), stats.srtt);
            assert!(stats.cwnd > 0);
            let _ = client.as_mut().try_send_datagram(slot, vec![0x42]);
        }
    }
}

#[test]
fn immediate_reconnect_reuses_one_generation_checked_slot() {
    let signing = support::signing_key(0x39);
    let pubkey = *signing.pubkey().unwrap();
    let params = transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(65_535),
        ..transport_params::Params::default()
    };
    let executor = Executor::new(driver::Config::for_quic_udp(64, 2048)).unwrap();
    executor.enter(|mut session| {
        let (token, mut driver) = session.token_and_driver();
        let reference = driver.driver_ref();
        let server = Endpoint::build_server(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            signing,
            params.clone(),
            CloseImmediately,
            ENDPOINT,
            &mut driver,
        )
        .unwrap();
        let connects = Rc::new(Cell::new(0));
        let client = Client::build(
            "127.0.0.1:0".parse().unwrap(),
            vec![EndpointSpec {
                addr: server.local_addr(),
                pubkey,
            }],
            conn::Config {
                transport_params: params,
                ..conn::Config::default()
            },
            Events {
                connects: connects.clone(),
                connected: false,
            },
            Immediate,
            client::Config {
                endpoint: ENDPOINT,
                event_budget: 64,
                retry_budget: 64,
            },
            &mut driver,
        )
        .unwrap();
        assert!(client.smoothed_rtt(SlotId::from_index(0)).is_none());
        assert!(client.path_stats(SlotId::from_index(0)).is_none());
        assert!(client.path_stats(SlotId::from_index(1)).is_none());
        let runtime = pin!(cell::BrandCell::new(Runtime { server, client }));
        let mut completions = [const { None }; 64];
        let mut ready = Vec::with_capacity(64);
        for _ in 0..2_000 {
            let count = driver.drain(&mut completions);
            for completion in &mut completions[..count] {
                let Some(event) = completion.take() else {
                    continue;
                };
                Runtime::dispatch(runtime.as_ref().borrow_pin_mut(token), event, &mut driver);
            }
            ready.clear();
            reference.drain_ready(|target| ready.push(target));
            for target in ready.drain(..) {
                Runtime::activate(runtime.as_ref().borrow_pin_mut(token), target, &mut driver);
            }
            Runtime::pre_park(runtime.as_ref().borrow_pin_mut(token), &mut driver);
            if connects.get() >= 3 {
                return;
            }
            driver.wait(Some(Duration::from_millis(1))).unwrap();
        }
        panic!("client connected {} times", connects.get());
    });
}
