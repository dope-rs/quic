mod sealed;

use std::cell::Cell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dope::core::driver::settings;
use dope::manifold::timing;
use dope::runtime::{executor::Executor, shutdown};
use dope_quic::conn::{Handle, session::Connection};
use dope_quic::{
    BackoffPolicy, Client, Endpoint, EndpointSpec, Handler, Protocol, SlotId, client, conn,
    endpoint, transport_params,
};
use shin::crypto::sig::SigningKey;

const ENDPOINT: endpoint::Config = endpoint::Config {
    max_conns: 1,
    outgoing_capacity: 64,
    outgoing_bytes_capacity: 1 << 20,
    packet_buffer_slots: 64,
    packet_buffer_bytes: u16::MAX as u32,
};
const SERVER_ROUTE: u8 = 0;
const CLIENT_ROUTE: u8 = 1;

struct Timeout(Instant);

impl timing::Schedule for Timeout {
    fn deadline(&self) -> Option<Instant> {
        Some(self.0)
    }
}

struct CloseImmediately;

impl Handler<SERVER_ROUTE> for CloseImmediately {
    type Connection = ();

    fn create_connection(&mut self, _conn: &mut Connection<SERVER_ROUTE>, _handle: Handle) {}

    fn established(
        &mut self,
        _connection: &mut (),
        conn: &mut Connection<SERVER_ROUTE>,
        _handle: Handle,
    ) {
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
    stop: Option<shutdown::Trigger>,
    timed_out: Rc<Cell<bool>>,
}

impl Protocol for Events {
    fn connect(&mut self, _slot: SlotId) {
        let connects = self.connects.get() + 1;
        self.connects.set(connects);
        self.connected = true;
        if connects == 3 {
            self.stop
                .take()
                .expect("reconnect stop capability")
                .fire()
                .expect("stop reconnect runtime");
        }
    }

    fn datagram(&mut self, _slot: SlotId, _data: Vec<u8>) {}

    fn close(&mut self, _slot: SlotId) {
        self.connected = false;
    }
}

struct EventsControl<'step>(&'step mut Events);

impl EventsControl<'_> {
    fn stop_timed_out(&mut self) {
        self.0.timed_out.set(true);
        self.0
            .stop
            .take()
            .expect("reconnect timeout stop capability")
            .fire()
            .expect("stop timed-out reconnect runtime");
    }
}

#[pin_project::pin_project]
#[derive(dope_gen::Application)]
#[coordinate]
struct Runtime<'d> {
    #[dispatcher(marker)]
    marker: ::core::marker::PhantomData<fn(&'d ()) -> &'d ()>,
    #[pin]
    #[manifold]
    server: Endpoint<'d, SERVER_ROUTE, CloseImmediately>,
    #[pin]
    #[manifold(control)]
    client: Client<'d, CLIENT_ROUTE, Events, Immediate>,
    #[dispatcher(schedule)]
    timeout: Timeout,
}

impl<'d> Runtime<'d> {
    fn coordinate(mut this: RuntimeCoordinate<'_, '_, 'd>) -> dope::runtime::coordinate::Flow {
        if this.timeout.0 <= this.step.now() {
            this.client.protocol_control().stop_timed_out();
            return dope::runtime::coordinate::Flow::Idle;
        }
        if this.client.protocol().connected {
            let slot = SlotId::from_index(0);
            let stats = this.client.path_stats(slot).unwrap();
            assert_eq!(this.client.smoothed_rtt(slot), stats.srtt);
            assert!(stats.cwnd > 0);
            let _ = this.client.try_send_datagram(slot, vec![0x42]);
        }
        dope::runtime::coordinate::Flow::Idle
    }
}

#[test]
fn immediate_reconnect_reuses_one_generation_checked_slot() {
    let signing = SigningKey::from_seed(&[0x39; 32]).expect("test signing key");
    let pubkey = *signing.pubkey().unwrap();
    let params = transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(65_535),
        ..transport_params::Params::default()
    };
    let (source, stop) = shutdown::Pair::new().unwrap().split();
    let executor =
        Executor::new(settings::Config::for_quic_udp(64, 2048).expect("valid driver config"))
            .unwrap()
            .with_shutdown(source)
            .unwrap();
    executor.enter(|mut session| {
        let connects = Rc::new(Cell::new(0));
        let timed_out = Rc::new(Cell::new(false));
        let timeout = Timeout(Instant::now() + Duration::from_secs(2));
        let (server, client) = {
            let mut driver = session.driver_access();
            let server = Endpoint::build_server(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                signing,
                params.clone(),
                CloseImmediately,
                ENDPOINT,
                &mut driver,
            )
            .unwrap();
            let client = Client::build(
                "127.0.0.1:0".parse().unwrap(),
                vec![EndpointSpec {
                    addr: server.local_addr(),
                    pubkey,
                }],
                conn::config::Options {
                    transport_params: params,
                    ..conn::config::Options::default()
                },
                Events {
                    connects: connects.clone(),
                    connected: false,
                    stop: Some(stop),
                    timed_out: timed_out.clone(),
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
            (server, client)
        };
        assert!(client.smoothed_rtt(SlotId::from_index(0)).is_none());
        assert!(client.path_stats(SlotId::from_index(0)).is_none());
        assert!(client.path_stats(SlotId::from_index(1)).is_none());
        drop(
            session
                .with_app(
                    Runtime {
                        marker: ::core::marker::PhantomData,
                        server,
                        client,
                        timeout,
                    },
                    |mut app| app.run(),
                )
                .expect("reconnect teardown")
                .expect("reconnect runtime"),
        );
        assert!(!timed_out.get(), "reconnect deadline elapsed");
        assert_eq!(connects.get(), 3, "shutdown restarted the client");
    });
}
