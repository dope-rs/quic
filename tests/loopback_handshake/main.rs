mod sealed;

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dope::core::driver::settings;
use dope::manifold::timing;
use dope::runtime::{executor::Executor, shutdown};
use dope_quic::conn::Handle;
use dope_quic::conn::server;
use dope_quic::{Endpoint, Handler, conn, conn::session::Connection, endpoint, transport_params};
use shin::crypto::sig::SigningKey;
use shin::server::config::NoGuard;

const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];
const SERVER_ROUTE: u8 = 0;
const CLIENT_ROUTE: u8 = 1;

struct Timeout(Instant);

impl timing::Schedule for Timeout {
    fn deadline(&self) -> Option<Instant> {
        Some(self.0)
    }
}

const ENDPOINT: endpoint::Config = endpoint::Config {
    max_conns: 1,
    outgoing_capacity: 64,
    outgoing_bytes_capacity: 1 << 20,
    packet_buffer_slots: 64,
    packet_buffer_bytes: u16::MAX as u32,
};

#[derive(Default)]
struct Events {
    established: Vec<Handle>,
    datagrams: Vec<(Handle, Vec<u8>)>,
}

struct CapturingHandler {
    events: Rc<RefCell<Events>>,
    established: Rc<RefCell<usize>>,
    stop: Rc<RefCell<Option<shutdown::Trigger>>>,
    connect: Option<Connect>,
    timed_out: Rc<RefCell<bool>>,
}

struct Connect {
    peer: SocketAddr,
    public_key: [u8; 32],
    params: transport_params::Params,
}

impl<const ID: u8> Handler<ID> for CapturingHandler {
    type Connection = ();

    fn create_connection(&mut self, _conn: &mut Connection<ID>, _handle: Handle) {}

    fn established(&mut self, _connection: &mut (), _conn: &mut Connection<ID>, h: Handle) {
        self.events.borrow_mut().established.push(h);
        let total = self.established.borrow().saturating_add(1);
        *self.established.borrow_mut() = total;
        if total == 2 {
            self.stop
                .borrow_mut()
                .take()
                .expect("loopback stop capability")
                .fire()
                .expect("stop completed loopback");
        }
    }
    fn datagram(
        &mut self,
        _connection: &mut (),
        _conn: &mut Connection<ID>,
        h: Handle,
        data: Vec<u8>,
    ) {
        self.events.borrow_mut().datagrams.push((h, data.to_vec()));
    }
}

struct CapturingControl<'step>(&'step mut CapturingHandler);

impl CapturingControl<'_> {
    fn stop_timed_out(&mut self) {
        *self.0.timed_out.borrow_mut() = true;
        self.0
            .stop
            .borrow_mut()
            .take()
            .expect("loopback timeout stop capability")
            .fire()
            .expect("stop timed-out loopback");
    }

    fn take_connect(&mut self) -> Option<Connect> {
        self.0.connect.take()
    }
}

#[pin_project::pin_project]
#[derive(dope_gen::Application)]
#[coordinate]
struct App<'d> {
    #[dispatcher(marker)]
    marker: ::core::marker::PhantomData<fn(&'d ()) -> &'d ()>,
    #[pin]
    #[manifold]
    server: Endpoint<'d, SERVER_ROUTE, CapturingHandler>,
    #[pin]
    #[manifold(control)]
    client: Endpoint<'d, CLIENT_ROUTE, CapturingHandler>,
    #[dispatcher(schedule)]
    timeout: Timeout,
}

impl<'d> App<'d> {
    fn coordinate(mut this: AppCoordinate<'_, '_, 'd>) -> dope::runtime::coordinate::Flow {
        if this.timeout.0 <= this.step.now() {
            this.client.handler_control().stop_timed_out();
            return dope::runtime::coordinate::Flow::Idle;
        }
        let connect = this.client.handler_control().take_connect();
        if let Some(connect) = connect {
            this.client
                .connect(
                    connect.peer,
                    connect.public_key,
                    connect.params,
                    CID.to_vec(),
                )
                .expect("connect loopback client");
        }
        dope::runtime::coordinate::Flow::Idle
    }
}

#[test]
fn quic_datagram_handshake_completes_on_loopback() {
    let signing = SigningKey::from_seed(&[0x39; 32]).expect("test signing key");
    let server_pubkey = *signing.pubkey().unwrap();

    let user_tp = transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(65535),
        ..transport_params::Params::default()
    };

    let (source, stop) = shutdown::Pair::new().unwrap().split();
    let stop = Rc::new(RefCell::new(Some(stop)));
    let executor =
        Executor::new(settings::Config::for_quic_udp(128, 2048).expect("valid driver config"))
            .unwrap()
            .with_shutdown(source)
            .unwrap();
    executor.enter(|mut session| {
        let established = Rc::new(RefCell::new(0));
        let server_events = Rc::new(RefCell::new(Events::default()));
        let client_events = Rc::new(RefCell::new(Events::default()));
        let timed_out = Rc::new(RefCell::new(false));
        let timeout = Timeout(Instant::now() + Duration::from_secs(2));
        let (server, client) = {
            let mut driver = session.driver_access();
            let server = Endpoint::<'_, SERVER_ROUTE, CapturingHandler, server::Standard>::build_server_with_policy(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                signing,
                conn::config::Options::from(user_tp.clone()),
                NoGuard,
                CapturingHandler {
                    events: server_events.clone(),
                    established: established.clone(),
                    stop: Rc::clone(&stop),
                    connect: None,
                    timed_out: timed_out.clone(),
                },
                ENDPOINT,
                &mut driver,
            )
            .unwrap();
            let server_addr = server.local_addr();
            let client = Endpoint::<'_, CLIENT_ROUTE, CapturingHandler>::build_client(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                CapturingHandler {
                    events: client_events.clone(),
                    established: established.clone(),
                    stop: Rc::clone(&stop),
                    connect: Some(Connect {
                        peer: server_addr,
                        public_key: server_pubkey,
                        params: user_tp,
                    }),
                    timed_out: timed_out.clone(),
                },
                ENDPOINT,
                &mut driver,
            )
            .unwrap();
            (server, client)
        };

        drop(
            session
            .with_app(
                App {
                    marker: ::core::marker::PhantomData,
                    server,
                    client,
                    timeout,
                },
                |mut app| app.run(),
            )
            .expect("loopback teardown")
            .expect("loopback runtime"),
        );

        assert!(!*timed_out.borrow(), "handshake deadline elapsed");
        assert_eq!(*established.borrow(), 2);
        assert_eq!(server_events.borrow().established.len(), 1);
        assert_eq!(client_events.borrow().established.len(), 1);
    });
}
