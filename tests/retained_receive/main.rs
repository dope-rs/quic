mod sealed;

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dope::core::driver::settings;
use dope::manifold::timing;
use dope::runtime::{executor::Executor, shutdown};
use dope_quic::conn::{self, Handle, server, session::Connection};
use dope_quic::{Handler, RecvBuffer, RetainedEndpoint, endpoint, transport_params};
use shin::crypto::sig::SigningKey;
use shin::server::config::NoGuard;

const CID: [u8; 8] = [0x31; 8];
const SERVER_ROUTE: u8 = 0;
const CLIENT_ROUTE: u8 = 1;

const ENDPOINT: endpoint::Config = endpoint::Config {
    max_conns: 1,
    outgoing_capacity: 16,
    outgoing_bytes_capacity: 1 << 16,
    packet_buffer_slots: 16,
    packet_buffer_bytes: 2048,
};

struct Timeout(Instant);

impl timing::Schedule for Timeout {
    fn deadline(&self) -> Option<Instant> {
        Some(self.0)
    }
}

#[derive(Default)]
struct Proof {
    client: Option<Handle>,
    server_ready: bool,
    payload: Option<Vec<u8>>,
    received: Option<(Vec<u8>, usize)>,
    timed_out: bool,
    stop: Option<shutdown::Trigger>,
}

struct Capture {
    client: bool,
    proof: Rc<RefCell<Proof>>,
    connect: Option<Connect>,
}

struct Connect {
    peer: SocketAddr,
    public_key: [u8; 32],
    parameters: transport_params::Params,
}

impl<'d, const ID: u8> Handler<ID, RecvBuffer<'d>> for Capture {
    type Connection = ();

    fn create_connection(
        &mut self,
        _connection: &mut Connection<ID, RecvBuffer<'d>>,
        _handle: Handle,
    ) {
    }

    fn established(
        &mut self,
        _connection: &mut (),
        _conn: &mut Connection<ID, RecvBuffer<'d>>,
        handle: Handle,
    ) {
        if self.client {
            self.proof.borrow_mut().client = Some(handle);
        } else {
            self.proof.borrow_mut().server_ready = true;
        }
    }

    fn datagram(
        &mut self,
        _connection: &mut (),
        _conn: &mut Connection<ID, RecvBuffer<'d>>,
        _handle: Handle,
        data: RecvBuffer<'d>,
    ) {
        if self.client {
            return;
        }
        let mut proof = self.proof.borrow_mut();
        proof.received = Some((data.as_slice().to_vec(), data.resident_bytes()));
        proof
            .stop
            .take()
            .expect("retained receive stop capability")
            .fire()
            .expect("stop retained receive loopback");
    }
}

struct CaptureControl<'step>(&'step mut Capture);

impl CaptureControl<'_> {
    fn take_connect(&mut self) -> Option<Connect> {
        self.0.connect.take()
    }

    fn take_send(&mut self) -> Option<(Handle, Vec<u8>)> {
        let mut proof = self.0.proof.borrow_mut();
        if !proof.server_ready {
            return None;
        }
        let handle = proof.client?;
        let payload = proof.payload.take()?;
        Some((handle, payload))
    }

    fn timeout(&mut self) {
        let mut proof = self.0.proof.borrow_mut();
        proof.timed_out = true;
        proof
            .stop
            .take()
            .expect("retained receive timeout stop capability")
            .fire()
            .expect("stop timed-out retained receive loopback");
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
    server: RetainedEndpoint<'d, SERVER_ROUTE, Capture>,
    #[pin]
    #[manifold(control)]
    client: RetainedEndpoint<'d, CLIENT_ROUTE, Capture>,
    #[dispatcher(schedule)]
    timeout: Timeout,
}

impl<'d> App<'d> {
    fn coordinate(mut this: AppCoordinate<'_, '_, 'd>) -> dope::runtime::coordinate::Flow {
        if this.timeout.0 <= this.step.now() {
            this.client.handler_control().timeout();
            return dope::runtime::coordinate::Flow::Idle;
        }
        if let Some(connect) = this.client.handler_control().take_connect() {
            this.client
                .connect(
                    connect.peer,
                    connect.public_key,
                    connect.parameters,
                    CID.to_vec(),
                )
                .expect("connect retained receive loopback");
        }
        if let Some((handle, payload)) = this.client.handler_control().take_send() {
            this.client
                .try_send_datagram(handle, payload)
                .expect("queue retained receive proof datagram");
        }
        dope::runtime::coordinate::Flow::Idle
    }
}

fn receive(payload: Vec<u8>) -> (Vec<u8>, usize) {
    let signing = SigningKey::from_seed(&[0x52; 32]).expect("test signing key");
    let server_pubkey = *signing.pubkey().unwrap();
    let parameters = transport_params::Params {
        max_idle_timeout_ms: 30_000,
        max_datagram_frame_size: Some(2048),
        ..transport_params::Params::default()
    };
    let (source, stop) = shutdown::Pair::new().unwrap().split();
    let proof = Rc::new(RefCell::new(Proof {
        payload: Some(payload),
        stop: Some(stop),
        ..Proof::default()
    }));
    let executor = Executor::new(
        settings::Config::for_quic_udp(64, ENDPOINT.packet_buffer_bytes)
            .expect("valid retained receive driver config"),
    )
    .unwrap()
    .with_shutdown(source)
    .unwrap();

    executor.enter(|mut session| {
        let timeout = Timeout(Instant::now() + Duration::from_secs(2));
        let (server, client) = {
            let mut driver = session.driver_access();
            let server = RetainedEndpoint::<'_, SERVER_ROUTE, Capture, server::Standard>::build_server_with_policy(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                signing,
                conn::config::Options::from(parameters.clone()),
                NoGuard,
                Capture {
                    client: false,
                    proof: Rc::clone(&proof),
                    connect: None,
                },
                ENDPOINT,
                &mut driver,
            )
            .unwrap();
            let server_addr = server.local_addr();
            let client = RetainedEndpoint::<'_, CLIENT_ROUTE, Capture>::build_client(
                "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
                Capture {
                    client: true,
                    proof: Rc::clone(&proof),
                    connect: Some(Connect {
                        peer: server_addr,
                        public_key: server_pubkey,
                        parameters,
                    }),
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
                        marker: core::marker::PhantomData,
                        server,
                        client,
                        timeout,
                    },
                    |mut app| app.run(),
                )
                .expect("retained receive teardown")
                .expect("retained receive runtime"),
        );

        let proof = proof.borrow();
        assert!(!proof.timed_out, "retained receive deadline elapsed");
        proof.received.clone().expect("server datagram")
    })
}

#[test]
fn small_payload_falls_back_to_one_exact_lifetime_safe_owner() {
    let payload = b"compact";
    let (bytes, resident) = receive(payload.to_vec());
    assert_eq!(bytes, payload);
    assert_eq!(resident, payload.len());
}

#[test]
fn large_payload_keeps_the_driver_owner_without_copying() {
    let payload = vec![0xa5; 1000];
    let (bytes, resident) = receive(payload.clone());
    assert_eq!(bytes, payload);
    assert!(resident >= ENDPOINT.packet_buffer_bytes as usize);
}
