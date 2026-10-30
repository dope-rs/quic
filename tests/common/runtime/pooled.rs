use dope::core::driver::schedule::clock;
use dope::runtime::{control, shutdown};
use dope_quic::conn::life::tls::clients::Authority;
use dope_quic::conn::{id, output::transmit};
use dope_quic::errors::{self, SendFailure, detail};
use dope_quic::proto::{
    cid,
    datagram::{Arena, Error, Packet, Sealed},
    param,
};
use dope_quic::runtime::endpoint::{self, Endpoint, config::Config, owner::Owned};
use dope_quic::runtime::mux::handler;
use dope_quic::runtime::mux::handler::hook::{
    data::datagram,
    life::{create, ready},
    set,
    wire::{cert, ingress, packet},
};
use dope_test::harness::observe::VecCellExt as _;
use o3::buffer::resident;
use std::{cell::Cell, hint, net::SocketAddr, num::NonZero, rc::Rc};

pub const SERVER_ROUTE: u8 = 0;
pub const CLIENT_ROUTE: u8 = 1;
pub const PAYLOAD: &[u8] = b"one arena slot from FEC to kernel completion";

const ENDPOINT: Config = Config {
    max_conns: 1,
    outgoing_capacity: 64,
    outgoing_bytes_capacity: 1 << 20,
    packet_buffer_slots: 64,
    packet_buffer_bytes: 65_535,
    cid_rotation: cid::Rotation::disabled(),
};

pub fn endpoint() -> Config {
    Config {
        cid_rotation: cid::Rotation::from_nanos(
            NonZero::<u64>::MIN.saturating_add(3_599_999_999_999),
            NonZero::<u16>::MIN,
        ),
        ..ENDPOINT
    }
}

pub struct Connect {
    pub peer: SocketAddr,
    pub authority: Authority,
    pub params: param::Set,
}

#[derive(Default)]
pub struct Errors {
    pub packets: Cell<Vec<errors::Receive>>,
    detail: Cell<Option<detail::Diagnostic>>,
    pub certificates: Cell<bool>,
    pub failures: Cell<Vec<Failure>>,
    pub resident: Cell<Option<(usize, usize)>>,
}

#[derive(Debug)]
pub enum Failure {
    Payload(Vec<u8>),
    MissingShutdown,
    Shutdown(shutdown::FireError),
    Timeout,
    Connect(errors::Connect),
    MissingHandle,
    NotReady,
    Packet(Error),
    Available(usize),
    Access(errors::Access),
    MissingDeadline,
    Send(SendFailure<Vec<u8>>),
    Returned {
        expected: *const u8,
        actual: *const u8,
    },
}

pub struct Capture<'d, const ID: u8> {
    pub established: Rc<Cell<Option<id::Handle<id::Driver<'d>, ID>>>>,
    pub errors: Rc<Errors>,
    pub received: Rc<Cell<bool>>,
    pub stop: Rc<Cell<Option<shutdown::Trigger>>>,
}

impl<const ID: u8> Capture<'_, ID> {
    fn finish(&self) -> Result<(), Failure> {
        self.stop
            .take()
            .ok_or(Failure::MissingShutdown)?
            .fire()
            .map_err(Failure::Shutdown)
    }
}

impl<'d, const ID: u8> handler::Handler<ID, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID>
{
    type Connection = ();
    type Create = create::Unit;
    type Events = set::Set<
        set::On,
        set::On,
        set::Off,
        set::Off,
        set::Off,
        set::Off,
        ingress::Off,
        packet::On,
    >;
}

impl<'d, const ID: u8> ready::Sink<ID, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID>
{
    fn established(
        event: ready::Event<'_, Self, ID, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>,
    ) {
        let (this, _, handle, _) = event.into();
        this.established.set(Some(handle));
    }
}

impl<'d, const ID: u8> datagram::Sink<ID, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID>
{
    fn datagram(
        event: datagram::Event<'_, Self, ID, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>,
    ) {
        let (this, _, _, data, _) = event.into();
        if ID == SERVER_ROUTE {
            if data != PAYLOAD {
                this.errors.failures.push(Failure::Payload(data));
            }
            this.received.set(true);
            if let Err(error) = this.finish() {
                this.errors.failures.push(error);
            }
        }
    }
}

impl<'d, const ID: u8> packet::Sink<ID, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>
    for Capture<'d, ID>
{
    fn packet(event: packet::Event<'_, Self>) {
        let (this, _, error, _) = event.into_parts();
        match error {
            packet::Failure::Receive(error) => this.errors.packets.push(error),
            packet::Failure::Diagnostic(detail) => this.errors.detail.set(Some(detail.clone())),
        }
    }
}

pub struct State<'pool> {
    pub arena: &'pool Arena,
    pub connect: Option<Connect>,
    pub packet: Option<Packet<'pool>>,
    pub errors: Rc<Errors>,
    pub sent: bool,
}

#[pin_project::pin_project]
#[derive(dope::Application)]
#[dispatcher(driver = 'd)]
#[coordinate]
pub struct App<'d, 'pool> {
    #[pin]
    #[manifold]
    pub server: Endpoint<'d, SERVER_ROUTE, Capture<'d, SERVER_ROUTE>>,
    #[pin]
    #[manifold(control)]
    pub client: Endpoint<
        'd,
        CLIENT_ROUTE,
        Capture<'d, CLIENT_ROUTE>,
        Vec<u8>,
        endpoint::Idle,
        Owned,
        Sealed<'pool>,
    >,
    #[dispatcher(state)]
    pub state: State<'pool>,
    #[dispatcher(schedule)]
    pub timeout: clock::Deadline<'d>,
}

impl<'d, 'pool> App<'d, 'pool> {
    fn coordinate(mut this: app_coord::Fields<'_, 'd, 'pool>) -> control::Flow {
        if this.state.errors.failures.len() != 0 {
            return control::Flow::Idle;
        }
        if let Err(error) = Self::advance(&mut this) {
            this.state.errors.failures.push(error);
        }
        let failed = this.state.errors.failures.len() != 0
            || this.state.errors.packets.len() != 0
            || this.state.errors.certificates.get();
        if failed && let Err(error) = this.client.handler().finish() {
            this.state.errors.failures.push(error);
        }
        control::Flow::Idle
    }

    fn advance(this: &mut app_coord::Fields<'_, 'd, 'pool>) -> Result<(), Failure> {
        let clock = this.step.clock();
        let now = clock.now();
        if this.timeout.is_due(now) {
            return Err(Failure::Timeout);
        }
        if let Some(connect) = this.state.connect.take() {
            this.client
                .at(clock)
                .connect(
                    connect.peer,
                    &connect.authority,
                    connect.params,
                    vec![0x42; dope_quic::runtime::routing::ENTROPY_LEN],
                )
                .map_err(Failure::Connect)?;
        }
        if !this.state.sent
            && let Some(handle) = this.client.handler().established.get()
        {
            let (ready, window) = this
                .client
                .inspect(handle, |_events, _app, conn| {
                    (conn.lifecycle().is_ready(), conn.recovery().window())
                })
                .ok_or(Failure::MissingHandle)?;
            if !ready {
                return Err(Failure::NotReady);
            }
            hint::black_box(window);

            let packet = match this.state.packet.take() {
                Some(packet) => packet,
                None => {
                    let arena: &'pool Arena = this.state.arena;
                    let mut packet = arena.try_acquire(PAYLOAD.len()).map_err(Failure::Packet)?;
                    packet.payload_mut().copy_from_slice(PAYLOAD);
                    packet
                }
            };
            let mut client = this.client.at(clock);
            {
                let pointer = packet.payload().as_ptr();
                match client.try_pooled(handle, packet) {
                    Ok(()) => {
                        let free = this.state.arena.available();
                        if free != 0 {
                            return Err(Failure::Available(free));
                        }
                        let deadline = client
                            .with_conn(handle, |scope| scope.view().deadline())
                            .map_err(Failure::Access)?
                            .ok_or(Failure::MissingDeadline)?;
                        hint::black_box(deadline.try_left(now));
                        this.state.sent = true;
                    }
                    Err(SendFailure::Full(packet)) => this.state.packet = Some(packet),
                    Err(SendFailure::Admission(
                        packet,
                        transmit::Admission::Datagram(Error::Resident { required, maximum }),
                    )) => {
                        if packet.payload().as_ptr() != pointer {
                            return Err(Failure::Returned {
                                expected: pointer,
                                actual: packet.payload().as_ptr(),
                            });
                        }
                        if packet.payload() != PAYLOAD {
                            return Err(Failure::Payload(packet.payload().to_vec()));
                        }
                        this.state
                            .errors
                            .resident
                            .set(Some((required.get(), maximum)));
                    }
                    Err(SendFailure::Admission(packet, cause)) => {
                        return Err(Failure::Send(SendFailure::Admission(
                            packet.payload().to_vec(),
                            cause,
                        )));
                    }
                    Err(SendFailure::Closed(packet)) => {
                        return Err(Failure::Send(SendFailure::Closed(
                            packet.payload().to_vec(),
                        )));
                    }
                    Err(SendFailure::TooLarge(packet)) => {
                        return Err(Failure::Send(SendFailure::TooLarge(
                            packet.payload().to_vec(),
                        )));
                    }
                    Err(SendFailure::Unsupported(packet)) => {
                        return Err(Failure::Send(SendFailure::Unsupported(
                            packet.payload().to_vec(),
                        )));
                    }
                    Err(SendFailure::Crypto(cause)) => {
                        return Err(Failure::Send(SendFailure::Crypto(cause)));
                    }
                }
            }
        }
        Ok(())
    }
}

impl<'d, const ID: u8> cert::Sink<ID, id::Driver<'d>> for Capture<'d, ID> {
    fn certificate(event: cert::Event<'_, '_, Self, ID, id::Driver<'d>>) {
        let (this, _, _, _) = event.into_parts();
        this.errors.certificates.set(true);
    }
}
