use dope::core::driver::settings;
use dope::runtime::{control, shutdown};
use dope_quic::conn::{
    id,
    life::{options::Options, tls::clients},
};
use dope_quic::runtime::embedded::{self, link, plan};
use dope_quic::runtime::{
    mux::handler::{
        self,
        hook::{life::create, set, wire::cert},
    },
    routing,
};
use dope_quic::{errors, stream};
use dope_test::harness::observe::VecCellExt as _;
use embedded::link::Link;
use o3::buffer::resident;
use settings::claim::Needs;
use settings::errors::Claim;
use std::{
    cell::{Cell, RefCell},
    net::SocketAddr,
    rc::Rc,
};

pub fn config() -> embedded::Config {
    embedded::Config {
        max_connections: 8,
        outgoing_capacity: 32,
        outgoing_bytes_capacity: 1 << 18,
        link_capacity: 3,
        max_flight_resident_bytes: 2048,
    }
}

pub fn address(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

pub fn link<const ROUTE: u8>() -> Result<link::Plan<ROUTE, 7, 8>, plan::Error> {
    Ok(plan::Plan::try_new(config())?.link(address(7), address(8)))
}

pub fn driver<const ROUTE: u8, const FROM: u8, const TO: u8>(
    plan: &link::Plan<ROUTE, FROM, TO>,
) -> Result<settings::Config, Claim> {
    Needs::from_tree(plan)?.apply_to(settings::Config::default())
}

#[pin_project::pin_project]
#[derive(dope::Application)]
#[dispatcher(driver = 'd)]
#[coordinate]
pub struct Links<'d> {
    #[pin]
    #[manifold]
    pub forward: Link<'d, 21, 7, 8>,
    #[pin]
    #[manifold]
    pub reverse: Link<'d, 22, 8, 7>,
    #[dispatcher(state)]
    pub trigger: Option<shutdown::Trigger>,
    #[dispatcher(state)]
    pub fired: Rc<Cell<Vec<Result<(), shutdown::FireError>>>>,
}

impl<'d> Links<'d> {
    fn coordinate(this: links_coord::Fields<'_, 'd>) -> control::Flow {
        if let Some(trigger) = this.trigger.take() {
            this.fired.push(trigger.fire());
        }
        control::Flow::Idle
    }
}

#[derive(Default)]
pub struct Capture {
    pub failed: bool,
}

impl<'d, const ID: u8>
    handler::Handler<ID, stream::RecvBuffer<'d>, resident::Shared<'d>, id::Driver<'d>> for Capture
{
    type Connection = ();
    type Create = create::Unit;
    type Events = set::Set;
}

impl<'d, const ID: u8> cert::Sink<ID, id::Driver<'d>> for Capture {
    fn certificate(event: cert::Event<'_, '_, Self, ID, id::Driver<'d>>) {
        let (this, _, _, _) = event.into_parts();
        this.get_mut().failed = true;
    }
}

pub struct Retried<'d> {
    pub opened: Result<(), errors::Connect>,
    pub first: Result<usize, embedded::Error<'d, 7, 8>>,
    pub again: Result<usize, embedded::Error<'d, 7, 8>>,
    pub sent: Result<usize, embedded::Error<'d, 7, 8>>,
    pub empty: Result<usize, embedded::Error<'d, 7, 8>>,
    pub count: usize,
    pub failed: bool,
    pub stopped: Result<(), shutdown::FireError>,
}

#[pin_project::pin_project]
#[derive(dope::Application)]
#[dispatcher(driver = 'd)]
#[coordinate]
pub struct Retry<'d> {
    #[pin]
    #[manifold(control)]
    pub client: embedded::Endpoint<'d, 7, Capture, stream::RecvBuffer<'d>>,
    #[pin]
    #[manifold(control)]
    pub server: embedded::Endpoint<'d, 8, Capture, stream::RecvBuffer<'d>>,
    #[pin]
    #[manifold(control)]
    pub wrong: Link<'d, 31, 7, 8>,
    #[pin]
    #[manifold(control)]
    pub right: Link<'d, 32, 7, 8>,
    #[dispatcher(state)]
    pub auth: clients::Authority,
    #[dispatcher(state)]
    pub seen: Rc<RefCell<Option<Retried<'d>>>>,
    #[dispatcher(state)]
    pub stop: Option<shutdown::Trigger>,
}

impl<'d> Retry<'d> {
    fn coordinate(mut this: retry_coord::Fields<'_, 'd>) -> control::Flow {
        let Some(stop) = this.stop.take() else {
            return control::Flow::Idle;
        };
        let now = this.step.now();
        let opened = this
            .client
            .connect(
                now,
                address(8),
                this.auth,
                Options::default(),
                routing::Plain,
            )
            .map(|_| ());
        let first = this.client.relay(&mut this.server, &mut this.wrong, now);
        let again = this.client.relay(&mut this.server, &mut this.wrong, now);
        let sent = this.client.relay(&mut this.server, &mut this.right, now);
        let empty = this.client.relay(&mut this.server, &mut this.right, now);
        *this.seen.borrow_mut() = Some(Retried {
            opened,
            first,
            again,
            sent,
            empty,
            count: this.server.len(),
            failed: this.server.handler().failed,
            stopped: stop.fire(),
        });
        control::Flow::Idle
    }
}
