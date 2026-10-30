use crate::common::runtime::loopback::{capture::Capture, load::Load};
use dope::core::driver::schedule::{self, clock};
use dope::runtime::control;
use dope_quic::runtime::endpoint::config::Config;
use dope_quic::{
    proto::cid,
    runtime::{
        endpoint::{self, Endpoint},
        mux::{app, manage},
    },
};
pub mod capture;
pub mod load;
pub const CID: [u8; 8] = [0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42];
pub const SERVER_ROUTE: u8 = 0;
pub const CLIENT_ROUTE: u8 = 1;
pub const SATURATED_DATAGRAMS: usize = schedule::LIMIT * 16 + 17;
pub const APPLICATION_PAYLOAD: usize = 1_024;

pub const ENDPOINT: Config = Config {
    max_conns: 1,
    outgoing_capacity: 64,
    outgoing_bytes_capacity: 1 << 20,
    packet_buffer_slots: 64,
    packet_buffer_bytes: u16::MAX as u32,
    cid_rotation: cid::Rotation::disabled(),
};

#[pin_project::pin_project]
#[derive(dope::Application)]
#[dispatcher(driver = 'd)]
#[coordinate]
pub struct App<'d> {
    #[pin]
    #[manifold(control)]
    pub server: Endpoint<
        'd,
        SERVER_ROUTE,
        Capture<'d, SERVER_ROUTE>,
        Vec<u8>,
        endpoint::Run<Load, app::Watch>,
    >,
    #[pin]
    #[manifold(control)]
    pub client: Endpoint<'d, CLIENT_ROUTE, Capture<'d, CLIENT_ROUTE>>,
    #[dispatcher(schedule)]
    pub timeout: clock::Deadline<'d>,
}

impl<'d> App<'d> {
    fn coordinate(mut this: app_coord::Fields<'_, 'd>) -> control::Flow {
        if this.client.view().is_failed() {
            return control::Flow::Idle;
        }
        if this.client.view().gso_active().is_none() {
            let srv_gso = this.server.enable_gso().is_ok();
            let cli_gso = this.client.enable_gso().is_ok();
            let active = srv_gso && cli_gso;
            if !active {
                this.server.disable_gso();
                this.client.disable_gso();
            }
            this.client.view().set_gso(active);
        }
        if this.timeout.is_due(this.step.now()) {
            this.client.view().timeout();
            return control::Flow::Idle;
        }
        let fair = &this.client.handler().fairness;
        if fair.admitted.get() == fair.target && fair.received.get() == fair.target {
            this.server.seal();
            this.client.seal();
            let server = this
                .server
                .at(this.step.clock())
                .quiesce(|state| state.map(|mut turn| turn.lifecycle().advance()));
            let client = this
                .client
                .at(this.step.clock())
                .quiesce(|state| state.map(|mut turn| turn.lifecycle().advance()));
            match (server, client) {
                (Ok(manage::Status::Complete), Ok(manage::Status::Complete)) => {}
                (Ok(_), Ok(_)) => return control::Flow::More,
                (Err(_), _) | (_, Err(_)) => {
                    this.client.view().fail(load::Failure::Unsealed);
                    return control::Flow::Idle;
                }
            }
            let server = this.server.handler();
            let client = this.client.handler();
            if server.network.observed.is_complete()
                && client.network.observed.is_complete()
                && let Some(stop) = client.stop.take()
            {
                client.finish(stop);
            }
            return control::Flow::Idle;
        }
        if let Some(connect) = this.client.view().take_connect()
            && let Err(error) = this.client.at(this.step.clock()).connect(
                connect.peer,
                &connect.authority,
                connect.params,
                CID.to_vec(),
            )
        {
            this.client.view().fail(load::Failure::Connect(error));
        }
        control::Flow::Idle
    }
}
