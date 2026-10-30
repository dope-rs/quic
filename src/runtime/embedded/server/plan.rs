use dope::core::driver::route;
use dope::core::driver::route::indices;
use dope::core::driver::settings::claim;
use dope::core::driver::settings::errors::Claim;
use dope::core::driver::{self, settings};
use o3::buffer::resident;

use crate::conn::id;
use crate::conn::life::{accept, options};
use crate::errors;
use crate::runtime::embedded::{self, plan, server};
use crate::runtime::mux::{app, auth, builder, handler, router};
use crate::runtime::routing;
use crate::stream;

/// Validated, single-use socket-free server auth.
#[must_use = "an embedded server plan must be bound to one driver"]
pub struct Plan<const ID: u8> {
    auth: accept::Authority<ID>,
    proto: plan::Plan,
}

impl<const ID: u8> Plan<ID> {
    pub fn new(
        source: rustls::ServerConfig,
        opts: options::Options,
        plan: plan::Plan,
    ) -> Result<Self, errors::Connect> {
        let auth = accept::Authority::new(source, opts)?;
        Ok(Self { auth, proto: plan })
    }

    pub fn bind<'d, H, B>(
        self,
        handler: H,
        driver: &mut driver::Context<'_, 'd>,
    ) -> Result<embedded::Endpoint<'d, ID, H, B>, server::BindError>
    where
        H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
        B: stream::Recv,
    {
        let mux = self.build(handler, driver)?;
        Self::finish(mux, embedded::Idle, driver)
    }

    pub fn bind_with<'d, H, B, A, F, E>(
        self,
        driver: &mut driver::Context<'_, 'd>,
        bind: F,
    ) -> Result<embedded::Endpoint<'d, ID, H, B, embedded::Run<A>>, server::BindFailure<E>>
    where
        H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
        B: stream::Recv,
        A: app::Driver<'d, H, ID, B, resident::Shared<'d>>,
        F: FnOnce(driver::Binding<'d>) -> Result<(H, A), E>,
    {
        let binding = driver::Binding::new(driver.driver_ref().timer(), self.proto.capacity());
        let (handler, app) = bind(binding).map_err(server::BindFailure::Application)?;
        let mux = self
            .build(handler, driver)
            .map_err(server::BindFailure::Endpoint)?;
        let schedule = embedded::Run {
            app,
            work: embedded::WorkGraph::new(),
        };
        Self::finish(mux, schedule, driver).map_err(server::BindFailure::Endpoint)
    }

    fn build<'d, H, B>(
        self,
        handler: H,
        driver: &mut driver::Context<'_, 'd>,
    ) -> Result<
        router::Router<H, ID, B, auth::Owned<routing::Plain, id::Driver<'d>>>,
        server::BindError,
    >
    where
        H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
        B: stream::Recv,
    {
        let Self { auth, proto: plan } = self;
        builder::Builder::<auth::Owned<routing::Plain, id::Driver<'d>>, _, ID, B>::server_in(
            handler,
            auth,
            routing::Plain,
            plan.limits(),
        )
        .bind(driver)
        .map_err(server::BindError::Mux)
    }

    pub(in crate::runtime::embedded) fn finish<'d, H, B, S>(
        mux: router::Router<H, ID, B, auth::Owned<routing::Plain, id::Driver<'d>>>,
        schedule: S,
        driver: &mut driver::Context<'_, 'd>,
    ) -> Result<embedded::Endpoint<'d, ID, H, B, S>, server::BindError>
    where
        H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
        B: stream::Recv,
    {
        let access = driver.driver_ref();
        let target = access
            .targets::<route::KeyTag<ID>>()
            .bind(indices::SlotIndex::ZERO, route::Epoch::INITIAL);
        let ready = access
            .ready()
            .make_slot(target.dispatch())
            .map_err(server::BindError::Ready)?;
        Ok(embedded::Endpoint::new(mux, schedule, ready))
    }
}

impl<const ID: u8> settings::Resource for Plan<ID> {
    fn include_in(&self, needs: claim::Needs) -> Result<claim::Needs, Claim> {
        needs.include(
            claim::Claim::new(settings::Routes::singleton::<route::KeyTag<ID>>())
                .schedule(self.proto.schedule()),
        )
    }
}
