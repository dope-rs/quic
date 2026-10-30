use dope::core::driver::route;
use dope::core::driver::settings::claim;
use dope::core::driver::settings::errors::Claim;
use dope::core::driver::{self, settings};
use o3::buffer::resident;

use crate::conn::id;
use crate::runtime::embedded::{self, plan, server};
use crate::runtime::mux::{auth, builder, handler};
use crate::runtime::routing;
use crate::stream;

/// Validated, single-use socket-free client plan.
#[derive(Clone, Copy)]
#[must_use = "an embedded client plan must be bound to one driver"]
pub struct Plan<const ID: u8> {
    proto: plan::Plan,
}

impl<const ID: u8> Plan<ID> {
    pub const fn new(plan: plan::Plan) -> Self {
        Self { proto: plan }
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
        let mux =
            builder::Builder::<auth::Owned<routing::Plain, id::Driver<'d>>, _, ID, B>::client_in(
                handler,
                routing::Plain,
                self.proto.limits(),
            )
            .bind(driver)
            .map_err(server::BindError::Mux)?;
        server::Plan::<ID>::finish(mux, embedded::Idle, driver)
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
