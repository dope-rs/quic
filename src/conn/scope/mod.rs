use crate::runtime::brand;

use std::{mem, time};

use o3::buffer::{self, resident};

use crate::{conn, stream};
use conn::life::{datagram, status};
use conn::output;
use conn::stream::access;
use conn::wire::ingress;
use output::{recovery, transmit};
use path::Path;

mod app;
pub(crate) mod events;
mod life;
pub mod path;
mod routing;
mod security;
mod temporal;
mod turn;

pub use app::App;
pub use life::Life;
pub(crate) use routing::Routing;
pub use security::Security;
pub use temporal::Temporal;
pub use turn::Turn;

/// Fresh mutable auth for one connection.
/// A capability borrows the scope and cannot escape its callback:
///
/// The scope itself is likewise generative and cannot be retained:
#[repr(transparent)]
pub struct Access<
    'conn,
    const DOMAIN: u8,
    B: stream::Recv,
    const RECONCILE: bool,
    D: buffer::raw::Segment,
> {
    machine: &'conn mut conn::Machine<DOMAIN, B, D>,
    brand: brand::Token<'conn>,
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment>
    Access<'conn, DOMAIN, B, RECONCILE, D>
{
    pub(crate) fn new(
        machine: &'conn mut conn::Machine<DOMAIN, B, D>,
        brand: brand::Token<'conn>,
    ) -> Self {
        Self { machine, brand }
    }

    pub(crate) const fn brand(&self) -> brand::Token<'conn> {
        self.brand
    }

    pub(crate) fn reborrow<const TRACKED: bool>(&mut self) -> Access<'_, DOMAIN, B, TRACKED, D> {
        Access::new(self.machine, self.brand.reborrow())
    }

    pub fn output(&mut self) -> transmit::Emission<'_, DOMAIN, B, D, RECONCILE> {
        self.machine.record::<RECONCILE>(conn::Effects::TRANSMIT);
        transmit::Emission::new(self.machine)
    }

    pub fn recovery(&mut self) -> recovery::Progress<'_, DOMAIN, B, D> {
        self.machine.record::<RECONCILE>(conn::Effects::RECOVERY);
        recovery::Progress::new(self.machine)
    }

    pub fn view(&self) -> status::View<'_, DOMAIN, B, D> {
        status::View::new(self.machine)
    }

    pub fn streams(&mut self) -> access::Streams<'_, 'conn, DOMAIN, B, RECONCILE, D> {
        access::Streams::new(self.machine, self.brand)
    }

    pub fn datagrams(&mut self) -> datagram::Datagrams<'_, DOMAIN, B, RECONCILE, D> {
        datagram::Datagrams::new(self.machine)
    }

    pub fn path(&mut self) -> Path<'_, DOMAIN, B, RECONCILE, D> {
        Path::new(self.machine)
    }

    pub fn security(&mut self) -> Security<'_, DOMAIN, B, RECONCILE, D> {
        Security::new(self.machine)
    }

    pub fn lifecycle(&mut self) -> Life<'_, DOMAIN, B, RECONCILE, D> {
        Life::new(self.machine)
    }

    pub fn application(&mut self) -> App<'_, DOMAIN, B, RECONCILE, D> {
        App::new(self.machine)
    }

    pub(crate) fn routing(&mut self) -> Routing<'_, DOMAIN, B, D> {
        Routing::new(self.machine)
    }

    pub(crate) fn events(&mut self) -> events::Events<'_, DOMAIN, B, D> {
        events::Events::new(self.machine)
    }
}

impl<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Access<'_, DOMAIN, B, false, D> {
    pub fn input<'access>(
        &'access mut self,
        work: &'access mut conn::Workspace,
    ) -> ingress::Input<'access, DOMAIN, B, false, D> {
        ingress::Input::new(self.machine, work)
    }
}

impl<const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Access<'_, DOMAIN, B, true, D> {
    pub(crate) fn input<'access>(
        &'access mut self,
        work: &'access mut conn::Workspace,
    ) -> ingress::Input<'access, DOMAIN, B, true, D> {
        ingress::Input::new(self.machine, work)
    }
}

const _: () = {
    use conn::wire::path;

    type Machine = conn::Machine<0, Vec<u8>>;

    assert!(
        mem::size_of::<Access<'static, 0, Vec<u8>, false, resident::Shared<'static>>>()
            == mem::size_of::<&mut Machine>()
    );
    assert!(
        mem::align_of::<Access<'static, 0, Vec<u8>, false, resident::Shared<'static>>>()
            == mem::align_of::<&mut Machine>()
    );
    assert!(!mem::needs_drop::<
        Access<'static, 0, Vec<u8>, false, resident::Shared<'static>>,
    >());
    assert!(
        mem::size_of::<Access<'static, 0, Vec<u8>, true, resident::Shared<'static>>>()
            == mem::size_of::<&mut Machine>()
    );
    assert!(
        mem::size_of::<Turn<'static, 0, Vec<u8>, resident::Shared<'static>>>()
            == mem::size_of::<(&mut Machine, time::Instant)>()
    );
    assert!(
        mem::size_of::<Temporal<'static, 'static, 0, Vec<u8>, resident::Shared<'static>>>()
            == mem::size_of::<Turn<'static, 0, Vec<u8>, resident::Shared<'static>>>()
    );
    assert!(!mem::needs_drop::<
        Turn<'static, 0, Vec<u8>, resident::Shared<'static>>,
    >());
    assert!(!mem::needs_drop::<
        Temporal<'static, 'static, 0, Vec<u8>, resident::Shared<'static>>,
    >());
    assert!(mem::size_of::<Security<'static, 0>>() == mem::size_of::<&mut Machine>());
    assert!(
        mem::size_of::<Security<'static, 0, Vec<u8>, true, resident::Shared<'static>, time::Instant>>(
        ) == mem::size_of::<(&mut Machine, time::Instant)>()
    );
    assert!(
        mem::size_of::<ingress::Input<'static, 0, Vec<u8>>>()
            == mem::size_of::<(
                &mut conn::Machine<0, Vec<u8>>,
                &mut conn::Workspace,
                Option<path::LocalCidKey>,
            )>()
    );
    assert!(mem::size_of::<Path<'static, 0>>() == mem::size_of::<&mut Machine>());
    assert!(
        mem::size_of::<Life<'static, 0, Vec<u8>, false, resident::Shared<'static>>>()
            == mem::size_of::<&mut Machine>()
    );
    assert!(
        mem::size_of::<
            access::Streams<'static, 'static, 0, Vec<u8>, false, resident::Shared<'static>>,
        >() == mem::size_of::<&mut Machine>()
    );
    assert!(mem::size_of::<datagram::Datagrams<'static, 0>>() == mem::size_of::<&mut Machine>());
    assert!(mem::size_of::<transmit::Emission<'static, 0>>() == mem::size_of::<&mut Machine>());
};
