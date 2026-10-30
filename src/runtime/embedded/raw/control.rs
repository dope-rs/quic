use crate::conn::id;
use crate::runtime::embedded::link::{Control, Link};
use crate::runtime::{embedded, mux::handler};
use crate::stream;
use dope::manifold::app::dispatch;
use o3::buffer::resident;

// SAFETY: Control roots only the installed link's stable arena allocation and
// exposes owner adoption and return operations within the exclusive step.
unsafe impl<'d, const ROUTE: u8, const FROM: u8, const TO: u8> dispatch::raw::Control<'d>
    for Link<'d, ROUTE, FROM, TO>
{
    type View<'step>
        = Control<'step, 'd, ROUTE, FROM, TO>
    where
        Self: 'step,
        'd: 'step;

    fn view<'step>(owner: dispatch::raw::Installed<'step, 'd, Self>) -> Self::View<'step>
    where
        'd: 'step,
    {
        Control { owner }
    }
}

// SAFETY: Control exposes only a pinned, step-bounded mux observation and
// cannot move or release driver-branded endpoint storage.
unsafe impl<'d, const ID: u8, H, B, S> dispatch::raw::Control<'d>
    for embedded::Endpoint<'d, ID, H, B, S>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv,
    Self: dispatch::raw::Manifold<'d>,
{
    type View<'step>
        = embedded::Control<'step, 'd, ID, H, B, S>
    where
        Self: 'step,
        'd: 'step;

    fn view<'step>(owner: dispatch::raw::Installed<'step, 'd, Self>) -> Self::View<'step>
    where
        'd: 'step,
    {
        embedded::Control::new(owner)
    }
}
