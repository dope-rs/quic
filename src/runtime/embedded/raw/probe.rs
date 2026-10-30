use crate::conn::id;
use crate::runtime::embedded::Drives;
use crate::runtime::{embedded, mux::handler};
use crate::stream;
use dope::core::driver::schedule;
use dope::manifold::app::dispatch;
use o3::buffer::resident;

// SAFETY: unit selection binds each liveness query to this exact pinned endpoint.
unsafe impl<'d, const ID: u8, H, B, S> dispatch::raw::Probe<'d, Self>
    for embedded::Endpoint<'d, ID, H, B, S>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv,
    S: Drives<'d, ID, H, B>,
{
    type Plan = ();

    fn select() -> Option<Self::Plan> {
        Some(())
    }

    fn run(call: dispatch::raw::Call<'_, '_, '_, 'd, Self, Self::Plan>) -> schedule::Progress<'d> {
        let endpoint = call.owner();
        let progress = endpoint.progress(call.clock());
        S::augment(endpoint, progress)
    }
}
