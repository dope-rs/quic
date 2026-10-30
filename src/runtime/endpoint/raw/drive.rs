use std::pin;

use dope::{
    core::driver::{retained, route, schedule},
    manifold::network::datagram::hook,
};
use o3::buffer::{self, resident};

use crate::{
    conn::id,
    runtime::{
        endpoint::{Idle, Run, Socket, Transport, reactor},
        mux::{
            app, auth, handler,
            handler::hook::{
                set,
                wire::{cert, packet},
            },
        },
        receive::Storage,
    },
};

impl<'d, const ID: u8, H, B, M, Q>
    hook::raw::Drive<
        'd,
        route::KeyTag<ID>,
        reactor::Engine<'d, H, ID, B, Idle, M, Q>,
        hook::Enabled,
    > for Idle
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    M: auth::Mode<ID, Send = resident::Shared<'d>, Identity = id::Driver<'d>>,
    Q: buffer::Residency + buffer::raw::Source,
    H: cert::Sink<ID, id::Driver<'d>>,
    <H::Events as set::Dispatch<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::Packet:
        packet::Mode<H, ID, B, resident::Shared<'d>, id::Driver<'d>, Output = ()>,
{
    const COORDS: usize = <<Socket<'d, ID, H, B> as set::Socket<
        H,
        ID,
        B,
        resident::Shared<'d>,
        id::Driver<'d>,
    >>::Transport<'d, ID, reactor::Engine<'d, H, ID, B, Idle, M, Q>> as hook::raw::Drive<
        'd,
        route::KeyTag<ID>,
        reactor::Engine<'d, H, ID, B, Idle, M, Q>,
        hook::Enabled,
    >>::COORDS;

    unsafe fn pre_park<'a, 'turn>(
        endpoint: pin::Pin<&'a mut Transport<'d, ID, H, B, Idle, M, Q>>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut retained::Context<'_, '_, 'd>,
    ) -> pin::Pin<&'a mut Transport<'d, ID, H, B, Idle, M, Q>> {
        // SAFETY: the caller retains this exact endpoint through completion or quiescence.
        unsafe {
            <<Socket<'d, ID, H, B> as set::Socket<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::Transport<'d, ID, reactor::Engine<'d, H, ID, B, Idle, M, Q>> as hook::raw::Drive<'d, route::KeyTag<ID>, reactor::Engine<'d, H, ID, B, Idle, M, Q>, hook::Enabled>>::pre_park(endpoint, turn, driver)
        }
    }
}

impl<'d, const ID: u8, H, B, M, Q, A, R>
    hook::raw::Drive<
        'd,
        route::KeyTag<ID>,
        reactor::Engine<'d, H, ID, B, Run<A, R>, M, Q>,
        hook::Enabled,
    > for Run<A, R>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    M: auth::Mode<ID, Send = resident::Shared<'d>, Identity = id::Driver<'d>>,
    Q: buffer::Residency + buffer::raw::Source,
    A: app::Driver<'d, H, ID, B, resident::Shared<'d>>,
    R: app::Receipt<'d, H, ID, B, resident::Shared<'d>, A>,
    H: cert::Sink<ID, id::Driver<'d>>,
    <H::Events as set::Dispatch<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::Packet:
        packet::Mode<H, ID, B, resident::Shared<'d>, id::Driver<'d>, Output = ()>,
{
    const COORDS: usize = <<Socket<'d, ID, H, B> as set::Socket<
        H,
        ID,
        B,
        resident::Shared<'d>,
        id::Driver<'d>,
    >>::Application<'d, ID, reactor::Engine<'d, H, ID, B, Run<A, R>, M, Q>> as hook::raw::Drive<
        'd,
        route::KeyTag<ID>,
        reactor::Engine<'d, H, ID, B, Run<A, R>, M, Q>,
        hook::Enabled,
    >>::COORDS;

    unsafe fn pre_park<'a, 'turn>(
        endpoint: pin::Pin<&'a mut Transport<'d, ID, H, B, Run<A, R>, M, Q>>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut retained::Context<'_, '_, 'd>,
    ) -> pin::Pin<&'a mut Transport<'d, ID, H, B, Run<A, R>, M, Q>> {
        // SAFETY: the caller retains this exact endpoint through completion or quiescence.
        unsafe {
            <<Socket<'d, ID, H, B> as set::Socket<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::Application<'d, ID, reactor::Engine<'d, H, ID, B, Run<A, R>, M, Q>> as hook::raw::Drive<'d, route::KeyTag<ID>, reactor::Engine<'d, H, ID, B, Run<A, R>, M, Q>, hook::Enabled>>::pre_park(endpoint, turn, driver)
        }
    }
}
