//! Driver-installed QUIC mux execution without a socket boundary.
//! Packet proto remains under control of the enclosing runtime.

use crate::conn::id;
use crate::runtime::embedded;
use crate::runtime::mux::app::{Driver, drive, has_work};
use crate::runtime::mux::auth;
use crate::runtime::mux::handler;
use crate::runtime::mux::manage;
use crate::runtime::mux::output;
use crate::runtime::mux::router;
use crate::runtime::routing;
use crate::stream;
pub use config::Config;
pub use control::Control;
use dope::core::driver::retained;
use dope::core::driver::route;
use dope::core::driver::schedule;
use dope::core::driver::schedule::app;
use dope::core::driver::schedule::app::step;
use dope::core::driver::schedule::clock;
use dope::core::driver::schedule::ready;
use dope::manifold::app::dispatch;
use dope::runtime::executor;
pub use error::Error;
use handler::hook::set;
use handler::hook::wire::endpoint;
use o3::buffer::resident;
use o3::mem::quota;
use output::gate::Gate;
use std::{ops, pin};

pub mod client;
mod config;
mod control;
mod error;
pub mod link;
pub mod plan;
mod raw;
pub mod server;

pub struct Idle;

pub struct Run<A> {
    app: A,
    work: WorkGraph,
}

#[derive(dope::WorkGraph)]
enum Work {
    Application,
    Transport,
}

/// A socket-free, driver-branded mux and its app scheduler.
#[pin_project::pin_project]
pub struct Endpoint<'d, const ID: u8, H, B: stream::Recv = Vec<u8>, S = Idle>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
{
    #[pin]
    mux: router::Router<H, ID, B, auth::Owned<routing::Plain, id::Driver<'d>>>,
    schedule: S,
    ready: ready::Slot<'d, route::KeyTag<ID>>,
    flush: Gate,
    stopping: bool,
}

impl<'d, const ID: u8, H, B, S> executor::raw::Finishes<'d, Self> for Endpoint<'d, ID, H, B, S>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv,
{
    fn call<'app, 'finish, 'owner, 'epoch>(
        finish: executor::raw::Finish<'app, 'finish, 'owner, 'epoch, 'd, Self>,
    ) -> executor::raw::Finish<'app, 'finish, 'owner, 'epoch, 'd, Self> {
        let (mut owner, install, proof) = finish.into_parts();
        <<H::Events as set::Dispatch<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::Endpoint as endpoint::Mode<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::call(|| {
            let domain = owner.as_ref().project_ref().mux.domain();
            let handler = owner.as_mut().project().mux.handler_mut();
            endpoint::Event::finalized(handler, domain, None)
        });
        executor::raw::Finish::new(owner, install, proof)
    }
}

impl<'d, const ID: u8, H, B, S> dispatch::raw::Installs<'d, Self> for Endpoint<'d, ID, H, B, S>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv,
{
    fn call<'app, 'owner>(
        install: executor::raw::Install<'app, 'owner, 'd, Self>,
    ) -> executor::raw::Install<'app, 'owner, 'd, Self> {
        let (mut owner, proof) = install.into_parts();
        <<H::Events as set::Dispatch<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::Endpoint as endpoint::Mode<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::call(|| {
            let domain = owner.as_ref().project_ref().mux.domain();
            let handler = owner.as_mut().project().mux.handler_mut();
            endpoint::Event::opened(handler, domain)
        });
        executor::raw::Install::new(owner, proof)
    }
}

impl<'d, const ID: u8, H, B> Endpoint<'d, ID, H, B>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv,
{
    fn drive<'turn>(
        self: pin::Pin<&mut Self>,
        work: app::Work<'turn, 'd>,
        driver: &mut retained::Context<'_, '_, 'd>,
    ) {
        let now = driver.driver_ref().clock().now();
        now.at(self).apply(|runtime, raw| {
            let mut mux = runtime.project().mux;
            while mux.as_ref().schedule(raw).is_break() {
                let Some(permit) = work.permit() else {
                    return;
                };
                mux.as_mut().drive_net(permit, now);
            }
        });
    }
}

impl<'d, const ID: u8, H, B, A> Endpoint<'d, ID, H, B, Run<A>>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv,
    A: Driver<'d, H, ID, B, resident::Shared<'d>>,
{
    fn drive<'turn>(
        self: pin::Pin<&mut Self>,
        work: app::Work<'turn, 'd>,
        driver: &mut retained::Context<'_, '_, 'd>,
    ) {
        let now = driver.driver_ref().clock().now();
        now.at(self).apply(|runtime, raw| {
            let mut this = runtime.project();
            let mut mux = this.mux.as_mut();
            let schedule = this.schedule;
            loop {
                let app = has_work(mux.as_ref(), &schedule.app);
                let net = mux.as_ref().schedule(raw).is_break();
                let admit = schedule.work.admit(|source| match source {
                    Work::Application => {
                        use crate::runtime::mux::app::BATCH_QUANTUM;

                        if !app {
                            return quota::Admission::Empty;
                        }
                        let parent = this.ready.target();
                        let quantum = usize::from(BATCH_QUANTUM.get());
                        let mut driven = 0usize;
                        while driven < quantum {
                            let outcome =
                                drive(mux.as_mut(), &mut schedule.app, parent, work, driver, raw);
                            let batch = match outcome {
                                quota::Admission::Empty => {
                                    return if driven == 0 {
                                        quota::Admission::Empty
                                    } else {
                                        quota::Admission::Item(())
                                    };
                                }
                                quota::Admission::Exhausted => {
                                    return if driven == 0 {
                                        quota::Admission::Exhausted
                                    } else {
                                        quota::Admission::Item(())
                                    };
                                }
                                quota::Admission::Item(step::Flow::Batch) => true,
                                quota::Admission::Item(step::Flow::Yield) => false,
                            };
                            driven += 1;
                            if !batch {
                                break;
                            }
                        }
                        quota::Admission::Item(())
                    }
                    Work::Transport => {
                        if !net {
                            return quota::Admission::Empty;
                        }
                        let Some(permit) = work.permit() else {
                            return quota::Admission::Exhausted;
                        };
                        mux.as_mut().drive_net(permit, now);
                        quota::Admission::Item(())
                    }
                });
                match admit {
                    quota::Admission::Item(()) => {}
                    quota::Admission::Empty | quota::Admission::Exhausted => break,
                }
            }
        });
    }
}

impl<'d, const ID: u8, H, B, S> Endpoint<'d, ID, H, B, S>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv,
{
    fn new(
        mux: router::Router<H, ID, B, auth::Owned<routing::Plain, id::Driver<'d>>>,
        schedule: S,
        ready: ready::Slot<'d, route::KeyTag<ID>>,
    ) -> Self {
        Self {
            mux,
            schedule,
            ready,
            flush: Gate::new(),
            stopping: false,
        }
    }

    pub fn handler(&self) -> &H {
        self.mux.handler()
    }

    pub fn len(&self) -> usize {
        self.mux.active_conns()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn sole(&self) -> Option<id::Handle<id::Driver<'d>, ID>> {
        self.mux.sole()
    }

    fn progress(self: pin::Pin<&Self>, clock: clock::Clock<'_, 'd>) -> schedule::Progress<'d> {
        let this = self.project_ref();
        if *this.stopping {
            return if this.mux.is_done() {
                schedule::Progress::Quiescent
            } else {
                schedule::Progress::Runnable
            };
        }
        let progress = if this.flush.is_open() && this.mux.has_output() {
            schedule::Progress::Runnable
        } else {
            schedule::Progress::Quiescent
        };
        let now = clock.now();
        progress.reduce(now.at(this.mux).apply(|mux, raw| match mux.schedule(raw) {
            ops::ControlFlow::Break(_) => schedule::Progress::Runnable,
            ops::ControlFlow::Continue(Some(at)) => schedule::Progress::until(now.deadline_at(at)),
            ops::ControlFlow::Continue(None) => schedule::Progress::Quiescent,
        }))
    }

    fn shutdown_at<'turn>(
        self: pin::Pin<&mut Self>,
        work: app::Work<'turn, 'd>,
        now: clock::Moment<'d>,
    ) {
        now.at(self).apply(|runtime, raw| {
            let mut this = runtime.project();
            if !*this.stopping {
                *this.stopping = true;
                manage::Shutdown::new(this.mux.as_mut()).begin();
            }
            while !this.mux.as_ref().is_done() {
                let Some(permit) = work.permit() else {
                    return;
                };
                manage::Shutdown::new(this.mux.as_mut()).step(permit, raw);
            }
        });
    }
}

trait Drives<'d, const ID: u8, H, B>: Sized
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv,
{
    fn pre_park<'a, 'turn, 'root>(
        endpoint: pin::Pin<&'a mut embedded::Endpoint<'d, ID, H, B, Self>>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut dispatch::raw::Context<'_, 'root, 'd, dispatch::raw::Retained>,
    ) -> pin::Pin<&'a mut embedded::Endpoint<'d, ID, H, B, Self>>
    where
        embedded::Endpoint<'d, ID, H, B, Self>: 'root;

    fn augment(
        endpoint: pin::Pin<&embedded::Endpoint<'d, ID, H, B, Self>>,
        progress: schedule::Progress<'d>,
    ) -> schedule::Progress<'d>;
}

impl<'d, const ID: u8, H, B> Drives<'d, ID, H, B> for embedded::Idle
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv,
{
    fn pre_park<'a, 'turn, 'root>(
        mut endpoint: pin::Pin<&'a mut embedded::Endpoint<'d, ID, H, B>>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut dispatch::raw::Context<'_, 'root, 'd, dispatch::raw::Retained>,
    ) -> pin::Pin<&'a mut embedded::Endpoint<'d, ID, H, B>>
    where
        embedded::Endpoint<'d, ID, H, B>: 'root,
    {
        if *endpoint.as_ref().project_ref().stopping {
            endpoint
                .as_mut()
                .shutdown_at(turn.app(), driver.driver_ref().clock().now());
        } else {
            endpoint.as_mut().drive(turn.app(), driver);
        }
        endpoint
    }

    fn augment(
        _: pin::Pin<&embedded::Endpoint<'d, ID, H, B>>,
        progress: schedule::Progress<'d>,
    ) -> schedule::Progress<'d> {
        progress
    }
}

impl<'d, const ID: u8, H, B, A> Drives<'d, ID, H, B> for embedded::Run<A>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: stream::Recv,
    A: Driver<'d, H, ID, B, resident::Shared<'d>>,
{
    fn pre_park<'a, 'turn, 'root>(
        mut endpoint: pin::Pin<&'a mut embedded::Endpoint<'d, ID, H, B, Self>>,
        turn: schedule::Turn<'turn, 'd>,
        driver: &mut dispatch::raw::Context<'_, 'root, 'd, dispatch::raw::Retained>,
    ) -> pin::Pin<&'a mut embedded::Endpoint<'d, ID, H, B, Self>>
    where
        embedded::Endpoint<'d, ID, H, B, Self>: 'root,
    {
        if *endpoint.as_ref().project_ref().stopping {
            endpoint
                .as_mut()
                .shutdown_at(turn.app(), driver.driver_ref().clock().now());
        } else {
            endpoint.as_mut().drive(turn.app(), driver);
        }
        endpoint
    }

    fn augment(
        endpoint: pin::Pin<&embedded::Endpoint<'d, ID, H, B, Self>>,
        progress: schedule::Progress<'d>,
    ) -> schedule::Progress<'d> {
        let app = {
            let this = endpoint.as_ref().project_ref();
            !*this.stopping && has_work(this.mux, &this.schedule.app)
        };
        if app {
            progress.reduce(schedule::Progress::Runnable)
        } else {
            progress
        }
    }
}
