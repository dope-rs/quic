#![deny(unsafe_code)]

use std::{marker, pin};

use app::step;
use dope::{
    core::driver::{
        retained, route,
        schedule::{self, app, clock},
    },
    manifold::network::datagram::{self, hook},
};
use o3::{
    base::cell::region,
    buffer::{self, resident},
    mem::quota,
};

use crate::{
    conn::id,
    runtime::{
        endpoint::{Payload, Socket, Transport, reactor},
        mux::{
            self, auth, handler,
            handler::hook::{
                set,
                wire::{cert, packet},
            },
            manage, output,
        },
        receive::Storage,
    },
};

use mux::app::{Accepted, Driver, Receipt, Silent, drive, has_work};
use output::quantum::Quantum;
use reactor::{Engine, Work, queue};

/// Application scheduler and its endpoint-owned fair-work cursor.
pub struct Run<A, R = Silent> {
    pub(in crate::runtime::endpoint) app: A,
    pub(in crate::runtime::endpoint) work: reactor::WorkGraph,
    receipt: marker::PhantomData<fn() -> R>,
}

impl<A, R> Run<A, R> {
    pub(in crate::runtime::endpoint) fn new(app: A) -> Self {
        Self {
            app,
            work: reactor::WorkGraph::new(),
            receipt: marker::PhantomData,
        }
    }
}

impl<'d, const ID: u8, H, B, M, Q, A, R>
    hook::Schedule<'d, route::KeyTag<ID>, reactor::Engine<'d, H, ID, B, Run<A, R>, M, Q>>
    for Run<A, R>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    M: auth::Mode<ID, Send = resident::Shared<'d>, Identity = id::Driver<'d>>,
    Q: buffer::Residency + buffer::raw::Source,
    A: Driver<'d, H, ID, B, resident::Shared<'d>>,
    R: Receipt<'d, H, ID, B, resident::Shared<'d>, A>,
    H: cert::Sink<ID, id::Driver<'d>>,
    <H::Events as set::Dispatch<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::Packet:
        packet::Mode<H, ID, B, resident::Shared<'d>, id::Driver<'d>, Output = ()>,
{
    type Plan<'turn> = <<Socket<'d, ID, H, B> as set::Socket<
        H,
        ID,
        B,
        resident::Shared<'d>,
        id::Driver<'d>,
    >>::Application<'d, ID, reactor::Engine<'d, H, ID, B, Run<A, R>, M, Q>> as hook::Schedule<
        'd,
        route::KeyTag<ID>,
        reactor::Engine<'d, H, ID, B, Run<A, R>, M, Q>,
    >>::Plan<'turn>;

    fn select<'turn>(clock: clock::Clock<'turn, 'd>) -> Option<Self::Plan<'turn>> {
        <<Socket<'d, ID, H, B> as set::Socket<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::Application<'d, ID, reactor::Engine<'d, H, ID, B, Run<A, R>, M, Q>> as hook::Schedule<'d, route::KeyTag<ID>, reactor::Engine<'d, H, ID, B, Run<A, R>, M, Q>>>::select(clock)
    }

    fn progress(
        endpoint: pin::Pin<&Transport<'d, ID, H, B, Run<A, R>, M, Q>>,
        plan: Self::Plan<'_>,
        token: &region::Token<region::Identity<'d, 1>>,
    ) -> schedule::Progress<'d> {
        <<Socket<'d, ID, H, B> as set::Socket<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::Application<'d, ID, reactor::Engine<'d, H, ID, B, Run<A, R>, M, Q>> as hook::Schedule<'d, route::KeyTag<ID>, reactor::Engine<'d, H, ID, B, Run<A, R>, M, Q>>>::progress(endpoint, plan, token)
    }
}

impl<'d, const ID: u8, H, B, A, R, M, Q: buffer::Residency + buffer::raw::Source>
    datagram::Application<'d, route::KeyTag<ID>> for Engine<'d, H, ID, B, Run<A, R>, M, Q>
where
    H: handler::Handler<ID, B, resident::Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, resident::Shared<'d>>,
    A: Driver<'d, H, ID, B, resident::Shared<'d>>,
    R: Receipt<'d, H, ID, B, resident::Shared<'d>, A>,
    M: auth::Mode<ID, Send = resident::Shared<'d>, Identity = id::Driver<'d>>,
    H: cert::Sink<ID, id::Driver<'d>>,
    <H::Events as set::Dispatch<H, ID, B, resident::Shared<'d>, id::Driver<'d>>>::Packet:
        packet::Mode<H, ID, B, resident::Shared<'d>, id::Driver<'d>, Output = ()>,
{
    fn pre_park<'turn>(
        self: pin::Pin<&mut Self>,
        mut socket: pin::Pin<&mut datagram::Socket<'d, route::KeyTag<ID>, Payload<Q>>>,
        now: clock::Moment<'d>,
        work: app::Work<'turn, 'd>,
        driver: &mut retained::Context<'_, '_, 'd>,
    ) {
        now.at(self).apply(|engine, raw| {
            let mut this = engine.project();
            let mut mux = this.mux.as_mut();
            let app = &mut this.app.app;
            if *this.stopping {
                while !mux.as_ref().is_done() {
                    let Some(permit) = work.permit() else {
                        return;
                    };
                    manage::Shutdown::new(mux.as_mut()).step(permit, raw);
                }
                return;
            }
            this.flush.open();
            let mut quota = Quantum::new();
            loop {
                let ready = has_work(mux.as_ref(), app);
                let output = (this.pooled.is_some() || !mux.as_mut().output().is_empty())
                    && this.flush.is_open();
                let due = mux.as_ref().schedule(raw).is_break();
                if !ready && !output && !due {
                    break;
                }
                let admit = this.app.work.admit(|source| match source {
                    Work::Application => {
                        use mux::app::BATCH_QUANTUM;

                        if !ready {
                            return quota::Admission::Empty;
                        }
                        let parent = socket.as_ref().wake_target();
                        let limit = usize::from(BATCH_QUANTUM.get());
                        let mut driven = 0usize;
                        while driven < limit {
                            let step = drive(mux.as_mut(), app, parent, work, driver, raw);
                            let batch = match step {
                                quota::Admission::Empty => {
                                    return if driven == 0 {
                                        quota::Admission::Empty
                                    } else {
                                        quota::Admission::Item(false)
                                    };
                                }
                                quota::Admission::Exhausted => {
                                    return if driven == 0 {
                                        quota::Admission::Exhausted
                                    } else {
                                        quota::Admission::Item(true)
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
                        quota::Admission::Item(false)
                    }
                    Work::Output => {
                        if !output {
                            return quota::Admission::Empty;
                        }
                        let Some(permit) = work.permit() else {
                            return quota::Admission::Exhausted;
                        };
                        let Some(credit) = quota.credit() else {
                            return quota::Admission::Item(true);
                        };
                        match queue::Queue::new(socket.as_mut(), this.pooled, mux.as_mut())
                            .one(permit, credit)
                        {
                            output::Submit::Empty => quota::Admission::Item(false),
                            output::Submit::Deferred => quota::Admission::Item(true),
                            output::Submit::Accepted((), grant) => {
                                if let Some(observer) = R::observer(app) {
                                    observer.accepted();
                                }
                                quota::Admission::Item(grant.commit().is_exhausted())
                            }
                            output::Submit::Rejected(cause) => {
                                this.flush.block();
                                if queue::Queue::new(socket.as_mut(), this.pooled, mux.as_mut())
                                    .reject(cause)
                                    .is_break()
                                {
                                    Self::stop(mux.as_mut(), this.pooled, this.stopping);
                                }
                                quota::Admission::Item(*this.stopping)
                            }
                        }
                    }
                    Work::Transport => {
                        if !due {
                            return quota::Admission::Empty;
                        }
                        let Some(permit) = work.permit() else {
                            return quota::Admission::Exhausted;
                        };
                        mux.as_mut().drive_net(permit, now);
                        quota::Admission::Item(false)
                    }
                });
                match admit {
                    quota::Admission::Item(false) => {}
                    quota::Admission::Item(true)
                    | quota::Admission::Empty
                    | quota::Admission::Exhausted => break,
                }
            }
        });
    }

    fn progress(
        self: pin::Pin<&Self>,
        clock: clock::Clock<'_, 'd>,
        _: &region::Token<region::Identity<'d, 1>>,
    ) -> schedule::Progress<'d> {
        self.progress(clock, |state| {
            let this = self.project_ref();
            if has_work(this.mux, &this.app.app) {
                state.reduce(schedule::Progress::Runnable)
            } else {
                state
            }
        })
    }
}
