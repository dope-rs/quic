#![deny(unsafe_code)]

use crate::runtime::endpoint::Payload;
use dope::core::driver::{result::SubmitCause, route};
use o3::mem::quota;

use dope::core::io::datagram::{ReceiveError, Residency};
use o3::buffer;

use crate::proto::datagram::Sealed;

pub(super) mod buffers;
pub(super) mod queue;

use std::{net::SocketAddr, ops::ControlFlow, pin, time};

use dope::{
    core::driver::schedule::{self, app, clock},
    manifold::network::datagram::{self, hook, packet, send},
};
use handler::{
    hook::{
        set::{Dispatch, Socket as _},
        wire::{
            cert,
            endpoint::{self, Event},
            packet::Mode,
            socket,
        },
        writable::Mode as _,
    },
    net,
};
use hook::ingress::Coupled;
use manage::config;
use o3::{
    base::{Call as _, cell::region},
    buffer::resident::Shared,
};
use output::{gate::Gate, quantum::Quantum};

use crate::{
    conn::id,
    runtime::{
        endpoint::{Idle, Interest, control, owner},
        mux::{auth, handler, manage, output, router},
        receive::Storage,
        routing,
    },
    stream,
};

#[derive(dope::WorkGraph)]
pub(in crate::runtime::endpoint) enum Net {
    Output,
    Transport,
}

#[derive(dope::WorkGraph)]
pub(in crate::runtime::endpoint) enum Work {
    Application,
    Output,
    Transport,
}

#[pin_project::pin_project(!Unpin)]
pub struct Engine<
    'd,
    H: handler::Handler<ID, B, Shared<'d>, id::Driver<'d>>,
    const ID: u8,
    B: stream::Recv,
    A = Idle,
    M = auth::Owned<routing::Plain, id::Driver<'d>>,
    Q: buffer::Residency + buffer::raw::Source = Sealed<'d>,
> where
    M: auth::Mode<ID, Send = Shared<'d>, Identity = id::Driver<'d>>,
{
    #[pin]
    pub(super) mux: router::Router<H, ID, B, M>,
    pub(super) app: A,
    pub(super) pooled: buffers::Pending<Q, Interest<'d, H, ID, B>>,
    pub(super) flush: Gate,
    pub(super) stopping: bool,
}

impl<'d, H, const ID: u8, B, A, M, Q: buffer::Residency + buffer::raw::Source>
    Engine<'d, H, ID, B, A, M, Q>
where
    H: handler::Handler<ID, B, Shared<'d>, id::Driver<'d>>,
    B: stream::Recv,
    M: auth::Mode<ID, Send = Shared<'d>, Identity = id::Driver<'d>>,
{
    pub(super) fn new(mux: router::Router<H, ID, B, M>, app: A) -> Self {
        Self {
            mux,
            app,
            pooled: buffers::Pending::new(),
            flush: Gate::new(),
            stopping: false,
        }
    }

    pub(super) fn mux_mut(self: pin::Pin<&mut Self>) -> pin::Pin<&mut router::Router<H, ID, B, M>> {
        self.project().mux
    }

    pub(super) fn handler_mut(self: pin::Pin<&mut Self>) -> pin::Pin<&mut H> {
        self.project().mux.handler_mut()
    }

    pub(super) fn config(self: pin::Pin<&mut Self>) -> config::Config<'_, '_, H, ID, B, M> {
        self.project().mux.config()
    }

    pub(super) fn stop(
        mut mux: pin::Pin<&mut router::Router<H, ID, B, M>>,
        pooled: &mut buffers::Pending<Q, Interest<'d, H, ID, B>>,
        stopping: &mut bool,
    ) {
        pooled.clear();
        if let Some(clear) =
            <H::Events as Dispatch<H, ID, B, Shared<'d>, id::Driver<'d>>>::Writable::clear()
        {
            clear.call(mux.as_mut().handler_mut());
        }
        *stopping = true;
        manage::Shutdown::new(mux).begin();
    }

    pub(super) fn try_sender<N: owner::Binding<'d, ID, Mode = M>>(
        self: pin::Pin<&mut Self>,
        now: time::Instant,
    ) -> Result<control::Sender<'_, 'd, ID, H, B, N, Q>, control::SendError> {
        let this = self.project();
        if *this.stopping {
            return Err(control::SendError::Closed);
        }
        let slot = this.pooled.vacant().ok_or(control::SendError::Full)?;
        Ok(control::Sender::new(slot, this.mux, now))
    }

    pub(super) fn progress(
        self: pin::Pin<&Self>,
        clock: clock::Clock<'_, 'd>,
        ready: impl FnOnce(schedule::Progress<'d>) -> schedule::Progress<'d>,
    ) -> schedule::Progress<'d>
    where
        B: Storage<'d, Shared<'d>>,
    {
        let this = self.project_ref();
        if *this.stopping {
            return if this.mux.is_done() {
                schedule::Progress::Quiescent
            } else {
                schedule::Progress::Runnable
            };
        }
        let mut state = schedule::Progress::Quiescent;
        if <H::Events as Dispatch<H, ID, B, Shared<'d>, id::Driver<'d>>>::Writable::is_pending(
            this.mux.handler(),
        ) {
            state = state.reduce(schedule::Progress::Runnable);
        }
        if (this.pooled.is_some() || this.mux.has_output()) && this.flush.is_open() {
            state = state.reduce(schedule::Progress::Runnable);
        }
        let now = clock.now();
        state = state.reduce(
            now.at(this.mux.as_ref())
                .apply(|mux, raw| match mux.schedule(raw) {
                    ControlFlow::Break(_) => schedule::Progress::Runnable,
                    ControlFlow::Continue(Some(at)) => {
                        schedule::Progress::until(now.deadline_at(at))
                    }
                    ControlFlow::Continue(None) => schedule::Progress::Quiescent,
                }),
        );
        ready(state)
    }
}

impl<'d, const ID: u8, H, B, A, M, Q: buffer::Residency + buffer::raw::Source>
    datagram::Ingress<'d, route::KeyTag<ID>> for Engine<'d, H, ID, B, A, M, Q>
where
    H: handler::Handler<ID, B, Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, Shared<'d>>,
    M: auth::Mode<ID, Send = Shared<'d>, Identity = id::Driver<'d>>,
    H: cert::Sink<ID, id::Driver<'d>>,
    <H::Events as Dispatch<H, ID, B, Shared<'d>, id::Driver<'d>>>::Packet:
        Mode<H, ID, B, Shared<'d>, id::Driver<'d>, Output = ()>,
{
    type Hooks = hook::Set<
        <<H::Events as Dispatch<H, ID, B, Shared<'d>, id::Driver<'d>>>::Endpoint as endpoint::Mode<H, ID, B, Shared<'d>, id::Driver<'d>>>::Install<'d, ID, Self>,
        hook::Enabled,
        <<H::Events as Dispatch<H, ID, B, Shared<'d>, id::Driver<'d>>>::Endpoint as endpoint::Mode<H, ID, B, Shared<'d>, id::Driver<'d>>>::Finalize<'d, ID, Self>,
        A,
        hook::Enabled,
        Payload<Q>,
    >;
    type Mode = Coupled;
}

impl<'d, const ID: u8, H, B, A, M, Q: buffer::Residency + buffer::raw::Source>
    datagram::Coupled<'d, route::KeyTag<ID>> for Engine<'d, H, ID, B, A, M, Q>
where
    H: handler::Handler<ID, B, Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, Shared<'d>>,
    M: auth::Mode<ID, Send = Shared<'d>, Identity = id::Driver<'d>>,
    H: cert::Sink<ID, id::Driver<'d>>,
    <H::Events as Dispatch<H, ID, B, Shared<'d>, id::Driver<'d>>>::Packet:
        Mode<H, ID, B, Shared<'d>, id::Driver<'d>, Output = ()>,
{
    fn packet<'turn>(
        mut self: pin::Pin<&mut Self>,
        received: Result<(SocketAddr, packet::Packet<'turn, 'd>), ReceiveError>,
        socket: pin::Pin<&'turn mut datagram::Socket<'d, route::KeyTag<ID>, Payload<Q>>>,
        now: clock::Moment<'d>,
    ) {
        let (addr, packet) = match received {
            Ok(packet) => packet,
            Err(error) => {
                let mut this = self.as_mut().project();
                let endpoint = this.mux.as_ref().get_ref().domain();
                let handler = this.mux.as_mut().handler_mut();
                <H::Events as Dispatch<H, ID, B, Shared<'d>, id::Driver<'d>>>::Socket::call(|| {
                    socket::Event::new(handler, net::Event::Receive { endpoint, error })
                });
                if matches!(error, ReceiveError::Submit(error)
                    if error.cause() == SubmitCause::IdentityExhausted)
                    && !*this.stopping
                {
                    Self::stop(this.mux, this.pooled, this.stopping);
                }
                return;
            }
        };
        let keep = socket.as_ref().retainer();
        self.as_mut().mux_mut().observe(now, |mut turn| {
            let () = turn.receive(addr, packet, keep);
        });
    }
}

impl<'d, const ID: u8, H, B, A, M, Q: buffer::Residency + buffer::raw::Source>
    datagram::Settlement<'d, route::KeyTag<ID>> for Engine<'d, H, ID, B, A, M, Q>
where
    H: handler::Handler<ID, B, Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, Shared<'d>>,
    M: auth::Mode<ID, Send = Shared<'d>, Identity = id::Driver<'d>>,
    H: cert::Sink<ID, id::Driver<'d>>,
    <H::Events as Dispatch<H, ID, B, Shared<'d>, id::Driver<'d>>>::Packet:
        Mode<H, ID, B, Shared<'d>, id::Driver<'d>, Output = ()>,
{
    fn settle<'turn>(
        self: pin::Pin<&mut Self>,
        done: send::Settlement<'turn, 'd, route::KeyTag<ID>, Payload<Q>>,
        _: &mut region::Token<region::Identity<'d, 1>>,
    ) {
        let mut this = self.project();
        let failed = matches!(done.outcome(), send::Outcome::Submit(error)
            if error.cause() == SubmitCause::IdentityExhausted);
        let domain = this.mux.as_ref().get_ref().domain();
        let handler = this.mux.as_mut().handler_mut();
        <H::Events as Dispatch<H, ID, B, Shared<'d>, id::Driver<'d>>>::Socket::call(|| {
            socket::Event::new(
                handler,
                net::Event::Settled(net::Settlement::from_driver(domain, &done)),
            )
        });
        let (_, _, _, data, _) = done.into_parts();
        this.mux.as_mut().output().reclaim(data);
        if failed && !*this.stopping {
            Self::stop(this.mux, this.pooled, this.stopping);
        }
    }
}

impl<'d, const ID: u8, H, B, M, Q: buffer::Residency + buffer::raw::Source>
    datagram::Transport<'d, route::KeyTag<ID>> for Engine<'d, H, ID, B, Idle, M, Q>
where
    H: handler::Handler<ID, B, Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, Shared<'d>>,
    M: auth::Mode<ID, Send = Shared<'d>, Identity = id::Driver<'d>>,
    H: cert::Sink<ID, id::Driver<'d>>,
    <H::Events as Dispatch<H, ID, B, Shared<'d>, id::Driver<'d>>>::Packet:
        Mode<H, ID, B, Shared<'d>, id::Driver<'d>, Output = ()>,
{
    fn pre_park<'turn>(
        self: pin::Pin<&mut Self>,
        mut socket: pin::Pin<&mut datagram::Socket<'d, route::KeyTag<ID>, Payload<Q>>>,
        now: clock::Moment<'d>,
        work: app::Work<'turn, 'd>,
        _: &mut region::Token<region::Identity<'d, 1>>,
    ) {
        now.at(self).apply(|engine, raw| {
            let mut this = engine.project();
            let mut mux = this.mux.as_mut();
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
                let output = (this.pooled.is_some() || !mux.as_mut().output().is_empty())
                    && this.flush.is_open();
                let drive = mux.as_ref().schedule(raw).is_break();
                if !output && !drive {
                    break;
                }
                let admit = this.app.work.admit(|source| match source {
                    Net::Output => {
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
                    Net::Transport => {
                        if !drive {
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
        use std::convert::identity;

        self.progress(clock, identity)
    }
}

impl<'d, const ID: u8, H, B, A, M, Q: buffer::Residency + buffer::raw::Source> datagram::Install
    for Engine<'d, H, ID, B, A, M, Q>
where
    H: handler::Handler<ID, B, Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, Shared<'d>>,
    M: auth::Mode<ID, Send = Shared<'d>, Identity = id::Driver<'d>>,
{
    fn installed(self: pin::Pin<&mut Self>) {
        let domain = self.as_ref().project_ref().mux.domain();
        let handler = self.project().mux.handler_mut();
        <<H::Events as Dispatch<H, ID, B, Shared<'d>, id::Driver<'d>>>::Endpoint as endpoint::Mode<
            H,
            ID,
            B,
            Shared<'d>,
            id::Driver<'d>,
        >>::call(|| Event::opened(handler, domain));
    }
}

impl<'d, const ID: u8, H, B, A, M, Q: buffer::Residency + buffer::raw::Source> datagram::Shutdown
    for Engine<'d, H, ID, B, A, M, Q>
where
    H: handler::Handler<ID, B, Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, Shared<'d>>,
    M: auth::Mode<ID, Send = Shared<'d>, Identity = id::Driver<'d>>,
{
    fn shutdown(self: pin::Pin<&mut Self>) {
        let this = self.project();
        Self::stop(this.mux, this.pooled, this.stopping);
    }
}

impl<'d, const ID: u8, H, B, A, M, Q: buffer::Residency + buffer::raw::Source> datagram::Finalize
    for Engine<'d, H, ID, B, A, M, Q>
where
    H: handler::Handler<ID, B, Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, Shared<'d>>,
    M: auth::Mode<ID, Send = Shared<'d>, Identity = id::Driver<'d>>,
{
    fn finalized(self: pin::Pin<&mut Self>, state: Option<Residency>) {
        let mut this = self.project();
        let domain = this.mux.as_ref().get_ref().domain();
        let handler = this.mux.as_mut().handler_mut();
        <<H::Events as Dispatch<H, ID, B, Shared<'d>, id::Driver<'d>>>::Endpoint as endpoint::Mode<
            H,
            ID,
            B,
            Shared<'d>,
            id::Driver<'d>,
        >>::call(|| Event::finalized(handler, domain, state));
    }
}

impl<'d, const ID: u8, H, B, A, M, Q: buffer::Residency + buffer::raw::Source>
    datagram::Transfer<'d, route::KeyTag<ID>> for Engine<'d, H, ID, B, A, M, Q>
where
    H: handler::Handler<ID, B, Shared<'d>, id::Driver<'d>>,
    B: Storage<'d, Shared<'d>>,
    M: auth::Mode<ID, Send = Shared<'d>, Identity = id::Driver<'d>>,
{
    fn transferred(self: pin::Pin<&mut Self>, sent: send::Transfer<'d, route::KeyTag<ID>>) {
        let mut this = self.project();
        let domain = this.mux.as_ref().get_ref().domain();
        let handler = this.mux.as_mut().handler_mut();
        <H::Events as Dispatch<H, ID, B, Shared<'d>, id::Driver<'d>>>::Socket::call(|| {
            socket::Event::new(
                handler,
                net::Event::Transferred(net::Transfer::from_driver(domain, sent)),
            )
        });
    }
}
