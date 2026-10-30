use crate::runtime::brand;
use o3::buffer;
use o3::mem::quota;
use std::convert::Infallible;

use std::{num, pin, time};

use app::step;
use dope::core::driver::{
    retained,
    schedule::{app, ready},
};

use crate::conn::{id, scope};
use crate::runtime::mux::{self, auth, handler, router};
use crate::runtime::routing::registry::Scope;
use crate::{conn, errors, stream};

mod layout;
mod set;

/// Admissions that fill one maximum UDP GSO packet train.
pub const BATCH_QUANTUM: num::NonZero<u16> = num::NonZero::<u16>::MIN.saturating_add(63);

/// Exact app-queue decision committed by one slot mutation.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
#[repr(u8)]
#[must_use = "readiness must be committed at the enclosing slot boundary"]
pub enum Readiness {
    #[default]
    Preserve,
    Idle,
    Ready,
}

impl Readiness {
    pub(crate) fn update(&mut self, next: Self) {
        if next != Self::Preserve {
            *self = next;
        }
    }

    pub(crate) const fn into_ready(self) -> Option<bool> {
        match self {
            Self::Preserve => None,
            Self::Idle => Some(false),
            Self::Ready => Some(true),
        }
    }
}

/// Linear app transition over disjoint endpoint authorities.
pub struct Turn<'turn, H, C> {
    handler: pin::Pin<&'turn mut H>,
    conns: C,
}

impl<'turn, H, C> Turn<'turn, H, C> {
    fn new(handler: pin::Pin<&'turn mut H>, conns: C) -> Self {
        Self { handler, conns }
    }

    pub fn into_parts(self) -> (pin::Pin<&'turn mut H>, C) {
        (self.handler, self.conns)
    }
}

/// Bounded connection transactions split from one app turn.
#[must_use = "a rejected selection returns the still-open connection set"]
pub struct Rejected<S> {
    set: S,
    error: errors::Access,
}

impl<S> Rejected<S> {
    fn new(set: S, error: errors::Access) -> Self {
        Self { set, error }
    }

    pub const fn error(&self) -> errors::Access {
        self.error
    }

    pub fn into_parts(self) -> (S, errors::Access) {
        (self.set, self.error)
    }

    pub fn discard(self) -> errors::Access {
        self.error
    }
}

pub trait Selected<
    H: handler::Handler<DOMAIN, B, D, I>,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
>
{
    /// Runs one exact mutation before exposing its result.
    fn run<R>(
        self,
        op: impl for<'scope> FnOnce(Connection<'scope, H::Connection, DOMAIN, B, D, I>) -> R,
    ) -> R;
}

pub trait Set<
    H: handler::Handler<DOMAIN, B, D, I>,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
>: Sized
{
    type Ready: Selected<H, DOMAIN, B, D, I>;
    type Exact: Selected<H, DOMAIN, B, D, I>;

    /// Selects the front connection without unlinking it.
    fn next(self) -> Option<Self::Ready>;

    fn has_ready(&self) -> bool;

    /// Selects one possibly stale connection or returns the open set.
    fn select(self, handle: id::Handle<I, DOMAIN>) -> Result<Self::Exact, Rejected<Self>> {
        self.try_select(handle)
    }

    /// Selects one possibly stale connection or returns the open set.
    fn try_select(self, handle: id::Handle<I, DOMAIN>) -> Result<Self::Exact, Rejected<Self>>;
}

/// Generative app and proto auth for one live slot.
pub struct Connection<
    'scope,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
> {
    handle: id::Handle<I, DOMAIN>,
    slot: handler::Slot<'scope, C, DOMAIN, B, D>,
}

impl<'scope, C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, I: id::Temporal>
    Connection<'scope, C, DOMAIN, B, D, I>
{
    pub(in crate::runtime::mux) fn new(
        handle: id::Handle<I, DOMAIN>,
        slot: handler::Slot<'scope, C, DOMAIN, B, D>,
    ) -> Self {
        Self { handle, slot }
    }

    pub const fn handle(&self) -> id::Handle<I, DOMAIN> {
        self.handle
    }

    pub fn application(&mut self) -> &mut C {
        self.slot.application()
    }

    pub fn transport(&mut self) -> &mut scope::Access<'scope, DOMAIN, B, true, D> {
        self.slot.transport()
    }

    pub fn set_ready(&mut self, ready: bool) {
        self.slot.set_ready(ready);
    }

    pub fn ready(&mut self) {
        self.set_ready(true);
    }

    pub fn idle(&mut self) {
        self.set_ready(false);
    }

    pub fn split(
        &mut self,
    ) -> (
        id::Handle<I, DOMAIN>,
        &mut C,
        &mut scope::Access<'scope, DOMAIN, B, true, D>,
    ) {
        let handle = self.handle;
        let (app, conn) = self.slot.split();
        (handle, app, conn)
    }
}

pub enum Silent {}
pub enum Watch {}

/// Selects whether the application observes an accepted endpoint admission.
pub trait Receipt<'d, H, const ID: u8, B, D, A>
where
    H: handler::Handler<ID, B, D, id::Driver<'d>>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    A: Driver<'d, H, ID, B, D>,
{
    type Observer<'a>: Accepted
    where
        A: 'a;
    fn observer(app: &mut A) -> Option<Self::Observer<'_>>;
}

impl<'d, H, const ID: u8, B, D, A> Receipt<'d, H, ID, B, D, A> for Silent
where
    H: handler::Handler<ID, B, D, id::Driver<'d>>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    A: Driver<'d, H, ID, B, D>,
{
    type Observer<'a>
        = Infallible
    where
        A: 'a;
    fn observer(_: &mut A) -> Option<Self::Observer<'_>> {
        None
    }
}

impl<'d, H, const ID: u8, B, D, A> Receipt<'d, H, ID, B, D, A> for Watch
where
    H: handler::Handler<ID, B, D, id::Driver<'d>>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    A: Driver<'d, H, ID, B, D>,
    for<'a> &'a mut A: Accepted,
{
    type Observer<'a>
        = &'a mut A
    where
        A: 'a;
    fn observer(app: &mut A) -> Option<Self::Observer<'_>> {
        Some(app)
    }
}

/// One borrowed application notification, consumed exactly once after admission.
pub trait Accepted {
    fn accepted(self);
}

impl Accepted for Infallible {
    fn accepted(self) {
        match self {}
    }
}

/// Optional app scheduler installed beside a protocol handler.
pub trait Driver<
    'd,
    H: handler::Handler<DOMAIN, B, D, id::Driver<'d>>,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
>
{
    fn has_work(&self, handler: pin::Pin<&H>) -> bool;

    /// Drives at most one app transition.
    fn drive<'scope, 'turn, C: Set<H, DOMAIN, B, D, id::Driver<'d>>>(
        &mut self,
        turn: Turn<'scope, H, C>,
        parent: ready::Target<'d>,
        work: app::Work<'turn, 'd>,
        driver: &mut retained::Context<'_, '_, 'd>,
    ) -> quota::Admission<step::Flow>;
}

pub(crate) fn has_work<'d, A, H, const DOMAIN: u8, B, App>(
    mux: pin::Pin<&router::Router<H, DOMAIN, B, A>>,
    app: &App,
) -> bool
where
    A: auth::Mode<DOMAIN, Identity = id::Driver<'d>>,
    H: handler::Handler<DOMAIN, B, A::Send, id::Driver<'d>>,
    B: stream::Recv,
    App: Driver<'d, H, DOMAIN, B, A::Send>,
{
    !mux.state
        .registry
        .is_empty_in::<{ mux::APPLICATION_QUEUE }>()
        || app.has_work(mux.project_ref().handler)
}

pub(crate) fn drive<'turn, 'd, A, H, const DOMAIN: u8, B, App>(
    mux: pin::Pin<&mut router::Router<H, DOMAIN, B, A>>,
    app: &mut App,
    parent: ready::Target<'d>,
    work: app::Work<'turn, 'd>,
    driver: &mut retained::Context<'_, '_, 'd>,
    now: time::Instant,
) -> quota::Admission<step::Flow>
where
    A: auth::Mode<DOMAIN, Identity = id::Driver<'d>>,
    H: handler::Handler<DOMAIN, B, A::Send, id::Driver<'d>>,
    B: stream::Recv,
    App: Driver<'d, H, DOMAIN, B, A::Send>,
{
    let mut turn = router::Turn::new(mux);
    execute(&mut turn, now, |turn| app.drive(turn, parent, work, driver))
}

/// Runs one app transition with an open connection set.
pub(super) fn execute<
    'turn,
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
    R,
>(
    turn: &mut router::Turn<'turn, A, H, DOMAIN, B>,
    now: time::Instant,
    op: impl FnOnce(Turn<'_, H, set::Set<'_, '_, A, H, DOMAIN, B>>) -> R,
) -> R {
    brand::Token::with_mut(turn, |brand, turn| {
        let handler = turn.handler.as_mut();
        let state = &mut *turn.state;
        Scope::with(&mut state.registry, |slots| {
            op(Turn::new(
                handler,
                set::Set::new(
                    brand,
                    slots,
                    &mut state.binding,
                    state.lifecycle.shutting_down,
                    now,
                ),
            ))
        })
    })
}

const _: () = assert!(BATCH_QUANTUM.get() as usize == conn::MAX_BATCH_PACKETS);
