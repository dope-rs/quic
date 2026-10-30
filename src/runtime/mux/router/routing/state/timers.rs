use o3::buffer;
use std::{ops, pin, time};

use crate::runtime::mux::handler::hook::{
    data::{datagram, stream},
    life::{early, ready},
    set::{Datagram as _, Dispatch, Early as _, Established as _, Stream as _},
};
use crate::stream::Recv;
use crate::{
    conn,
    runtime::{mux, routing::registry},
};
use conn::id;
use mux::{auth, handler, router};
use router::drive;

struct Notification<'scope, H, const DOMAIN: u8, B, D, I, T>
where
    H: handler::Handler<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    handle: id::Handle<I, DOMAIN>,
    sink: pin::Pin<&'scope mut H>,
    slot: registry::Access<'scope, H::Connection, DOMAIN, B, D, T, false>,
    at: I::Observation,
}

impl<H, const DOMAIN: u8, B, D, I, T> Notification<'_, H, DOMAIN, B, D, I, T>
where
    H: handler::Handler<DOMAIN, B, D, I>,
    B: Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn reject(&mut self) -> ops::ControlFlow<()> {
        <H::Events as Dispatch<H, DOMAIN, B, D, I>>::Early::call(move || {
            match self.slot.conn.events().early() {
                conn::Early::None => return None,
                conn::Early::Rejected => {}
            }
            Some(move || {
                let this = self;
                early::Event::new(this.sink.as_mut(), &mut *this.slot.connection, this.handle)
            })
        })
    }

    fn establish(&mut self) -> ops::ControlFlow<()> {
        <H::Events as Dispatch<H, DOMAIN, B, D, I>>::Established::call(move || {
            if !self.slot.conn.view().lifecycle().is_ready() || *self.slot.notified_established {
                return None;
            }
            *self.slot.notified_established = true;
            Some(move || {
                let this = self;
                ready::Event::new(
                    this.sink.as_mut(),
                    handler::Slot::new(
                        &mut *this.slot.connection,
                        this.slot.conn.reborrow::<true>(),
                    ),
                    this.handle,
                    this.at,
                )
            })
        })
    }

    fn datagram(&mut self) -> ops::ControlFlow<()> {
        <H::Events as Dispatch<H, DOMAIN, B, D, I>>::Datagram::call(move || {
            let data = self.slot.conn.datagrams().recv()?;
            *self.slot.stream_first = true;
            Some(move || {
                datagram::Event::new(
                    self.sink.as_mut(),
                    handler::Slot::new(
                        &mut *self.slot.connection,
                        self.slot.conn.reborrow::<true>(),
                    ),
                    self.handle,
                    data,
                    self.at,
                )
            })
        })
    }

    /// Early deferrals retain their event without rearming its notification.
    fn stream(&mut self) -> ops::ControlFlow<()> {
        let Some(lease) = self.slot.conn.events().poll_stream() else {
            return ops::ControlFlow::Continue(());
        };
        *self.slot.stream_first = false;
        let ready = *self.slot.notified_established;
        let owner = &mut *self;
        let bound = &lease;
        let event = move || {
            let this = owner;
            stream::Event::new(
                this.sink.as_mut(),
                handler::Slot::new(
                    &mut *this.slot.connection,
                    this.slot.conn.reborrow::<true>(),
                ),
                this.handle,
                bound.bound_event(),
                this.at,
            )
        };
        let action = if ready {
            <H::Events as Dispatch<H, DOMAIN, B, D, I>>::Stream::call(event)
        } else {
            <H::Events as Dispatch<H, DOMAIN, B, D, I>>::Stream::early(event)
        };
        self.slot
            .conn
            .events()
            .finish(lease, action == mux::Disposition::Accept);
        if ready || action == mux::Disposition::Accept {
            ops::ControlFlow::Break(())
        } else {
            ops::ControlFlow::Continue(())
        }
    }

    fn data(&mut self) -> ops::ControlFlow<()> {
        let first = *self.slot.notified_established && *self.slot.stream_first;
        if !first {
            self.datagram()?;
        }
        self.stream()?;
        if first {
            self.datagram()?;
        }
        ops::ControlFlow::Continue(())
    }

    fn dispatch(&mut self) {
        if self.reject().is_break() || self.establish().is_break() || self.data().is_break() {
            self.slot.conn.events().mark(conn::Effects::NOTIFY);
        }
    }
}

pub(in crate::runtime::mux) fn notify<
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: Recv,
>(
    turn: &mut router::Turn<'_, A, H, DOMAIN, B>,
    at: <A::Identity as id::Temporal>::Observation,
) -> drive::Step {
    let now = Into::<time::Instant>::into(at);
    let Some(()) = turn.ready::<(), { mux::NOTIFY_QUEUE }>(now, |handle, sink, slot| {
        Notification {
            handle,
            sink,
            slot,
            at,
        }
        .dispatch();
    }) else {
        return drive::Step::Idle;
    };
    drive::Step::Driven
}
