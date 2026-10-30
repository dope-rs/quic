use o3::{base::Call, buffer};
use std::{convert::Infallible, mem, pin};

use crate::conn::id;
use crate::runtime::mux::handler::Handler;
use crate::stream;

pub struct On;
pub struct Off;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Receipt {
    Idle,
    Ready,
}

/// Coalesces retry interest until its owner explicitly consumes the receipt.
pub trait Interest: Sized {
    type State;
    type Hook<H, const DOMAIN: u8, B, D, I>: Mode<H, DOMAIN, B, D, I, Interest = Self>
    where
        H: Sink<DOMAIN, B, D, I>,
        B: stream::Recv,
        D: buffer::raw::Segment,
        I: id::Temporal;

    const EMPTY: Self::State;

    fn exchange(state: &mut Self::State, next: Receipt) -> Receipt;
    fn is_pending(state: &Self::State) -> bool;
}

impl Interest for On {
    type State = bool;
    type Hook<H, const DOMAIN: u8, B, D, I>
        = Self
    where
        H: Sink<DOMAIN, B, D, I>,
        B: stream::Recv,
        D: buffer::raw::Segment,
        I: id::Temporal;

    const EMPTY: Self::State = false;

    fn exchange(state: &mut Self::State, next: Receipt) -> Receipt {
        if mem::replace(state, next == Receipt::Ready) {
            Receipt::Ready
        } else {
            Receipt::Idle
        }
    }

    fn is_pending(state: &Self::State) -> bool {
        *state
    }
}

impl Interest for Off {
    type State = ();
    type Hook<H, const DOMAIN: u8, B, D, I>
        = Self
    where
        H: Sink<DOMAIN, B, D, I>,
        B: stream::Recv,
        D: buffer::raw::Segment,
        I: id::Temporal;

    const EMPTY: Self::State = ();

    fn exchange(_: &mut Self::State, _: Receipt) -> Receipt {
        Receipt::Idle
    }

    fn is_pending(_: &Self::State) -> bool {
        false
    }
}

pub trait Sink<const DOMAIN: u8, B, D, I>: Handler<DOMAIN, B, D, I>
where
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    fn writable(self: pin::Pin<&mut Self>);
    fn has_writable(&self) -> bool;
    fn clear(self: pin::Pin<&mut Self>);
}

/// Endpoint staging receipts are independent of socket instrumentation.
pub trait Mode<H, const DOMAIN: u8, B, D, I>
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    type Interest: Interest;

    fn arm() -> Option<impl for<'a> Call<pin::Pin<&'a mut H>>>;
    fn clear() -> Option<impl for<'a> Call<pin::Pin<&'a mut H>>>;

    fn is_pending(handler: &H) -> bool;
}

impl<H, const DOMAIN: u8, B, D, I> Mode<H, DOMAIN, B, D, I> for On
where
    H: Sink<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    type Interest = Self;

    fn arm() -> Option<impl for<'a> Call<pin::Pin<&'a mut H>>> {
        Some(H::writable)
    }

    fn clear() -> Option<impl for<'a> Call<pin::Pin<&'a mut H>>> {
        Some(H::clear)
    }

    fn is_pending(handler: &H) -> bool {
        handler.has_writable()
    }
}

impl<H, const DOMAIN: u8, B, D, I> Mode<H, DOMAIN, B, D, I> for Off
where
    H: Handler<DOMAIN, B, D, I>,
    B: stream::Recv,
    D: buffer::raw::Segment,
    I: id::Temporal,
{
    type Interest = Self;

    fn arm() -> Option<impl for<'a> Call<pin::Pin<&'a mut H>>> {
        None::<Infallible>
    }

    fn clear() -> Option<impl for<'a> Call<pin::Pin<&'a mut H>>> {
        None::<Infallible>
    }

    fn is_pending(_: &H) -> bool {
        false
    }
}
