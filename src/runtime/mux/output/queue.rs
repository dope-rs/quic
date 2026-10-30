use crate::runtime::endpoint::Payload;
use dope::manifold::network::datagram::send;

use crate::runtime::Transit;

use std::{iter, marker, pin};

use crate::conn::id;
use crate::errors;
use crate::runtime::mux::{self, auth, handler, output, router};
use crate::runtime::routing;
use crate::stream;
use output::quantum;
use router::drive;

/// Exclusive output access tied to one router borrow and TLS auth.
#[repr(transparent)]
pub struct Queue<
    'a,
    'tls,
    H,
    const DOMAIN: u8,
    B = Vec<u8>,
    A = auth::Pooled<'tls, routing::Plain, id::Static>,
> where
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
    A: auth::Mode<DOMAIN>,
{
    mux: pin::Pin<&'a mut router::Router<H, DOMAIN, B, A>>,
    lifetime: marker::PhantomData<&'tls ()>,
}

impl<
    'a,
    'tls,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
    A: auth::Mode<DOMAIN>,
> Queue<'a, 'tls, H, DOMAIN, B, A>
{
    pub(crate) fn new(mux: pin::Pin<&'a mut router::Router<H, DOMAIN, B, A>>) -> Self {
        Self {
            mux,
            lifetime: marker::PhantomData,
        }
    }

    pub(crate) fn drain(
        self,
    ) -> impl Iterator<Item = output::Flight> + 'a + use<'a, H, DOMAIN, B, A>
    where
        'tls: 'a,
    {
        let mut mux = router::Turn::new(self.mux);
        let mut left = if mux.lifecycle.shutting_down {
            0
        } else {
            mux::DIRECT_DRIVE_BUDGET
        };
        iter::from_fn(move || {
            if left == 0 {
                return None;
            }
            let outgoing = mux.outgoing.pop_front()?;
            left -= 1;
            Some(outgoing)
        })
    }

    pub fn capacity(&self) -> usize {
        self.mux
            .as_ref()
            .get_ref()
            .state
            .outgoing
            .pending
            .capacity()
    }

    pub fn len(&self) -> usize {
        self.mux.as_ref().get_ref().state.outgoing.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mux
            .as_ref()
            .get_ref()
            .state
            .outgoing
            .pending
            .is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.mux.as_ref().get_ref().state.outgoing.pending.bytes()
    }

    pub fn byte_limit(&self) -> usize {
        self.mux.as_ref().get_ref().state.outgoing.bytes_capacity
    }

    /// Returns a completed output owner to the packet pool.
    pub fn recycle(&mut self, outgoing: output::Flight) {
        self.mux
            .as_mut()
            .project()
            .state
            .outgoing
            .cache
            .recycle(outgoing.into_storage());
    }

    pub(crate) fn reclaim<Q>(&mut self, payload: send::Payload<'_, '_, Payload<Q>>) {
        let packet = match payload {
            send::Payload::Owned(packet) => packet.into_inner(),
            send::Payload::Buffer(packet) => match packet.into_inner() {
                Payload::Retry(packet) => packet.into_storage(),
                Payload::Pooled(_) => return,
            },
            send::Payload::Packet(_) => return,
        };
        self.mux
            .as_mut()
            .project()
            .state
            .outgoing
            .cache
            .recycle(packet);
    }

    pub(in crate::runtime) fn submit<'quota, R, E>(
        &mut self,
        credit: quantum::Credit<'quota>,
        submit: impl for<'op> FnOnce(Transit<'op>) -> Result<R, (Transit<'op>, E)>,
    ) -> output::Submit<'quota, R, E> {
        let state = self.mux.as_mut().project().state;
        state.outgoing.pending.submit(credit, submit)
    }

    pub(crate) fn drive_at(
        &mut self,
        at: <A::Identity as id::Temporal>::Observation,
    ) -> Result<usize, errors::Transmit<A::Identity, DOMAIN>>
    where
        A::Identity: id::Temporal,
    {
        let mut mux = router::Turn::new(self.mux.as_mut());
        if mux.lifecycle.shutting_down {
            return Ok(0);
        }
        let mut driven = 0;
        while driven != mux::DIRECT_DRIVE_BUDGET && drive::drive_one(&mut mux, at)?.is_driven() {
            driven += 1;
        }
        Ok(driven)
    }
}
