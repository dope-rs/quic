use crate::runtime::endpoint::{Interest, Payload};
use dope::core::driver::route;
use o3::buffer::Residency;
use o3::{base::Call as _, buffer};
use std::{ops::ControlFlow, pin};

use o3::buffer::resident;

use dope::core::driver::schedule::app;
use dope::manifold::network::datagram;

use crate::conn::id;
use crate::runtime::endpoint::reactor::buffers;
use crate::runtime::mux::{auth, handler, output, router};
use crate::stream;
use handler::hook::{
    set::{Dispatch, Socket as _},
    wire::socket,
    writable::{self, Mode as _},
};
use handler::net;
use output::quantum;

pub(in crate::runtime::endpoint) struct Queue<
    'a,
    'd,
    const ID: u8,
    H,
    B,
    M,
    Q: Residency + buffer::raw::Source,
> where
    H: handler::Handler<ID, B, M::Send, M::Identity>,
    B: stream::Recv,
    M: auth::Mode<ID, Send = resident::Shared<'d>, Identity = id::Driver<'d>>,
{
    socket: pin::Pin<&'a mut datagram::Socket<'d, route::KeyTag<ID>, Payload<Q>>>,
    pooled: &'a mut buffers::Pending<Q, Interest<'d, H, ID, B>>,
    mux: pin::Pin<&'a mut router::Router<H, ID, B, M>>,
}

impl<'a, 'd, const ID: u8, H, B, M, Q: Residency + buffer::raw::Source>
    Queue<'a, 'd, ID, H, B, M, Q>
where
    H: handler::Handler<ID, B, M::Send, M::Identity>,
    B: stream::Recv,
    M: auth::Mode<ID, Send = resident::Shared<'d>, Identity = id::Driver<'d>>,
{
    pub(in crate::runtime::endpoint) fn new(
        socket: pin::Pin<&'a mut datagram::Socket<'d, route::KeyTag<ID>, Payload<Q>>>,
        pooled: &'a mut buffers::Pending<Q, Interest<'d, H, ID, B>>,
        mux: pin::Pin<&'a mut router::Router<H, ID, B, M>>,
    ) -> Self {
        Self {
            socket,
            pooled,
            mux,
        }
    }

    pub(in crate::runtime::endpoint) fn one<'turn, 'quota>(
        mut self,
        permit: app::Permit<'turn, 'd>,
        credit: quantum::Credit<'quota>,
    ) -> output::Submit<'quota, (), datagram::RejectCause> {
        permit.run(|| {
            if let Some((pending, slot)) = self.pooled.take() {
                return Self::pooled(
                    self.socket.as_mut(),
                    self.mux.as_mut(),
                    credit,
                    pending,
                    slot,
                );
            }
            let endpoint = self.mux.as_ref().get_ref().domain();
            let result = self.mux.as_mut().output().submit(credit, |item| {
                let addr = item.flight().addr();
                let bytes = item.flight().byte_len();
                let count = item.flight().packet_count();
                let shape = match item.flight().segment_size() {
                    None => net::Shape::Plain,
                    Some(size) => net::Shape::Segmented {
                        segment_size: size,
                        datagrams: count,
                    },
                };
                item.send(self.socket.as_mut()).map(|owner| {
                    net::Accepted::new(net::Owner::queued(endpoint, owner), addr, bytes, shape)
                })
            });
            match result {
                output::Submit::Accepted(accepted, grant) => {
                    Self::notify(self.mux.as_mut(), accepted);
                    output::Submit::Accepted((), grant)
                }
                output::Submit::Empty => output::Submit::Empty,
                output::Submit::Deferred => output::Submit::Deferred,
                output::Submit::Rejected(cause) => output::Submit::Rejected(cause),
            }
        })
    }

    pub(in crate::runtime::endpoint) fn reject(
        mut self,
        error: datagram::RejectCause,
    ) -> ControlFlow<()> {
        match error {
            datagram::RejectCause::QueueFull => return ControlFlow::Continue(()),
            datagram::RejectCause::Resident { required, .. }
                if required.get() <= self.mux.as_mut().output().byte_limit() =>
            {
                return ControlFlow::Continue(());
            }
            _ => {}
        }
        let endpoint = self.mux.as_ref().get_ref().domain();
        let handler = self.mux.as_mut().handler_mut();
        <H::Events as Dispatch<H, ID, B, M::Send, M::Identity>>::Socket::call(|| {
            socket::Event::new(handler, net::Event::Rejected { endpoint, error })
        });
        ControlFlow::Break(())
    }

    fn pooled<'quota>(
        mut socket: pin::Pin<&mut datagram::Socket<'d, route::KeyTag<ID>, Payload<Q>>>,
        mut mux: pin::Pin<&mut router::Router<H, ID, B, M>>,
        credit: quantum::Credit<'quota>,
        pending: buffers::Queued<Q>,
        slot: buffers::Vacant<'_, Q, Interest<'d, H, ID, B>>,
    ) -> output::Submit<'quota, (), datagram::RejectCause> {
        let (addr, pending) = pending;
        let grant = credit.one();
        let bytes = pending.as_ref().len();
        let endpoint = mux.as_ref().get_ref().domain();
        let owner = match socket.as_mut().queue_pooled(pending, addr) {
            Ok(owner) => owner,
            Err(rejected) => {
                let (pending, cause) = rejected.into_parts();
                slot.restore((addr, pending));
                return output::Submit::Rejected(cause);
            }
        };
        if slot.accepted() == writable::Receipt::Ready
            && let Some(arm) =
                <H::Events as Dispatch<H, ID, B, M::Send, M::Identity>>::Writable::arm()
        {
            arm.call(mux.as_mut().handler_mut());
        }
        let accepted = net::Accepted::new(
            net::Owner::queued(endpoint, owner),
            addr,
            bytes,
            net::Shape::Plain,
        );
        Self::notify(mux, accepted);
        output::Submit::Accepted((), grant)
    }

    fn notify(
        mut mux: pin::Pin<&mut router::Router<H, ID, B, M>>,
        accepted: net::Accepted<M::Identity, ID>,
    ) {
        let handler = mux.as_mut().handler_mut();
        <H::Events as Dispatch<H, ID, B, M::Send, M::Identity>>::Socket::call(|| {
            socket::Event::new(handler, net::Event::Accepted(accepted))
        });
    }
}
